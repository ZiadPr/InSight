import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { PostgresAttendanceStore } from "../../server/postgresStore.js";
import { PostgresConnection, bindStatement, type TransactionExecutor } from "../../server/postgresConnection.js";
import { checkPersistentRateLimit, resetPersistentRateLimit } from "../../server/persistentRateLimit.js";
import { buildTestLegacyState } from "./fixtures.js";

test("Postgres SQL parameters preserve literals and bind named and positional values", () => {
  assert.deepEqual(bindStatement("SELECT '?' AS literal WHERE id = ?", ["input"]), {
    text: "SELECT '?' AS literal WHERE id = $1", values: ["input"],
  });
  assert.deepEqual(bindStatement("UPDATE users SET full_name = @name WHERE id = @id", [{ name: "input", id: "id" }]), {
    text: "UPDATE users SET full_name = $1 WHERE id = $2", values: ["input", "id"],
  });
});

test("Postgres preserves encrypted records, commits scans atomically, rejects replay, and persists session revocation", async () => {
  const pg = new PGlite();
  let stage = "schema";
  try {
    // This is an isolated, disposable PostgreSQL engine used only by tests.
    for (const dir of fs.readdirSync("netlify/database/migrations").sort()) {
      if (fs.existsSync(`netlify/database/migrations/${dir}/migration.sql`)) {
        await pg.exec(fs.readFileSync(`netlify/database/migrations/${dir}/migration.sql`, "utf8"));
      }
    }
    const database = drizzle({ client: pg });
    const connection = new PostgresConnection(database as unknown as TransactionExecutor);
    const masterKey = crypto.randomBytes(32);
    const store = new PostgresAttendanceStore(masterKey, connection);
    const state = buildTestLegacyState(masterKey);
    stage = "bootstrap";
    assert.equal(await store.isInitialized(), false);
    await store.importDatabaseState(state);
    assert.equal(await store.isInitialized(), true);
    assert.ok((await store.getRuntimeSecrets()).auth_secret === state.auth_secret);
    assert.equal((await store.getUserByEmail("ADMIN@TEST.LOCAL"))?.id, "usr-admin-1");
    assert.equal(store.decryptUserMfaSecret((await store.getUserById("usr-admin-1"))!) !== null, true);
    assert.equal((await store.getEmployeeAttendanceHistory("usr-emp-1"))[0].distance_m, 42);
    const raw = await pg.query<{distance_m: number | null; gps_meta_enc: string}>("SELECT distance_m, gps_meta_enc FROM attendance_records LIMIT 1");
    assert.equal(raw.rows[0].distance_m, null);
    assert.ok(raw.rows[0].gps_meta_enc.includes("aes-256-gcm"));

    stage = "attendance transaction";
    const nowIso = new Date().toISOString();
    const token = { id: "qr-test", token_hash: "token-hash", manual_code_hash: "manual-hash", kiosk_device_id: "kiosk-01", issued_at: nowIso, expires_at: new Date(Date.now()+60_000).toISOString(), consumed_at: null, consumed_by: null, consumed_action: null, status: "active" as const };
    await store.issueQrToken("kiosk-01", token, nowIso);
    const originalRecord = state.attendance_records[0];
    const params = { tokenId: token.id, employeeId: "usr-emp-1", nowIso,
      record: { ...originalRecord, id: "att-new", attendance_date: "2026-11-19", qr_token_id: token.id, idempotency_key: "request-1", checked_out_at: null },
      securityLog: { id: "scan-log", user_id: "usr-emp-1", event_type: "check_in_succeeded", reason_code: "OK", ip_hash: "ip-hash", created_at: nowIso, metadata: {} },
    };
    await store.commitCheckInScan(params);
    await assert.rejects(() => store.commitCheckInScan(params), /QR_ALREADY_CONSUMED/);
    assert.equal((await store.getQrTokenForKiosk(token.id, "kiosk-01"))?.status, "consumed");
    assert.equal((await store.getTodayStats("2026-11-19")).checked_in_today, 1);
    assert.equal(await store.hasAttendanceIdempotencyKey("usr-emp-1", "request-1"), true);

    stage = "rollback";
    await store.issueQrToken("kiosk-01", { ...token, id: "qr-rollback", token_hash: "rollback-hash", manual_code_hash: "rollback-manual" }, nowIso);
    // A duplicate employee/date must roll back QR consumption as well as the insert.
    await assert.rejects(() => store.commitCheckInScan({ ...params, tokenId: "qr-rollback", record: { ...params.record, id: "att-conflict", qr_token_id: "qr-rollback" } }));
    assert.equal((await store.getQrTokenForKiosk("qr-rollback", "kiosk-01"))?.status, "active");

    stage = "session durability";
    await store.createActiveSessionWithEviction({ jti: "session-1", user_id: "usr-emp-1", role: "employee", aal: "aal1", ua_hash: "ua", ip_hash: "ip", created_at: nowIso, last_active_at: nowIso, idle_expires_at: new Date(Date.now()+60_000).toISOString(), absolute_expires_at: new Date(Date.now()+120_000).toISOString() }, 2, nowIso);
    const reopened = new PostgresAttendanceStore(masterKey, new PostgresConnection(database as unknown as TransactionExecutor));
    assert.ok(await reopened.getActiveSession("session-1", "usr-emp-1"));
    await reopened.revokeSessionByJti("session-1");
    assert.equal(await store.isJtiRevoked("session-1"), true);
    assert.equal(await store.getActiveSessionByJti("session-1"), null);
    stage = "persistent lockout";
    const now = Date.now();
    assert.equal((await checkPersistentRateLimit("test-login", 2, 60_000, 120_000, connection, now)).allowed, true);
    assert.equal((await checkPersistentRateLimit("test-login", 2, 60_000, 120_000, connection, now+1)).allowed, true);
    assert.equal((await checkPersistentRateLimit("test-login", 2, 60_000, 120_000, connection, now+2)).allowed, false);
    const secondConnection = new PostgresConnection(database as unknown as TransactionExecutor);
    assert.equal((await checkPersistentRateLimit("test-login", 2, 60_000, 120_000, secondConnection, now+65_000)).allowed, false);
    assert.equal((await checkPersistentRateLimit("test-login", 2, 60_000, 120_000, secondConnection, now+125_000)).allowed, true);
    await resetPersistentRateLimit("test-login", secondConnection);
    assert.equal((await checkPersistentRateLimit("test-login", 2, 60_000, 120_000, connection, now+125_001)).allowed, true);
    const backup = await reopened.exportBackupPayload();
    assert.equal(backup.users.length, 3);
    assert.equal(backup.attendance_records.length, 2);
  } catch (error) {
    // Never let a driver dump parameter values (including test key material).
    const failure = error as { cause?: { code?: string; routine?: string }; code?: string; name?: string };
    throw new Error(`Postgres integration failed during ${stage} (${failure.cause?.code ?? failure.code ?? failure.name}; ${failure.cause?.routine ?? "unknown"})`);
  } finally {
    await pg.close();
  }
});
