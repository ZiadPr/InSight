import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import {
  buildDefaultRbacRoles,
  buildDefaultSecurityPolicy,
  encryptJsonPayload,
  SqliteAttendanceStore,
  type DatabaseState,
} from "../../server/sqliteStore.ts";
import { runJsonToSqliteMigration } from "../../scripts/migrate-json-db-to-sqlite.ts";

function buildTestLegacyState(masterKey: Buffer): DatabaseState {
  const nowIso = "2026-11-19T08:00:00.000Z";
  return {
    auth_secret: crypto.randomBytes(32).toString("hex"),
    kiosk_salt: crypto.randomBytes(32).toString("hex"),
    ip_salt: crypto.randomBytes(32).toString("hex"),
    users: [
      {
        id: "usr-admin-1",
        email: "admin@test.local",
        password_salt: "salt1",
        password_hash: "hash1",
        token_version: 2,
        full_name: "مدير الاختبار",
        employee_number: "HR-01",
        department: "الموارد البشرية",
        job_title: "مدير النظام",
        shift_start: "08:00",
        shift_end: "16:00",
        role: "admin",
        admin_role_key: "super_admin",
        is_active: true,
        mfa_enabled: true,
        mfa_secret_enc: encryptJsonPayload("JBSWY3DPEHPK3PXP", masterKey),
        last_used_totp_step: 100,
        created_at: nowIso,
        updated_at: nowIso,
      },
      {
        id: "usr-emp-1",
        email: "emp1@test.local",
        password_salt: "salt2",
        password_hash: "hash2",
        token_version: 1,
        full_name: "أحمد اختبار",
        employee_number: "EMP-01",
        department: "الهندسة",
        job_title: "مهندس",
        shift_start: "09:00",
        shift_end: "17:00",
        role: "employee",
        is_active: true,
        created_at: nowIso,
        updated_at: nowIso,
      },
      {
        id: "usr-kiosk-1",
        email: "kiosk1@test.local",
        password_salt: "salt3",
        password_hash: "hash3",
        token_version: 1,
        full_name: "شاشة الاختبار",
        employee_number: null,
        department: "الاستقبال",
        job_title: "جهاز عرض QR",
        shift_start: "00:00",
        shift_end: "23:59",
        role: "kiosk",
        is_active: true,
        created_at: nowIso,
        updated_at: nowIso,
      },
    ],
    settings: {
      id: "company-hq",
      company_name: "شركة الاختبار",
      branch_name: "الفرع الرئيسي",
      latitude: 24.7136,
      longitude: 46.6753,
      allowed_radius_m: 250,
      max_gps_accuracy_m: 100,
      qr_ttl_seconds: 20,
      timezone: "Asia/Riyadh",
      work_start_time: "09:00",
      work_end_time: "17:00",
      late_grace_minutes: 15,
      enforce_geofence: true,
      is_enabled: true,
      qr_schedule_enabled: true,
      qr_window_start: "07:30",
      qr_cutoff_time: "11:00",
      qr_reappear_time: "15:30",
      qr_window_end: "19:00",
      updated_at: nowIso,
    },
    security_policy: buildDefaultSecurityPolicy(),
    rbac_roles: buildDefaultRbacRoles(),
    kiosk_devices: [
      {
        id: "kiosk-01",
        device_name: "بوابة 1",
        branch_name: "الفرع الرئيسي",
        auth_user_id: "usr-kiosk-1",
        secret_hash: "sec-hash-1",
        is_active: true,
        last_seen_at: nowIso,
        revoked_before: null,
        created_at: nowIso,
      },
    ],
    qr_tokens: [],
    attendance_records: [
      {
        id: "att-1",
        employee_id: "usr-emp-1",
        attendance_date: "2026-11-18",
        checked_in_at: "2026-11-18T06:05:00.000Z",
        checked_out_at: "2026-11-18T14:15:00.000Z",
        worked_minutes: 490,
        late_minutes: 0,
        status: "present",
        qr_token_id: null,
        idempotency_key: null,
        distance_m: 42,
        notes: null,
        created_at: "2026-11-18T06:05:00.000Z",
      },
    ],
    security_logs: [
      {
        id: "log-1",
        user_id: "usr-emp-1",
        event_type: "check_in_succeeded",
        reason_code: "OK",
        ip_hash: "iphash1",
        created_at: nowIso,
        metadata: { attendance_date: "2026-11-18" },
      },
    ],
    security_alerts: [],
    active_sessions: [],
    revoked_jtis: [],
  };
}

test("Migration script converts legacy encrypted JSON DB to SQLite WAL with automatic backup and column AES-256-GCM encryption", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "insight-migrate-"));
  try {
    const masterKey = crypto.randomBytes(32);
    const encPath = path.join(tmpDir, "attendance-db.enc");
    const dbPath = path.join(tmpDir, "attendance.db");

    const legacy = buildTestLegacyState(masterKey);
    fs.writeFileSync(encPath, encryptJsonPayload(JSON.stringify(legacy), masterKey), { mode: 0o600 });

    const res = runJsonToSqliteMigration({
      inputPath: encPath,
      outputPath: dbPath,
      masterKey,
    });

    assert.equal(fs.existsSync(res.backupPath), true, "Expected automatic .bak copy of encrypted source");
    assert.equal(fs.existsSync(dbPath), true, "Expected migrated SQLite database file");
    assert.equal(res.counts.users, 3);
    assert.equal(res.counts.kiosks, 1);
    assert.equal(res.counts.attendanceRecords, 1);
    assert.equal(res.counts.securityLogs, 1);

    // Inspect raw SQLite columns to verify sensitive GPS distance & secrets are encrypted at rest
    const rawDb = new Database(dbPath, { readonly: true });
    const rawAtt = rawDb
      .prepare(`SELECT distance_m, gps_meta_enc FROM attendance_records WHERE id = 'att-1'`)
      .get() as { distance_m: number | null; gps_meta_enc: string | null };
    assert.equal(rawAtt.distance_m, null, "Plaintext distance_m column must be scrubbed at rest");
    assert.ok(rawAtt.gps_meta_enc?.includes("aes-256-gcm"), "Expected AES-256-GCM envelope on gps_meta_enc");

    const rawSecret = rawDb
      .prepare(`SELECT value, is_encrypted FROM system_secrets WHERE key = 'auth_secret'`)
      .get() as { value: string; is_encrypted: number };
    assert.equal(rawSecret.is_encrypted, 1);
    assert.equal(rawSecret.value.includes(legacy.auth_secret), false);

    const indexes = rawDb
      .prepare(`SELECT name FROM sqlite_master WHERE type = 'index'`)
      .all() as Array<{ name: string }>;
    const idxNames = indexes.map((i) => i.name);
    assert.ok(idxNames.includes("idx_attendance_emp_date"), "Expected index on (employee_id, attendance_date)");
    assert.ok(idxNames.includes("idx_attendance_date"), "Expected index on (attendance_date)");
    rawDb.close();

    // Re-open via SqliteAttendanceStore and verify transparent decryption & fidelity
    const store = new SqliteAttendanceStore(dbPath, masterKey);
    const secrets = store.getRuntimeSecrets();
    assert.equal(secrets.auth_secret, legacy.auth_secret);
    assert.equal(secrets.kiosk_salt, legacy.kiosk_salt);

    const admin = store.getUserByEmail("admin@test.local");
    assert.ok(admin);
    assert.equal(store.decryptUserMfaSecret(admin!), "JBSWY3DPEHPK3PXP");

    const rec = store.getAttendanceByEmployeeAndDate("usr-emp-1", "2026-11-18");
    assert.ok(rec);
    assert.equal(rec!.distance_m, 42);
    assert.equal(rec!.status, "present");

    const settings = store.getSettings();
    assert.equal(settings.qr_schedule_enabled, true);
    assert.equal(settings.qr_cutoff_time, "11:00");
    store.close();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Atomic check-in transaction consumes single-use QR token once and rejects replay", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "insight-atomic-"));
  try {
    const masterKey = crypto.randomBytes(32);
    const dbPath = path.join(tmpDir, "attendance.db");
    const store = new SqliteAttendanceStore(dbPath, masterKey);
    store.importDatabaseState(buildTestLegacyState(masterKey));

    const issuedAt = "2026-11-19T06:00:00.000Z";
    const expiresAt = "2026-11-19T06:00:20.000Z";
    store.issueQrToken(
      "kiosk-01",
      {
        id: "tok-1",
        token_hash: "tok-hash-1",
        manual_code_hash: "man-hash-1",
        kiosk_device_id: "kiosk-01",
        issued_at: issuedAt,
        expires_at: expiresAt,
        consumed_at: null,
        consumed_by: null,
        consumed_action: null,
        status: "active",
      },
      issuedAt,
    );

    store.commitCheckInScan({
      tokenId: "tok-1",
      employeeId: "usr-emp-1",
      nowIso: issuedAt,
      record: {
        id: "att-new-1",
        employee_id: "usr-emp-1",
        attendance_date: "2026-11-19",
        checked_in_at: issuedAt,
        checked_out_at: null,
        worked_minutes: null,
        late_minutes: 0,
        status: "present",
        qr_token_id: "tok-1",
        idempotency_key: "idem-1",
        distance_m: 15,
        notes: null,
        created_at: issuedAt,
      },
      securityLog: {
        id: "log-new-1",
        user_id: "usr-emp-1",
        event_type: "check_in_succeeded",
        reason_code: "OK",
        ip_hash: "ip1",
        created_at: issuedAt,
        metadata: { attendance_date: "2026-11-19" },
      },
    });

    assert.throws(
      () =>
        store.commitCheckInScan({
          tokenId: "tok-1",
          employeeId: "usr-emp-1",
          nowIso: issuedAt,
          record: {
            id: "att-replay",
            employee_id: "usr-emp-1",
            attendance_date: "2026-11-20",
            checked_in_at: issuedAt,
            checked_out_at: null,
            worked_minutes: null,
            late_minutes: 0,
            status: "present",
            qr_token_id: "tok-1",
            idempotency_key: "idem-2",
            distance_m: 15,
            notes: null,
            created_at: issuedAt,
          },
          securityLog: {
            id: "log-replay",
            user_id: "usr-emp-1",
            event_type: "check_in_succeeded",
            reason_code: "OK",
            ip_hash: "ip1",
            created_at: issuedAt,
            metadata: {},
          },
        }),
      /QR_ALREADY_CONSUMED/,
    );

    const saved = store.getAttendanceByEmployeeAndDate("usr-emp-1", "2026-11-19");
    assert.ok(saved);
    assert.equal(saved!.distance_m, 15);
    store.close();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Micro-benchmark: writing 10,000 individual attendance records scales without linear full-DB degradation", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "insight-bench-"));
  try {
    const masterKey = crypto.randomBytes(32);
    const dbPath = path.join(tmpDir, "bench.db");
    const store = new SqliteAttendanceStore(dbPath, masterKey);
    const baseState = buildTestLegacyState(masterKey);

    // Provision 100 test employees (100 days x 100 employees = 10,000 unique attendance rows)
    const nowIso = "2026-01-01T08:00:00.000Z";
    for (let e = 0; e < 100; e += 1) {
      baseState.users.push({
        id: `bench-emp-${e}`,
        email: `bench${e}@test.local`,
        password_salt: "s",
        password_hash: "h",
        token_version: 1,
        full_name: `موظف ${e}`,
        employee_number: `BENCH-${1000 + e}`,
        department: "الهندسة",
        job_title: "مهندس",
        shift_start: "09:00",
        shift_end: "17:00",
        role: "employee",
        is_active: true,
        created_at: nowIso,
        updated_at: nowIso,
      });
    }
    store.importDatabaseState(baseState);

    const startAllNs = process.hrtime.bigint();
    let first1000Ms = 0;
    let last1000Ms = 0;
    let sliceStartNs = process.hrtime.bigint();

    for (let i = 0; i < 10_000; i += 1) {
      const empIdx = i % 100;
      const dayOffset = Math.floor(i / 100);
      const dayDate = new Date(Date.UTC(2026, 0, 1 + dayOffset)).toISOString().slice(0, 10);

      if (i === 9_000) {
        sliceStartNs = process.hrtime.bigint();
      }

      store.insertStandaloneAttendanceRecord({
        id: `att-bench-${i}`,
        employee_id: `bench-emp-${empIdx}`,
        attendance_date: dayDate,
        checked_in_at: `${dayDate}T06:05:00.000Z`,
        checked_out_at: `${dayDate}T14:05:00.000Z`,
        worked_minutes: 480,
        late_minutes: 0,
        status: "present",
        qr_token_id: null,
        idempotency_key: null,
        distance_m: 12 + (i % 50),
        notes: null,
        created_at: `${dayDate}T06:05:00.000Z`,
      });

      if (i === 999) {
        first1000Ms = Number(process.hrtime.bigint() - sliceStartNs) / 1e6;
      }
      if (i === 9_999) {
        last1000Ms = Number(process.hrtime.bigint() - sliceStartNs) / 1e6;
      }
    }

    const totalMs = Number(process.hrtime.bigint() - startAllNs) / 1e6;

    // Indexed lookup benchmark across 10,000+ rows
    const lookupStartNs = process.hrtime.bigint();
    const fetched = store.getAttendanceByEmployeeAndDate("bench-emp-42", "2026-03-10");
    const todayStats = store.getTodayStats("2026-03-10");
    const lookupMs = Number(process.hrtime.bigint() - lookupStartNs) / 1e6;

    assert.ok(fetched);
    assert.equal(todayStats.checked_in_today, 100);

    console.info(
      `[BENCHMARK] 10,000 SQLite WAL attendance writes (with AES-256-GCM GPS encryption): total=${totalMs.toFixed(1)}ms, first_1k=${first1000Ms.toFixed(1)}ms, last_1k=${last1000Ms.toFixed(1)}ms, indexed_lookup+stats=${lookupMs.toFixed(2)}ms`,
    );

    assert.ok(
      totalMs < 15_000,
      `Expected 10,000 writes under 15s, measured ${totalMs.toFixed(1)}ms`,
    );
    // Ensure last 1k doesn't degrade >3x compared to first 1k (with floor guard for tiny jitter)
    const baseline = Math.max(first1000Ms, 25);
    assert.ok(
      last1000Ms < baseline * 3,
      `Write latency degraded linearly: first_1k=${first1000Ms.toFixed(1)}ms, last_1k=${last1000Ms.toFixed(1)}ms`,
    );

    store.close();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
