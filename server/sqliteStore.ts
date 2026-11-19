import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import type { Database as SqliteDatabase, Statement } from "better-sqlite3";

export * from "./domain.ts";
import { parseJsonSafe, ALL_PERMISSION_KEYS, buildDefaultRbacRoles, buildDefaultSecurityPolicy, encryptJsonPayload, decryptJsonPayload } from "./domain.ts";
import type { UserRole, AttendanceStatus, PermissionKey, RbacRoleDefinition, SecurityPolicySettings, StoredUser, CompanySettings, KioskDevice, QrToken, AttendanceRecord, SecurityLog, RevokedJti, ActiveSession, SecurityAlertEntry, DatabaseState, RuntimeSecrets, RawUserRow, RawAttendanceRow, RawSettingsRow, RawKioskRow } from "./domain.ts";

export class SqliteAttendanceStore {
  private db: SqliteDatabase;
  private masterKey: Buffer;
  private dbPath: string;

  private stmtInsertAttendance: Statement;
  private stmtUpdateAttendanceCheckOut: Statement;
  private stmtConsumeQrToken: Statement;
  private stmtGetAttendanceByEmpDate: Statement;
  private stmtFindQrByTokenHash: Statement;
  private stmtFindQrByManualHash: Statement;
  private stmtInsertSecurityLog: Statement;
  private stmtGetUserById: Statement;
  private stmtGetUserByEmail: Statement;
  private stmtIsJtiRevoked: Statement;

  constructor(dbPath: string, masterKey: Buffer) {
    this.dbPath = dbPath;
    this.masterKey = masterKey;

    if (dbPath !== ":memory:") {
      const dir = path.dirname(dbPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      }
    }

    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = NORMAL");
    this.db.pragma("foreign_keys = ON");
    this.db.pragma("busy_timeout = 5000");

    this.initSchema();
    this.lockFilePermissions();

    this.stmtInsertAttendance = this.db.prepare(`
      INSERT INTO attendance_records (
        id, employee_id, attendance_date, checked_in_at, checked_out_at,
        worked_minutes, late_minutes, status, qr_token_id, idempotency_key,
        distance_m, gps_meta_enc, notes, created_at
      ) VALUES (
        @id, @employee_id, @attendance_date, @checked_in_at, @checked_out_at,
        @worked_minutes, @late_minutes, @status, @qr_token_id, @idempotency_key,
        NULL, @gps_meta_enc, @notes, @created_at
      )
    `);

    this.stmtUpdateAttendanceCheckOut = this.db.prepare(`
      UPDATE attendance_records
      SET checked_out_at = @checked_out_at,
          worked_minutes = @worked_minutes
      WHERE id = @id
    `);

    this.stmtConsumeQrToken = this.db.prepare(`
      UPDATE qr_tokens
      SET status = 'consumed',
          consumed_at = @consumed_at,
          consumed_by = @consumed_by,
          consumed_action = @consumed_action
      WHERE id = @id AND status = 'active'
    `);

    this.stmtGetAttendanceByEmpDate = this.db.prepare(`
      SELECT * FROM attendance_records
      WHERE employee_id = ? AND attendance_date = ?
      LIMIT 1
    `);

    this.stmtFindQrByTokenHash = this.db.prepare(`
      SELECT * FROM qr_tokens WHERE token_hash = ? LIMIT 1
    `);

    this.stmtFindQrByManualHash = this.db.prepare(`
      SELECT * FROM qr_tokens WHERE manual_code_hash = ? LIMIT 1
    `);

    this.stmtInsertSecurityLog = this.db.prepare(`
      INSERT INTO security_logs (id, user_id, event_type, reason_code, ip_hash, created_at, metadata_json)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    this.stmtGetUserById = this.db.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`);
    this.stmtGetUserByEmail = this.db.prepare(`SELECT * FROM users WHERE email = ? COLLATE NOCASE LIMIT 1`);
    this.stmtIsJtiRevoked = this.db.prepare(`SELECT 1 FROM revoked_jtis WHERE jti = ? LIMIT 1`);
  }

  private lockFilePermissions(): void {
    if (this.dbPath === ":memory:") return;
    for (const suffix of ["", "-wal", "-shm"]) {
      const target = `${this.dbPath}${suffix}`;
      if (fs.existsSync(target)) {
        try {
          fs.chmodSync(target, 0o600);
        } catch {
          // Ignore on filesystems that do not support POSIX chmod
        }
      }
    }
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS system_secrets (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        is_encrypted INTEGER NOT NULL DEFAULT 1,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS company_settings (
        id TEXT PRIMARY KEY,
        company_name TEXT NOT NULL,
        branch_name TEXT NOT NULL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        allowed_radius_m INTEGER NOT NULL,
        max_gps_accuracy_m INTEGER NOT NULL,
        qr_ttl_seconds INTEGER NOT NULL,
        timezone TEXT NOT NULL,
        work_start_time TEXT NOT NULL,
        work_end_time TEXT NOT NULL,
        late_grace_minutes INTEGER NOT NULL,
        enforce_geofence INTEGER NOT NULL,
        is_enabled INTEGER NOT NULL,
        qr_schedule_enabled INTEGER NOT NULL DEFAULT 0,
        qr_window_start TEXT NOT NULL DEFAULT '07:30',
        qr_cutoff_time TEXT NOT NULL DEFAULT '11:00',
        qr_reappear_time TEXT NOT NULL DEFAULT '15:30',
        qr_window_end TEXT NOT NULL DEFAULT '19:00',
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS security_policy (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        cloudflare_enabled INTEGER NOT NULL DEFAULT 0,
        trust_cf_headers INTEGER NOT NULL DEFAULT 0,
        allowed_countries_json TEXT NOT NULL DEFAULT '[]',
        max_cf_threat_score INTEGER NOT NULL DEFAULT 25,
        turnstile_enabled INTEGER NOT NULL DEFAULT 0,
        turnstile_site_key TEXT NOT NULL DEFAULT '',
        strict_ip_binding INTEGER NOT NULL DEFAULT 0,
        block_method_override INTEGER NOT NULL DEFAULT 1,
        enforce_json_content_type INTEGER NOT NULL DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS rbac_roles (
        role_key TEXT PRIMARY KEY,
        label_ar TEXT NOT NULL,
        label_en TEXT NOT NULL,
        permissions_json TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        token_version INTEGER NOT NULL DEFAULT 1,
        full_name TEXT NOT NULL,
        employee_number TEXT UNIQUE,
        department TEXT,
        job_title TEXT,
        shift_start TEXT NOT NULL DEFAULT '09:00',
        shift_end TEXT NOT NULL DEFAULT '17:00',
        role TEXT NOT NULL CHECK (role IN ('employee', 'kiosk', 'admin')),
        admin_role_key TEXT,
        permissions_json TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        mfa_enabled INTEGER NOT NULL DEFAULT 0,
        mfa_secret_enc TEXT,
        last_used_totp_step INTEGER,
        must_change_password INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_users_role_active ON users(role, is_active);

      CREATE TABLE IF NOT EXISTS kiosk_devices (
        id TEXT PRIMARY KEY,
        device_name TEXT NOT NULL,
        branch_name TEXT NOT NULL,
        auth_user_id TEXT NOT NULL UNIQUE,
        secret_hash TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        last_seen_at TEXT,
        revoked_before TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (auth_user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS qr_tokens (
        id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL UNIQUE,
        manual_code_hash TEXT,
        kiosk_device_id TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed_at TEXT,
        consumed_by TEXT,
        consumed_action TEXT CHECK (consumed_action IN ('check_in', 'check_out') OR consumed_action IS NULL),
        status TEXT NOT NULL CHECK (status IN ('active', 'consumed', 'expired', 'revoked')),
        FOREIGN KEY (kiosk_device_id) REFERENCES kiosk_devices(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_qr_tokens_kiosk_status ON qr_tokens(kiosk_device_id, status);
      CREATE INDEX IF NOT EXISTS idx_qr_tokens_manual ON qr_tokens(manual_code_hash);
      CREATE INDEX IF NOT EXISTS idx_qr_tokens_issued ON qr_tokens(issued_at);

      CREATE TABLE IF NOT EXISTS attendance_records (
        id TEXT PRIMARY KEY,
        employee_id TEXT NOT NULL,
        attendance_date TEXT NOT NULL,
        checked_in_at TEXT,
        checked_out_at TEXT,
        worked_minutes INTEGER,
        late_minutes INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL CHECK (status IN ('present', 'late', 'excused')),
        qr_token_id TEXT UNIQUE,
        idempotency_key TEXT,
        distance_m INTEGER,
        gps_meta_enc TEXT,
        notes TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (employee_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_attendance_emp_date ON attendance_records(employee_id, attendance_date);
      CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance_records(attendance_date);
      CREATE INDEX IF NOT EXISTS idx_attendance_emp_idempotency ON attendance_records(employee_id, idempotency_key);

      CREATE TABLE IF NOT EXISTS active_sessions (
        jti TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL,
        aal TEXT NOT NULL,
        ua_hash TEXT NOT NULL,
        ip_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_active_at TEXT NOT NULL,
        idle_expires_at TEXT NOT NULL,
        absolute_expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_active_sessions_user ON active_sessions(user_id);

      CREATE TABLE IF NOT EXISTS revoked_jtis (
        jti TEXT PRIMARY KEY,
        exp_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_revoked_jtis_exp ON revoked_jtis(exp_ms);

      CREATE TABLE IF NOT EXISTS security_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        event_type TEXT NOT NULL,
        reason_code TEXT,
        ip_hash TEXT,
        created_at TEXT NOT NULL,
        metadata_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_security_logs_created ON security_logs(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_security_logs_anomaly ON security_logs(event_type, ip_hash, created_at);

      CREATE TABLE IF NOT EXISTS security_alerts (
        id TEXT PRIMARY KEY,
        severity TEXT NOT NULL,
        event TEXT NOT NULL,
        request_id TEXT,
        ip_hash TEXT,
        created_at TEXT NOT NULL,
        details_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_security_alerts_created ON security_alerts(created_at DESC);
    `);
  }

  public isInitialized(): boolean {
    const row = this.db
      .prepare(`SELECT COUNT(*) AS cnt FROM company_settings`)
      .get() as { cnt: number };
    const secretRow = this.db
      .prepare(`SELECT COUNT(*) AS cnt FROM system_secrets WHERE key = 'auth_secret'`)
      .get() as { cnt: number };
    return row.cnt > 0 && secretRow.cnt > 0;
  }

  public close(): void {
    this.db.close();
  }

  private encryptGpsMeta(distanceM: number | null): string | null {
    if (distanceM === null || distanceM === undefined) return null;
    return encryptJsonPayload(JSON.stringify({ distance_m: distanceM }), this.masterKey);
  }

  private decryptGpsDistance(row: { distance_m: number | null; gps_meta_enc: string | null }): number | null {
    if (row.gps_meta_enc) {
      try {
        const parsed = JSON.parse(decryptJsonPayload(row.gps_meta_enc, this.masterKey)) as {
          distance_m?: number | null;
        };
        return typeof parsed.distance_m === "number" ? parsed.distance_m : null;
      } catch {
        return row.distance_m;
      }
    }
    return row.distance_m;
  }

  private mapUserRow(row: RawUserRow): StoredUser {
    return {
      id: row.id,
      email: row.email,
      password_salt: row.password_salt,
      password_hash: row.password_hash,
      token_version: row.token_version,
      full_name: row.full_name,
      employee_number: row.employee_number,
      department: row.department,
      job_title: row.job_title,
      shift_start: row.shift_start,
      shift_end: row.shift_end,
      role: row.role,
      admin_role_key: row.admin_role_key,
      permissions: row.permissions_json
        ? parseJsonSafe<PermissionKey[]>(row.permissions_json, [])
        : undefined,
      is_active: row.is_active === 1,
      mfa_enabled: row.mfa_enabled === 1,
      mfa_secret_enc: row.mfa_secret_enc,
      last_used_totp_step: row.last_used_totp_step ?? undefined,
      must_change_password: row.must_change_password === 1,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  private mapAttendanceRow(row: RawAttendanceRow): AttendanceRecord {
    return {
      id: row.id,
      employee_id: row.employee_id,
      attendance_date: row.attendance_date,
      checked_in_at: row.checked_in_at,
      checked_out_at: row.checked_out_at,
      worked_minutes: row.worked_minutes,
      late_minutes: row.late_minutes,
      status: row.status,
      qr_token_id: row.qr_token_id,
      idempotency_key: row.idempotency_key,
      distance_m: this.decryptGpsDistance(row),
      notes: row.notes,
      created_at: row.created_at,
    };
  }

  private mapSettingsRow(row: RawSettingsRow): CompanySettings {
    return {
      id: row.id,
      company_name: row.company_name,
      branch_name: row.branch_name,
      latitude: row.latitude,
      longitude: row.longitude,
      allowed_radius_m: row.allowed_radius_m,
      max_gps_accuracy_m: row.max_gps_accuracy_m,
      qr_ttl_seconds: row.qr_ttl_seconds,
      timezone: row.timezone,
      work_start_time: row.work_start_time,
      work_end_time: row.work_end_time,
      late_grace_minutes: row.late_grace_minutes,
      enforce_geofence: row.enforce_geofence === 1,
      is_enabled: row.is_enabled === 1,
      qr_schedule_enabled: row.qr_schedule_enabled === 1,
      qr_window_start: row.qr_window_start,
      qr_cutoff_time: row.qr_cutoff_time,
      qr_reappear_time: row.qr_reappear_time,
      qr_window_end: row.qr_window_end,
      updated_at: row.updated_at,
    };
  }

  private mapKioskRow(row: RawKioskRow): KioskDevice {
    return {
      id: row.id,
      device_name: row.device_name,
      branch_name: row.branch_name,
      auth_user_id: row.auth_user_id,
      secret_hash: row.secret_hash,
      is_active: row.is_active === 1,
      last_seen_at: row.last_seen_at,
      revoked_before: row.revoked_before,
      created_at: row.created_at,
    };
  }

  public importDatabaseState(state: DatabaseState): {
    users: number;
    kiosks: number;
    attendanceRecords: number;
    securityLogs: number;
  } {
    const nowIso = new Date().toISOString();
    let privPem = state.signing_private_pem;
    let pubSpki = state.signing_public_spki;
    if (!privPem || !pubSpki) {
      const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "prime256v1",
      });
      privPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
      pubSpki = Buffer.from(publicKey.export({ format: "der", type: "spki" })).toString("base64url");
    }

    const tx = this.db.transaction(() => {
      const upsertSecret = this.db.prepare(`
        INSERT INTO system_secrets (key, value, is_encrypted, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, is_encrypted = excluded.is_encrypted, updated_at = excluded.updated_at
      `);
      upsertSecret.run("auth_secret", encryptJsonPayload(state.auth_secret, this.masterKey), 1, nowIso);
      upsertSecret.run("kiosk_salt", encryptJsonPayload(state.kiosk_salt, this.masterKey), 1, nowIso);
      upsertSecret.run("ip_salt", encryptJsonPayload(state.ip_salt, this.masterKey), 1, nowIso);
      upsertSecret.run("signing_private_pem", encryptJsonPayload(privPem!, this.masterKey), 1, nowIso);
      upsertSecret.run("signing_public_spki", pubSpki!, 0, nowIso);

      const s = state.settings;
      this.db
        .prepare(`
          INSERT INTO company_settings (
            id, company_name, branch_name, latitude, longitude,
            allowed_radius_m, max_gps_accuracy_m, qr_ttl_seconds, timezone,
            work_start_time, work_end_time, late_grace_minutes, enforce_geofence, is_enabled,
            qr_schedule_enabled, qr_window_start, qr_cutoff_time, qr_reappear_time, qr_window_end, updated_at
          ) VALUES (
            @id, @company_name, @branch_name, @latitude, @longitude,
            @allowed_radius_m, @max_gps_accuracy_m, @qr_ttl_seconds, @timezone,
            @work_start_time, @work_end_time, @late_grace_minutes, @enforce_geofence, @is_enabled,
            @qr_schedule_enabled, @qr_window_start, @qr_cutoff_time, @qr_reappear_time, @qr_window_end, @updated_at
          )
          ON CONFLICT(id) DO UPDATE SET
            company_name = excluded.company_name,
            branch_name = excluded.branch_name,
            latitude = excluded.latitude,
            longitude = excluded.longitude,
            allowed_radius_m = excluded.allowed_radius_m,
            max_gps_accuracy_m = excluded.max_gps_accuracy_m,
            qr_ttl_seconds = excluded.qr_ttl_seconds,
            timezone = excluded.timezone,
            work_start_time = excluded.work_start_time,
            work_end_time = excluded.work_end_time,
            late_grace_minutes = excluded.late_grace_minutes,
            enforce_geofence = excluded.enforce_geofence,
            is_enabled = excluded.is_enabled,
            qr_schedule_enabled = excluded.qr_schedule_enabled,
            qr_window_start = excluded.qr_window_start,
            qr_cutoff_time = excluded.qr_cutoff_time,
            qr_reappear_time = excluded.qr_reappear_time,
            qr_window_end = excluded.qr_window_end,
            updated_at = excluded.updated_at
        `)
        .run({
          ...s,
          enforce_geofence: s.enforce_geofence ? 1 : 0,
          is_enabled: s.is_enabled ? 1 : 0,
          qr_schedule_enabled: s.qr_schedule_enabled ? 1 : 0,
        });

      const pol = { ...buildDefaultSecurityPolicy(), ...(state.security_policy ?? {}) };
      this.db
        .prepare(`
          INSERT INTO security_policy (
            id, cloudflare_enabled, trust_cf_headers, allowed_countries_json, max_cf_threat_score,
            turnstile_enabled, turnstile_site_key, strict_ip_binding, block_method_override, enforce_json_content_type
          ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            cloudflare_enabled = excluded.cloudflare_enabled,
            trust_cf_headers = excluded.trust_cf_headers,
            allowed_countries_json = excluded.allowed_countries_json,
            max_cf_threat_score = excluded.max_cf_threat_score,
            turnstile_enabled = excluded.turnstile_enabled,
            turnstile_site_key = excluded.turnstile_site_key,
            strict_ip_binding = excluded.strict_ip_binding,
            block_method_override = excluded.block_method_override,
            enforce_json_content_type = excluded.enforce_json_content_type
        `)
        .run(
          pol.cloudflare_enabled ? 1 : 0,
          pol.trust_cf_headers ? 1 : 0,
          JSON.stringify(pol.allowed_countries),
          pol.max_cf_threat_score,
          pol.turnstile_enabled ? 1 : 0,
          pol.turnstile_site_key,
          pol.strict_ip_binding ? 1 : 0,
          pol.block_method_override ? 1 : 0,
          pol.enforce_json_content_type ? 1 : 0,
        );

      const roles = { ...buildDefaultRbacRoles(), ...(state.rbac_roles ?? {}) };
      const upsertRole = this.db.prepare(`
        INSERT INTO rbac_roles (role_key, label_ar, label_en, permissions_json)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(role_key) DO UPDATE SET
          label_ar = excluded.label_ar,
          label_en = excluded.label_en,
          permissions_json = excluded.permissions_json
      `);
      for (const [roleKey, def] of Object.entries(roles)) {
        upsertRole.run(roleKey, def.label_ar, def.label_en, JSON.stringify(def.permissions));
      }

      const upsertUser = this.db.prepare(`
        INSERT INTO users (
          id, email, password_salt, password_hash, token_version, full_name,
          employee_number, department, job_title, shift_start, shift_end,
          role, admin_role_key, permissions_json, is_active, mfa_enabled,
          mfa_secret_enc, last_used_totp_step, must_change_password, created_at, updated_at
        ) VALUES (
          @id, @email, @password_salt, @password_hash, @token_version, @full_name,
          @employee_number, @department, @job_title, @shift_start, @shift_end,
          @role, @admin_role_key, @permissions_json, @is_active, @mfa_enabled,
          @mfa_secret_enc, @last_used_totp_step, @must_change_password, @created_at, @updated_at
        )
        ON CONFLICT(id) DO UPDATE SET
          email = excluded.email,
          password_salt = excluded.password_salt,
          password_hash = excluded.password_hash,
          token_version = excluded.token_version,
          full_name = excluded.full_name,
          employee_number = excluded.employee_number,
          department = excluded.department,
          job_title = excluded.job_title,
          shift_start = excluded.shift_start,
          shift_end = excluded.shift_end,
          role = excluded.role,
          admin_role_key = excluded.admin_role_key,
          permissions_json = excluded.permissions_json,
          is_active = excluded.is_active,
          mfa_enabled = excluded.mfa_enabled,
          mfa_secret_enc = excluded.mfa_secret_enc,
          last_used_totp_step = excluded.last_used_totp_step,
          must_change_password = excluded.must_change_password,
          updated_at = excluded.updated_at
      `);
      for (const u of state.users) {
        upsertUser.run({
          id: u.id,
          email: u.email,
          password_salt: u.password_salt,
          password_hash: u.password_hash,
          token_version: u.token_version ?? 1,
          full_name: u.full_name,
          employee_number: u.employee_number ?? null,
          department: u.department ?? null,
          job_title: u.job_title ?? null,
          shift_start: u.shift_start || "09:00",
          shift_end: u.shift_end || "17:00",
          role: u.role,
          admin_role_key: u.admin_role_key ?? (u.role === "admin" ? "super_admin" : null),
          permissions_json: u.permissions && u.permissions.length > 0 ? JSON.stringify(u.permissions) : null,
          is_active: u.is_active ? 1 : 0,
          mfa_enabled: u.mfa_enabled ? 1 : 0,
          mfa_secret_enc: u.mfa_secret_enc ?? null,
          last_used_totp_step: u.last_used_totp_step ?? null,
          must_change_password: u.must_change_password ? 1 : 0,
          created_at: u.created_at,
          updated_at: u.updated_at,
        });
      }

      const upsertKiosk = this.db.prepare(`
        INSERT INTO kiosk_devices (
          id, device_name, branch_name, auth_user_id, secret_hash, is_active, last_seen_at, revoked_before, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          device_name = excluded.device_name,
          branch_name = excluded.branch_name,
          auth_user_id = excluded.auth_user_id,
          secret_hash = excluded.secret_hash,
          is_active = excluded.is_active,
          last_seen_at = excluded.last_seen_at,
          revoked_before = excluded.revoked_before
      `);
      for (const d of state.kiosk_devices) {
        upsertKiosk.run(
          d.id,
          d.device_name,
          d.branch_name,
          d.auth_user_id,
          d.secret_hash,
          d.is_active ? 1 : 0,
          d.last_seen_at ?? null,
          d.revoked_before ?? null,
          d.created_at,
        );
      }

      const upsertToken = this.db.prepare(`
        INSERT INTO qr_tokens (
          id, token_hash, manual_code_hash, kiosk_device_id, issued_at, expires_at,
          consumed_at, consumed_by, consumed_action, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO NOTHING
      `);
      for (const t of state.qr_tokens ?? []) {
        upsertToken.run(
          t.id,
          t.token_hash,
          t.manual_code_hash ?? null,
          t.kiosk_device_id,
          t.issued_at,
          t.expires_at,
          t.consumed_at ?? null,
          t.consumed_by ?? null,
          t.consumed_action ?? null,
          t.status,
        );
      }

      const upsertAtt = this.db.prepare(`
        INSERT INTO attendance_records (
          id, employee_id, attendance_date, checked_in_at, checked_out_at,
          worked_minutes, late_minutes, status, qr_token_id, idempotency_key,
          distance_m, gps_meta_enc, notes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
        ON CONFLICT(employee_id, attendance_date) DO UPDATE SET
          checked_in_at = excluded.checked_in_at,
          checked_out_at = excluded.checked_out_at,
          worked_minutes = excluded.worked_minutes,
          late_minutes = excluded.late_minutes,
          status = excluded.status,
          qr_token_id = excluded.qr_token_id,
          idempotency_key = excluded.idempotency_key,
          distance_m = NULL,
          gps_meta_enc = excluded.gps_meta_enc,
          notes = excluded.notes
      `);
      for (const r of state.attendance_records ?? []) {
        upsertAtt.run(
          r.id,
          r.employee_id,
          r.attendance_date,
          r.checked_in_at ?? null,
          r.checked_out_at ?? null,
          r.worked_minutes ?? null,
          r.late_minutes ?? 0,
          r.status,
          r.qr_token_id ?? null,
          r.idempotency_key ?? null,
          this.encryptGpsMeta(r.distance_m ?? null),
          r.notes ?? null,
          r.created_at,
        );
      }

      const upsertLog = this.db.prepare(`
        INSERT INTO security_logs (id, user_id, event_type, reason_code, ip_hash, created_at, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO NOTHING
      `);
      for (const l of state.security_logs ?? []) {
        upsertLog.run(
          l.id,
          l.user_id ?? null,
          l.event_type,
          l.reason_code ?? null,
          l.ip_hash ?? null,
          l.created_at,
          JSON.stringify(l.metadata ?? {}),
        );
      }

      const upsertAlert = this.db.prepare(`
        INSERT INTO security_alerts (id, severity, event, request_id, ip_hash, created_at, details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO NOTHING
      `);
      for (const a of state.security_alerts ?? []) {
        upsertAlert.run(
          a.id,
          a.severity,
          a.event,
          a.request_id ?? null,
          a.ip_hash ?? null,
          a.created_at,
          JSON.stringify(a.details ?? {}),
        );
      }

      const upsertSession = this.db.prepare(`
        INSERT INTO active_sessions (
          jti, user_id, role, aal, ua_hash, ip_hash, created_at, last_active_at, idle_expires_at, absolute_expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(jti) DO NOTHING
      `);
      for (const sess of state.active_sessions ?? []) {
        upsertSession.run(
          sess.jti,
          sess.user_id,
          sess.role,
          sess.aal,
          sess.ua_hash,
          sess.ip_hash,
          sess.created_at,
          sess.last_active_at,
          sess.idle_expires_at,
          sess.absolute_expires_at,
        );
      }

      const upsertJti = this.db.prepare(`
        INSERT INTO revoked_jtis (jti, exp_ms) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING
      `);
      for (const r of state.revoked_jtis ?? []) {
        upsertJti.run(r.jti, r.exp_ms);
      }
    });

    tx();
    return {
      users: state.users.length,
      kiosks: state.kiosk_devices.length,
      attendanceRecords: (state.attendance_records ?? []).length,
      securityLogs: (state.security_logs ?? []).length,
    };
  }

  public getRuntimeSecrets(): RuntimeSecrets {
    const rows = this.db
      .prepare(`SELECT key, value, is_encrypted FROM system_secrets`)
      .all() as Array<{ key: string; value: string; is_encrypted: number }>;
    const map = new Map<string, string>();
    for (const row of rows) {
      map.set(
        row.key,
        row.is_encrypted === 1 ? decryptJsonPayload(row.value, this.masterKey) : row.value,
      );
    }
    const auth_secret = map.get("auth_secret");
    const kiosk_salt = map.get("kiosk_salt");
    const ip_salt = map.get("ip_salt");
    let signing_private_pem = map.get("signing_private_pem");
    let signing_public_spki = map.get("signing_public_spki");
    if (!auth_secret || !kiosk_salt || !ip_salt) {
      throw new Error("FATAL: Missing encrypted runtime secrets in SQLite system_secrets.");
    }
    if (!signing_private_pem || !signing_public_spki) {
      const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "prime256v1",
      });
      signing_private_pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
      signing_public_spki = Buffer.from(
        publicKey.export({ format: "der", type: "spki" }),
      ).toString("base64url");
      const nowIso = new Date().toISOString();
      const upsert = this.db.prepare(`
        INSERT INTO system_secrets (key, value, is_encrypted, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, is_encrypted = excluded.is_encrypted, updated_at = excluded.updated_at
      `);
      upsert.run("signing_private_pem", encryptJsonPayload(signing_private_pem, this.masterKey), 1, nowIso);
      upsert.run("signing_public_spki", signing_public_spki, 0, nowIso);
    }
    return { auth_secret, kiosk_salt, ip_salt, signing_private_pem, signing_public_spki };
  }

  public getSettings(): CompanySettings {
    const row = this.db
      .prepare(`SELECT * FROM company_settings LIMIT 1`)
      .get() as RawSettingsRow | undefined;
    if (!row) {
      throw new Error("FATAL: company_settings missing from SQLite store.");
    }
    return this.mapSettingsRow(row);
  }

  public updateSettings(next: CompanySettings): void {
    this.db
      .prepare(`
        UPDATE company_settings SET
          company_name = @company_name,
          branch_name = @branch_name,
          latitude = @latitude,
          longitude = @longitude,
          allowed_radius_m = @allowed_radius_m,
          max_gps_accuracy_m = @max_gps_accuracy_m,
          qr_ttl_seconds = @qr_ttl_seconds,
          timezone = @timezone,
          work_start_time = @work_start_time,
          work_end_time = @work_end_time,
          late_grace_minutes = @late_grace_minutes,
          enforce_geofence = @enforce_geofence,
          is_enabled = @is_enabled,
          qr_schedule_enabled = @qr_schedule_enabled,
          qr_window_start = @qr_window_start,
          qr_cutoff_time = @qr_cutoff_time,
          qr_reappear_time = @qr_reappear_time,
          qr_window_end = @qr_window_end,
          updated_at = @updated_at
        WHERE id = @id
      `)
      .run({
        ...next,
        enforce_geofence: next.enforce_geofence ? 1 : 0,
        is_enabled: next.is_enabled ? 1 : 0,
        qr_schedule_enabled: next.qr_schedule_enabled ? 1 : 0,
      });
  }

  public getSecurityPolicy(): SecurityPolicySettings {
    const row = this.db
      .prepare(`SELECT * FROM security_policy WHERE id = 1`)
      .get() as
      | {
          cloudflare_enabled: number;
          trust_cf_headers: number;
          allowed_countries_json: string;
          max_cf_threat_score: number;
          turnstile_enabled: number;
          turnstile_site_key: string;
          strict_ip_binding: number;
          block_method_override: number;
          enforce_json_content_type: number;
        }
      | undefined;
    if (!row) return buildDefaultSecurityPolicy();
    return {
      cloudflare_enabled: row.cloudflare_enabled === 1,
      trust_cf_headers: row.trust_cf_headers === 1,
      allowed_countries: parseJsonSafe<string[]>(row.allowed_countries_json, []),
      max_cf_threat_score: row.max_cf_threat_score,
      turnstile_enabled: row.turnstile_enabled === 1,
      turnstile_site_key: row.turnstile_site_key,
      strict_ip_binding: row.strict_ip_binding === 1,
      block_method_override: row.block_method_override === 1,
      enforce_json_content_type: row.enforce_json_content_type === 1,
    };
  }

  public updateSecurityPolicy(policy: SecurityPolicySettings): void {
    this.db
      .prepare(`
        INSERT INTO security_policy (
          id, cloudflare_enabled, trust_cf_headers, allowed_countries_json, max_cf_threat_score,
          turnstile_enabled, turnstile_site_key, strict_ip_binding, block_method_override, enforce_json_content_type
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          cloudflare_enabled = excluded.cloudflare_enabled,
          trust_cf_headers = excluded.trust_cf_headers,
          allowed_countries_json = excluded.allowed_countries_json,
          max_cf_threat_score = excluded.max_cf_threat_score,
          turnstile_enabled = excluded.turnstile_enabled,
          turnstile_site_key = excluded.turnstile_site_key,
          strict_ip_binding = excluded.strict_ip_binding,
          block_method_override = excluded.block_method_override,
          enforce_json_content_type = excluded.enforce_json_content_type
      `)
      .run(
        policy.cloudflare_enabled ? 1 : 0,
        policy.trust_cf_headers ? 1 : 0,
        JSON.stringify(policy.allowed_countries),
        policy.max_cf_threat_score,
        policy.turnstile_enabled ? 1 : 0,
        policy.turnstile_site_key,
        policy.strict_ip_binding ? 1 : 0,
        policy.block_method_override ? 1 : 0,
        policy.enforce_json_content_type ? 1 : 0,
      );
  }

  public getRbacRoles(): Record<string, RbacRoleDefinition> {
    const rows = this.db
      .prepare(`SELECT role_key, label_ar, label_en, permissions_json FROM rbac_roles`)
      .all() as Array<{
      role_key: string;
      label_ar: string;
      label_en: string;
      permissions_json: string;
    }>;
    const out: Record<string, RbacRoleDefinition> = {};
    for (const r of rows) {
      out[r.role_key] = {
        label_ar: r.label_ar,
        label_en: r.label_en,
        permissions: parseJsonSafe<PermissionKey[]>(r.permissions_json, []),
      };
    }
    return Object.keys(out).length > 0 ? out : buildDefaultRbacRoles();
  }

  public updateRbacRolePermissions(
    roleKey: string,
    permissions: PermissionKey[],
  ): Record<string, RbacRoleDefinition> | null {
    const res = this.db
      .prepare(`UPDATE rbac_roles SET permissions_json = ? WHERE role_key = ?`)
      .run(JSON.stringify(permissions), roleKey);
    if (res.changes === 0) return null;
    return this.getRbacRoles();
  }

  public getUserById(id: string): StoredUser | null {
    const row = this.stmtGetUserById.get(id) as RawUserRow | undefined;
    return row ? this.mapUserRow(row) : null;
  }

  public getUserByEmail(email: string): StoredUser | null {
    const row = this.stmtGetUserByEmail.get(email) as RawUserRow | undefined;
    return row ? this.mapUserRow(row) : null;
  }

  public getUserByEmployeeNumber(employeeNumber: string): StoredUser | null {
    const row = this.db
      .prepare(`SELECT * FROM users WHERE employee_number = ? LIMIT 1`)
      .get(employeeNumber) as RawUserRow | undefined;
    return row ? this.mapUserRow(row) : null;
  }

  public listUsersByRole(role: UserRole): StoredUser[] {
    const rows = this.db
      .prepare(`SELECT * FROM users WHERE role = ? ORDER BY created_at ASC`)
      .all(role) as RawUserRow[];
    return rows.map((r) => this.mapUserRow(r));
  }

  public listStaffUsers(): StoredUser[] {
    const rows = this.db
      .prepare(`SELECT * FROM users WHERE role IN ('admin', 'employee') ORDER BY created_at ASC`)
      .all() as RawUserRow[];
    return rows.map((r) => this.mapUserRow(r));
  }

  public createUser(user: StoredUser): void {
    this.db
      .prepare(`
        INSERT INTO users (
          id, email, password_salt, password_hash, token_version, full_name,
          employee_number, department, job_title, shift_start, shift_end,
          role, admin_role_key, permissions_json, is_active, mfa_enabled,
          mfa_secret_enc, last_used_totp_step, must_change_password, created_at, updated_at
        ) VALUES (
          @id, @email, @password_salt, @password_hash, @token_version, @full_name,
          @employee_number, @department, @job_title, @shift_start, @shift_end,
          @role, @admin_role_key, @permissions_json, @is_active, @mfa_enabled,
          @mfa_secret_enc, @last_used_totp_step, @must_change_password, @created_at, @updated_at
        )
      `)
      .run({
        id: user.id,
        email: user.email,
        password_salt: user.password_salt,
        password_hash: user.password_hash,
        token_version: user.token_version,
        full_name: user.full_name,
        employee_number: user.employee_number,
        department: user.department,
        job_title: user.job_title,
        shift_start: user.shift_start,
        shift_end: user.shift_end,
        role: user.role,
        admin_role_key: user.admin_role_key ?? null,
        permissions_json:
          user.permissions && user.permissions.length > 0 ? JSON.stringify(user.permissions) : null,
        is_active: user.is_active ? 1 : 0,
        mfa_enabled: user.mfa_enabled ? 1 : 0,
        mfa_secret_enc: user.mfa_secret_enc ?? null,
        last_used_totp_step: user.last_used_totp_step ?? null,
        must_change_password: user.must_change_password ? 1 : 0,
        created_at: user.created_at,
        updated_at: user.updated_at,
      });
  }

  public updateEmployee(
    employeeId: string,
    updates: {
      full_name?: string;
      department?: string;
      job_title?: string;
      shift_start?: string;
      shift_end?: string;
      is_active?: boolean;
    },
    updatedAt: string,
  ): StoredUser | null {
    const tx = this.db.transaction(() => {
      const current = this.getUserById(employeeId);
      if (!current || current.role !== "employee") return null;

      const deactivated = updates.is_active === false && current.is_active;
      const nextTokenVersion = deactivated ? current.token_version + 1 : current.token_version;

      this.db
        .prepare(`
          UPDATE users SET
            full_name = ?,
            department = ?,
            job_title = ?,
            shift_start = ?,
            shift_end = ?,
            is_active = ?,
            token_version = ?,
            updated_at = ?
          WHERE id = ?
        `)
        .run(
          updates.full_name ?? current.full_name,
          updates.department ?? current.department,
          updates.job_title ?? current.job_title,
          updates.shift_start ?? current.shift_start,
          updates.shift_end ?? current.shift_end,
          (updates.is_active ?? current.is_active) ? 1 : 0,
          nextTokenVersion,
          updatedAt,
          employeeId,
        );

      if (deactivated) {
        this.revokeAllSessionsForUser(employeeId);
      }

      return this.getUserById(employeeId);
    });
    return tx();
  }

  public updateUserPassword(
    userId: string,
    newSalt: string,
    newHash: string,
    updatedAt: string,
  ): StoredUser | null {
    const tx = this.db.transaction(() => {
      this.db
        .prepare(`
          UPDATE users
          SET password_salt = ?, password_hash = ?, token_version = token_version + 1,
              must_change_password = 0, updated_at = ?
          WHERE id = ?
        `)
        .run(newSalt, newHash, updatedAt, userId);
      this.revokeAllSessionsForUser(userId);
      return this.getUserById(userId);
    });
    return tx();
  }

  public decryptUserMfaSecret(user: StoredUser): string | null {
    if (!user.mfa_secret_enc) return null;
    return decryptJsonPayload(user.mfa_secret_enc, this.masterKey);
  }

  public updateUserLastTotpStep(userId: string, matchedStep: number): void {
    this.db
      .prepare(`UPDATE users SET last_used_totp_step = ? WHERE id = ?`)
      .run(matchedStep, userId);
  }

  public activateUserMfa(
    userId: string,
    plainSecret: string,
    matchedStep: number,
    updatedAt: string,
  ): void {
    const mfaSecretEnc = encryptJsonPayload(plainSecret, this.masterKey);
    this.db
      .prepare(`
        UPDATE users
        SET mfa_secret_enc = ?, mfa_enabled = 1, last_used_totp_step = ?, updated_at = ?
        WHERE id = ?
      `)
      .run(mfaSecretEnc, matchedStep, updatedAt, userId);
  }

  public updateUserRbac(
    userId: string,
    role: "employee" | "admin",
    adminRoleKey: string | null,
    permissions: PermissionKey[] | undefined,
    updatedAt: string,
  ): StoredUser | null {
    const tx = this.db.transaction(() => {
      this.db
        .prepare(`
          UPDATE users
          SET role = ?,
              admin_role_key = ?,
              permissions_json = ?,
              token_version = token_version + 1,
              updated_at = ?
          WHERE id = ?
        `)
        .run(
          role,
          adminRoleKey,
          permissions && permissions.length > 0 ? JSON.stringify(permissions) : null,
          updatedAt,
          userId,
        );
      this.revokeAllSessionsForUser(userId);
      return this.getUserById(userId);
    });
    return tx();
  }

  public assertNoDefaultCredentialsInProduction(
    isProduction: boolean,
    verifyPasswordFn: (pwd: string, salt: string, hash: string) => boolean,
    hashPasswordFn: (pwd: string, salt: string) => string,
    sha256Fn: (val: string) => string,
    constantTimeEqualFn: (a: string, b: string) => boolean,
    kioskSalt: string,
  ): boolean {
    if (!isProduction) return false;
    const forbiddenDemoPasswords = ["Admin@2026", "Emp@2026", "Kiosk@2026"];
    const nowIso = new Date().toISOString();
    let sanitized = false;

    const tx = this.db.transaction(() => {
      const activeUsers = this.db
        .prepare(`SELECT * FROM users WHERE is_active = 1`)
        .all() as RawUserRow[];

      const deactivateUserStmt = this.db.prepare(`
        UPDATE users
        SET password_salt = ?, password_hash = ?, token_version = token_version + 1, is_active = 0, updated_at = ?
        WHERE id = ?
      `);

      for (const row of activeUsers) {
        for (const demoPwd of forbiddenDemoPasswords) {
          if (verifyPasswordFn(demoPwd, row.password_salt, row.password_hash)) {
            const rotatedPwd = `${crypto.randomBytes(24).toString("base64url")}9A`;
            const newSalt = crypto.randomBytes(16).toString("hex");
            deactivateUserStmt.run(newSalt, hashPasswordFn(rotatedPwd, newSalt), nowIso, row.id);
            sanitized = true;
            break;
          }
        }
      }

      const demoKioskHash = sha256Fn(`${kioskSalt}:KIOSK-HQ-2026`);
      const activeKiosks = this.db
        .prepare(`SELECT id, secret_hash FROM kiosk_devices WHERE is_active = 1`)
        .all() as Array<{ id: string; secret_hash: string }>;
      const rotateKioskStmt = this.db.prepare(`
        UPDATE kiosk_devices SET secret_hash = ?, revoked_before = ? WHERE id = ?
      `);
      for (const dev of activeKiosks) {
        if (constantTimeEqualFn(dev.secret_hash, demoKioskHash)) {
          const rotatedHash = sha256Fn(`${kioskSalt}:${crypto.randomBytes(24).toString("base64url")}`);
          rotateKioskStmt.run(rotatedHash, nowIso, dev.id);
          sanitized = true;
        }
      }
    });

    tx();
    if (sanitized) {
      console.warn(
        "[SECURITY NOTICE] Deactivated and rotated inherited development demo credentials for production startup.",
      );
    }
    return sanitized;
  }

  public getKioskByAuthUserId(authUserId: string): KioskDevice | null {
    const row = this.db
      .prepare(`SELECT * FROM kiosk_devices WHERE auth_user_id = ? LIMIT 1`)
      .get(authUserId) as RawKioskRow | undefined;
    return row ? this.mapKioskRow(row) : null;
  }

  public getKioskById(kioskId: string): KioskDevice | null {
    const row = this.db
      .prepare(`SELECT * FROM kiosk_devices WHERE id = ? LIMIT 1`)
      .get(kioskId) as RawKioskRow | undefined;
    return row ? this.mapKioskRow(row) : null;
  }

  public listKiosksWithEmail(): Array<{
    id: string;
    device_name: string;
    branch_name: string;
    auth_email: string;
    is_active: boolean;
    last_seen_at: string | null;
    revoked_before: string | null;
    created_at: string;
  }> {
    const rows = this.db
      .prepare(`
        SELECT k.*, u.email AS auth_email
        FROM kiosk_devices k
        LEFT JOIN users u ON u.id = k.auth_user_id
        ORDER BY k.created_at ASC
      `)
      .all() as RawKioskRow[];
    return rows.map((r) => ({
      id: r.id,
      device_name: r.device_name,
      branch_name: r.branch_name,
      auth_email: r.auth_email ?? "—",
      is_active: r.is_active === 1,
      last_seen_at: r.last_seen_at,
      revoked_before: r.revoked_before,
      created_at: r.created_at,
    }));
  }

  public createKioskWithUser(kioskUser: StoredUser, device: KioskDevice): void {
    const tx = this.db.transaction(() => {
      this.createUser(kioskUser);
      this.db
        .prepare(`
          INSERT INTO kiosk_devices (
            id, device_name, branch_name, auth_user_id, secret_hash, is_active, last_seen_at, revoked_before, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          device.id,
          device.device_name,
          device.branch_name,
          device.auth_user_id,
          device.secret_hash,
          device.is_active ? 1 : 0,
          device.last_seen_at,
          device.revoked_before,
          device.created_at,
        );
    });
    tx();
  }

  public updateKioskDevice(
    kioskId: string,
    updates: { device_name?: string; branch_name?: string; is_active?: boolean },
    nowIso: string,
  ): {
    id: string;
    device_name: string;
    branch_name: string;
    auth_email: string;
    is_active: boolean;
    last_seen_at: string | null;
    revoked_before: string | null;
    created_at: string;
  } | null {
    const tx = this.db.transaction(() => {
      const current = this.getKioskById(kioskId);
      if (!current) return null;

      const nextActive = updates.is_active ?? current.is_active;
      const nextRevokedBefore =
        updates.is_active === false ? nowIso : current.revoked_before;

      this.db
        .prepare(`
          UPDATE kiosk_devices
          SET device_name = ?, branch_name = ?, is_active = ?, revoked_before = ?
          WHERE id = ?
        `)
        .run(
          updates.device_name ?? current.device_name,
          updates.branch_name ?? current.branch_name,
          nextActive ? 1 : 0,
          nextRevokedBefore,
          kioskId,
        );

      if (updates.is_active !== undefined) {
        if (!updates.is_active) {
          this.db
            .prepare(`
              UPDATE users
              SET is_active = 0, token_version = token_version + 1, updated_at = ?
              WHERE id = ?
            `)
            .run(nowIso, current.auth_user_id);
          this.revokeAllSessionsForUser(current.auth_user_id);
          this.db
            .prepare(`UPDATE qr_tokens SET status = 'revoked' WHERE kiosk_device_id = ? AND status = 'active'`)
            .run(kioskId);
        } else {
          this.db
            .prepare(`UPDATE users SET is_active = 1, updated_at = ? WHERE id = ?`)
            .run(nowIso, current.auth_user_id);
        }
      }

      const row = this.db
        .prepare(`
          SELECT k.*, u.email AS auth_email
          FROM kiosk_devices k
          LEFT JOIN users u ON u.id = k.auth_user_id
          WHERE k.id = ?
          LIMIT 1
        `)
        .get(kioskId) as RawKioskRow | undefined;
      if (!row) return null;
      return {
        id: row.id,
        device_name: row.device_name,
        branch_name: row.branch_name,
        auth_email: row.auth_email ?? "—",
        is_active: row.is_active === 1,
        last_seen_at: row.last_seen_at,
        revoked_before: row.revoked_before,
        created_at: row.created_at,
      };
    });
    return tx();
  }

  public revokeKioskSession(deviceId: string, nowIso: string, newSecretHash?: string): boolean {
    const tx = this.db.transaction(() => {
      const exists = this.getKioskById(deviceId);
      if (!exists) return false;
      if (newSecretHash) {
        this.db
          .prepare(`UPDATE kiosk_devices SET revoked_before = ?, secret_hash = ? WHERE id = ?`)
          .run(nowIso, newSecretHash, deviceId);
      } else {
        this.db
          .prepare(`UPDATE kiosk_devices SET revoked_before = ? WHERE id = ?`)
          .run(nowIso, deviceId);
      }
      this.db
        .prepare(`UPDATE qr_tokens SET status = 'revoked' WHERE kiosk_device_id = ? AND status = 'active'`)
        .run(deviceId);
      return true;
    });
    return tx();
  }

  public closeKioskQrWindow(deviceId: string, nowIso: string): void {
    const tx = this.db.transaction(() => {
      this.db
        .prepare(`UPDATE qr_tokens SET status = 'revoked' WHERE kiosk_device_id = ? AND status = 'active'`)
        .run(deviceId);
      this.db
        .prepare(`UPDATE kiosk_devices SET last_seen_at = ? WHERE id = ?`)
        .run(nowIso, deviceId);
    });
    tx();
  }

  public issueQrToken(deviceId: string, token: QrToken, nowIso: string): void {
    const tx = this.db.transaction(() => {
      this.db
        .prepare(`
          UPDATE qr_tokens
          SET status = CASE WHEN expires_at <= ? THEN 'expired' ELSE 'revoked' END
          WHERE kiosk_device_id = ? AND status = 'active'
        `)
        .run(nowIso, deviceId);

      this.db
        .prepare(`
          INSERT INTO qr_tokens (
            id, token_hash, manual_code_hash, kiosk_device_id, issued_at, expires_at,
            consumed_at, consumed_by, consumed_action, status
          ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 'active')
        `)
        .run(
          token.id,
          token.token_hash,
          token.manual_code_hash ?? null,
          deviceId,
          token.issued_at,
          token.expires_at,
        );

      this.db
        .prepare(`UPDATE kiosk_devices SET last_seen_at = ? WHERE id = ?`)
        .run(nowIso, deviceId);
    });
    tx();
  }

  public getQrTokenForKiosk(tokenId: string, kioskDeviceId: string): QrToken | null {
    const row = this.db
      .prepare(`SELECT * FROM qr_tokens WHERE id = ? AND kiosk_device_id = ? LIMIT 1`)
      .get(tokenId, kioskDeviceId) as QrToken | undefined;
    return row ?? null;
  }

  public updateQrTokenStatus(tokenId: string, status: QrToken["status"]): void {
    this.db.prepare(`UPDATE qr_tokens SET status = ? WHERE id = ?`).run(status, tokenId);
  }

  public touchKioskLastSeen(kioskDeviceId: string, nowIso: string): void {
    this.db
      .prepare(`UPDATE kiosk_devices SET last_seen_at = ? WHERE id = ?`)
      .run(nowIso, kioskDeviceId);
  }

  public findQrTokenForScan(
    tokenHash: string,
    manualCodeHash: string | null,
  ): { token: QrToken; entryMethod: "qr_scan" | "manual_code" } | null {
    const byQr = this.stmtFindQrByTokenHash.get(tokenHash) as QrToken | undefined;
    if (byQr) return { token: byQr, entryMethod: "qr_scan" };
    if (manualCodeHash) {
      const byManual = this.stmtFindQrByManualHash.get(manualCodeHash) as QrToken | undefined;
      if (byManual) return { token: byManual, entryMethod: "manual_code" };
    }
    return null;
  }

  public hasAttendanceIdempotencyKey(employeeId: string, idempotencyKey: string): boolean {
    const row = this.db
      .prepare(`SELECT 1 FROM attendance_records WHERE employee_id = ? AND idempotency_key = ? LIMIT 1`)
      .get(employeeId, idempotencyKey);
    return Boolean(row);
  }

  public getAttendanceByEmployeeAndDate(employeeId: string, attendanceDate: string): AttendanceRecord | null {
    const row = this.stmtGetAttendanceByEmpDate.get(employeeId, attendanceDate) as RawAttendanceRow | undefined;
    return row ? this.mapAttendanceRow(row) : null;
  }

  public getEmployeeAttendanceHistory(employeeId: string, limit = 60): AttendanceRecord[] {
    const rows = this.db
      .prepare(`
        SELECT * FROM attendance_records
        WHERE employee_id = ?
        ORDER BY attendance_date DESC
        LIMIT ?
      `)
      .all(employeeId, limit) as RawAttendanceRow[];
    return rows.map((r) => this.mapAttendanceRow(r));
  }

  public insertStandaloneAttendanceRecord(record: AttendanceRecord): void {
    this.stmtInsertAttendance.run({
      id: record.id,
      employee_id: record.employee_id,
      attendance_date: record.attendance_date,
      checked_in_at: record.checked_in_at,
      checked_out_at: record.checked_out_at,
      worked_minutes: record.worked_minutes,
      late_minutes: record.late_minutes,
      status: record.status,
      qr_token_id: record.qr_token_id,
      idempotency_key: record.idempotency_key,
      gps_meta_enc: this.encryptGpsMeta(record.distance_m),
      notes: record.notes,
      created_at: record.created_at,
    });
  }

  public commitCheckInScan(params: {
    tokenId: string;
    employeeId: string;
    nowIso: string;
    record: AttendanceRecord;
    securityLog: SecurityLog;
  }): void {
    const tx = this.db.transaction(() => {
      const consumeRes = this.stmtConsumeQrToken.run({
        id: params.tokenId,
        consumed_at: params.nowIso,
        consumed_by: params.employeeId,
        consumed_action: "check_in",
      });
      if (consumeRes.changes !== 1) {
        throw new Error("QR_ALREADY_CONSUMED");
      }

      this.stmtInsertAttendance.run({
        id: params.record.id,
        employee_id: params.record.employee_id,
        attendance_date: params.record.attendance_date,
        checked_in_at: params.record.checked_in_at,
        checked_out_at: params.record.checked_out_at,
        worked_minutes: params.record.worked_minutes,
        late_minutes: params.record.late_minutes,
        status: params.record.status,
        qr_token_id: params.record.qr_token_id,
        idempotency_key: params.record.idempotency_key,
        gps_meta_enc: this.encryptGpsMeta(params.record.distance_m),
        notes: params.record.notes,
        created_at: params.record.created_at,
      });

      this.stmtInsertSecurityLog.run(
        params.securityLog.id,
        params.securityLog.user_id,
        params.securityLog.event_type,
        params.securityLog.reason_code,
        params.securityLog.ip_hash,
        params.securityLog.created_at,
        JSON.stringify(params.securityLog.metadata),
      );
    });
    tx();
  }

  public commitCheckOutScan(params: {
    tokenId: string;
    employeeId: string;
    recordId: string;
    nowIso: string;
    workedMinutes: number;
    securityLog: SecurityLog;
  }): void {
    const tx = this.db.transaction(() => {
      const consumeRes = this.stmtConsumeQrToken.run({
        id: params.tokenId,
        consumed_at: params.nowIso,
        consumed_by: params.employeeId,
        consumed_action: "check_out",
      });
      if (consumeRes.changes !== 1) {
        throw new Error("QR_ALREADY_CONSUMED");
      }

      this.stmtUpdateAttendanceCheckOut.run({
        id: params.recordId,
        checked_out_at: params.nowIso,
        worked_minutes: params.workedMinutes,
      });

      this.stmtInsertSecurityLog.run(
        params.securityLog.id,
        params.securityLog.user_id,
        params.securityLog.event_type,
        params.securityLog.reason_code,
        params.securityLog.ip_hash,
        params.securityLog.created_at,
        JSON.stringify(params.securityLog.metadata),
      );
    });
    tx();
  }

  public upsertExcuseRecord(
    employeeId: string,
    attendanceDate: string,
    notes: string,
    nowIso: string,
  ): void {
    this.db
      .prepare(`
        INSERT INTO attendance_records (
          id, employee_id, attendance_date, checked_in_at, checked_out_at,
          worked_minutes, late_minutes, status, qr_token_id, idempotency_key,
          distance_m, gps_meta_enc, notes, created_at
        ) VALUES (?, ?, ?, NULL, NULL, NULL, 0, 'excused', NULL, NULL, NULL, NULL, ?, ?)
        ON CONFLICT(employee_id, attendance_date) DO UPDATE SET
          status = 'excused',
          late_minutes = 0,
          notes = excluded.notes
      `)
      .run(`att-${crypto.randomUUID()}`, employeeId, attendanceDate, notes, nowIso);
  }

  public getTodayStats(todayDate: string): {
    total_active_employees: number;
    checked_in_today: number;
    on_shift_now: number;
    checked_out_today: number;
    late_today: number;
    excused_today: number;
    not_checked_in_today: number;
  } {
    const activeEmpRow = this.db
      .prepare(`SELECT COUNT(*) AS cnt FROM users WHERE role = 'employee' AND is_active = 1`)
      .get() as { cnt: number };

    const todayAgg = this.db
      .prepare(`
        SELECT
          COUNT(CASE WHEN checked_in_at IS NOT NULL THEN 1 END) AS checked_in_today,
          COUNT(CASE WHEN checked_in_at IS NOT NULL AND checked_out_at IS NULL THEN 1 END) AS on_shift_now,
          COUNT(CASE WHEN checked_out_at IS NOT NULL THEN 1 END) AS checked_out_today,
          COUNT(CASE WHEN status = 'late' THEN 1 END) AS late_today,
          COUNT(CASE WHEN status = 'excused' THEN 1 END) AS excused_today,
          COUNT(DISTINCT CASE WHEN u.is_active = 1 AND u.role = 'employee' THEN a.employee_id END) AS accounted_active
        FROM attendance_records a
        LEFT JOIN users u ON u.id = a.employee_id
        WHERE a.attendance_date = ?
      `)
      .get(todayDate) as {
      checked_in_today: number;
      on_shift_now: number;
      checked_out_today: number;
      late_today: number;
      excused_today: number;
      accounted_active: number;
    };

    return {
      total_active_employees: activeEmpRow.cnt,
      checked_in_today: todayAgg.checked_in_today,
      on_shift_now: todayAgg.on_shift_now,
      checked_out_today: todayAgg.checked_out_today,
      late_today: todayAgg.late_today,
      excused_today: todayAgg.excused_today,
      not_checked_in_today: Math.max(0, activeEmpRow.cnt - todayAgg.accounted_active),
    };
  }

  public listEnrichedAttendanceRecords(limit = 500): Array<
    AttendanceRecord & {
      employee_name: string;
      employee_number: string | null;
      department: string | null;
      job_title: string | null;
    }
  > {
    const rows = this.db
      .prepare(`
        SELECT a.*, u.full_name AS employee_name, u.employee_number, u.department, u.job_title
        FROM attendance_records a
        LEFT JOIN users u ON u.id = a.employee_id
        ORDER BY a.attendance_date DESC, COALESCE(a.checked_in_at, a.created_at) DESC
        LIMIT ?
      `)
      .all(limit) as Array<
      RawAttendanceRow & {
        employee_name: string | null;
        employee_number: string | null;
        department: string | null;
        job_title: string | null;
      }
    >;

    return rows.map((r) => ({
      ...this.mapAttendanceRow(r),
      employee_name: r.employee_name ?? "—",
      employee_number: r.employee_number ?? null,
      department: r.department ?? null,
      job_title: r.job_title ?? null,
    }));
  }

  public queryAttendanceForExport(params: {
    fromDate?: string;
    toDate?: string;
    department?: string;
    statusFilter?: string;
    limit?: number;
  }): Array<
    AttendanceRecord & {
      employee_name: string;
      employee_number: string | null;
      department: string | null;
      job_title: string | null;
    }
  > {
    const conditions: string[] = [];
    const args: unknown[] = [];

    if (params.fromDate) {
      conditions.push("a.attendance_date >= ?");
      args.push(params.fromDate);
    }
    if (params.toDate) {
      conditions.push("a.attendance_date <= ?");
      args.push(params.toDate);
    }
    if (params.statusFilter) {
      conditions.push("a.status = ?");
      args.push(params.statusFilter);
    }
    if (params.department) {
      conditions.push("u.department = ?");
      args.push(params.department);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const rowLimit = params.limit ?? 50_001;
    args.push(rowLimit);

    const rows = this.db
      .prepare(`
        SELECT a.*, u.full_name AS employee_name, u.employee_number, u.department, u.job_title
        FROM attendance_records a
        LEFT JOIN users u ON u.id = a.employee_id
        ${whereClause}
        ORDER BY a.attendance_date DESC
        LIMIT ?
      `)
      .all(...args) as Array<
      RawAttendanceRow & {
        employee_name: string | null;
        employee_number: string | null;
        department: string | null;
        job_title: string | null;
      }
    >;

    return rows.map((r) => ({
      ...this.mapAttendanceRow(r),
      employee_name: r.employee_name ?? "",
      employee_number: r.employee_number ?? null,
      department: r.department ?? null,
      job_title: r.job_title ?? null,
    }));
  }

  public isJtiRevoked(jti: string): boolean {
    return Boolean(this.stmtIsJtiRevoked.get(jti));
  }

  public getActiveSession(jti: string, userId: string): ActiveSession | null {
    const row = this.db
      .prepare(`SELECT * FROM active_sessions WHERE jti = ? AND user_id = ? LIMIT 1`)
      .get(jti, userId) as ActiveSession | undefined;
    return row ?? null;
  }

  public getActiveSessionByJti(jti: string): ActiveSession | null {
    const row = this.db
      .prepare(`SELECT * FROM active_sessions WHERE jti = ? LIMIT 1`)
      .get(jti) as ActiveSession | undefined;
    return row ?? null;
  }

  public touchActiveSession(jti: string, lastActiveAt: string, idleExpiresAt: string): void {
    this.db
      .prepare(`UPDATE active_sessions SET last_active_at = ?, idle_expires_at = ? WHERE jti = ?`)
      .run(lastActiveAt, idleExpiresAt, jti);
  }

  public updateSessionAal(jti: string, aal: "aal1" | "aal2"): void {
    this.db.prepare(`UPDATE active_sessions SET aal = ? WHERE jti = ?`).run(aal, jti);
  }

  public createActiveSessionWithEviction(
    session: ActiveSession,
    maxConcurrent: number,
    nowIso: string,
  ): void {
    const tx = this.db.transaction(() => {
      const existing = this.db
        .prepare(`
          SELECT jti, absolute_expires_at
          FROM active_sessions
          WHERE user_id = ? AND absolute_expires_at > ? AND idle_expires_at > ?
          ORDER BY created_at ASC
        `)
        .all(session.user_id, nowIso, nowIso) as Array<{ jti: string; absolute_expires_at: string }>;

      const excess = existing.length - maxConcurrent + 1;
      if (excess > 0) {
        const revokeStmt = this.db.prepare(`
          INSERT INTO revoked_jtis (jti, exp_ms) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING
        `);
        const delStmt = this.db.prepare(`DELETE FROM active_sessions WHERE jti = ?`);
        for (let i = 0; i < excess; i += 1) {
          const old = existing[i];
          if (old) {
            revokeStmt.run(old.jti, Date.parse(old.absolute_expires_at));
            delStmt.run(old.jti);
          }
        }
      }

      this.db
        .prepare(`
          INSERT INTO active_sessions (
            jti, user_id, role, aal, ua_hash, ip_hash, created_at, last_active_at, idle_expires_at, absolute_expires_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          session.jti,
          session.user_id,
          session.role,
          session.aal,
          session.ua_hash,
          session.ip_hash,
          session.created_at,
          session.last_active_at,
          session.idle_expires_at,
          session.absolute_expires_at,
        );
    });
    tx();
  }

  public revokeSessionByJti(jti: string): void {
    const tx = this.db.transaction(() => {
      const target = this.db
        .prepare(`SELECT jti, absolute_expires_at FROM active_sessions WHERE jti = ?`)
        .get(jti) as { jti: string; absolute_expires_at: string } | undefined;
      if (target) {
        this.db
          .prepare(`INSERT INTO revoked_jtis (jti, exp_ms) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING`)
          .run(target.jti, Date.parse(target.absolute_expires_at));
        this.db.prepare(`DELETE FROM active_sessions WHERE jti = ?`).run(jti);
      }
    });
    tx();
  }

  public revokeAllSessionsForUser(userId: string, exceptJti?: string): void {
    const tx = this.db.transaction(() => {
      const sessions = (
        exceptJti
          ? this.db
              .prepare(`SELECT jti, absolute_expires_at FROM active_sessions WHERE user_id = ? AND jti != ?`)
              .all(userId, exceptJti)
          : this.db
              .prepare(`SELECT jti, absolute_expires_at FROM active_sessions WHERE user_id = ?`)
              .all(userId)
      ) as Array<{ jti: string; absolute_expires_at: string }>;

      const insertRev = this.db.prepare(`
        INSERT INTO revoked_jtis (jti, exp_ms) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING
      `);
      for (const s of sessions) {
        insertRev.run(s.jti, Date.parse(s.absolute_expires_at));
      }

      if (exceptJti) {
        this.db
          .prepare(`DELETE FROM active_sessions WHERE user_id = ? AND jti != ?`)
          .run(userId, exceptJti);
      } else {
        this.db.prepare(`DELETE FROM active_sessions WHERE user_id = ?`).run(userId);
      }
    });
    tx();
  }

  public listActiveSessionsWithUser(nowIso: string, currentJti?: string): Array<{
    jti: string;
    user_id: string;
    user_name: string;
    email: string;
    role: UserRole;
    aal: "aal1" | "aal2";
    created_at: string;
    last_active_at: string;
    idle_expires_at: string;
    absolute_expires_at: string;
    is_current: boolean;
  }> {
    const rows = this.db
      .prepare(`
        SELECT s.*, u.full_name AS user_name, u.email AS email
        FROM active_sessions s
        LEFT JOIN users u ON u.id = s.user_id
        WHERE s.absolute_expires_at > ? AND s.idle_expires_at > ?
        ORDER BY s.last_active_at DESC
      `)
      .all(nowIso, nowIso) as Array<ActiveSession & { user_name: string | null; email: string | null }>;

    return rows.map((s) => ({
      jti: s.jti,
      user_id: s.user_id,
      user_name: s.user_name ?? "—",
      email: s.email ?? "—",
      role: s.role,
      aal: s.aal,
      created_at: s.created_at,
      last_active_at: s.last_active_at,
      idle_expires_at: s.idle_expires_at,
      absolute_expires_at: s.absolute_expires_at,
      is_current: s.jti === currentJti,
    }));
  }

  public emergencyLockdownOtherUsers(exceptAdminId: string, nowIso: string): number {
    const tx = this.db.transaction(() => {
      const affectedRes = this.db
        .prepare(`UPDATE users SET token_version = token_version + 1 WHERE id != ?`)
        .run(exceptAdminId);

      const sessions = this.db
        .prepare(`SELECT jti, absolute_expires_at FROM active_sessions WHERE user_id != ?`)
        .all(exceptAdminId) as Array<{ jti: string; absolute_expires_at: string }>;
      const insertRev = this.db.prepare(`
        INSERT INTO revoked_jtis (jti, exp_ms) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING
      `);
      for (const s of sessions) {
        insertRev.run(s.jti, Date.parse(s.absolute_expires_at));
      }
      this.db.prepare(`DELETE FROM active_sessions WHERE user_id != ?`).run(exceptAdminId);
      this.db.prepare(`UPDATE kiosk_devices SET revoked_before = ?`).run(nowIso);
      this.db.prepare(`UPDATE qr_tokens SET status = 'revoked' WHERE status = 'active'`).run();
      return affectedRes.changes;
    });
    return tx();
  }

  public addSecurityLog(
    userId: string | null,
    eventType: string,
    reasonCode: string | null,
    ipHash: string | null = null,
    metadata: Record<string, unknown> = {},
  ): void {
    this.stmtInsertSecurityLog.run(
      `log-${crypto.randomUUID()}`,
      userId,
      eventType,
      reasonCode,
      ipHash,
      new Date().toISOString(),
      JSON.stringify(metadata),
    );
  }

  public findRecentCheckInAnomaly(
    excludeUserId: string,
    ipHash: string,
    uaHash: string,
    cutoffIso: string,
  ): { user_id: string } | null {
    const rows = this.db
      .prepare(`
        SELECT user_id, metadata_json
        FROM security_logs
        WHERE event_type = 'check_in_succeeded'
          AND ip_hash = ?
          AND created_at >= ?
          AND user_id IS NOT NULL
          AND user_id != ?
        ORDER BY created_at DESC
        LIMIT 10
      `)
      .all(ipHash, cutoffIso, excludeUserId) as Array<{ user_id: string; metadata_json: string }>;

    for (const r of rows) {
      const meta = parseJsonSafe<Record<string, unknown>>(r.metadata_json, {});
      if (meta.ua_hash === uaHash) {
        return { user_id: r.user_id };
      }
    }
    return null;
  }

  public listRecentSecurityLogs(limit = 40): Array<SecurityLog & { user_name: string }> {
    const rows = this.db
      .prepare(`
        SELECT l.*, u.full_name AS user_name
        FROM security_logs l
        LEFT JOIN users u ON u.id = l.user_id
        ORDER BY l.created_at DESC
        LIMIT ?
      `)
      .all(limit) as Array<{
      id: string;
      user_id: string | null;
      event_type: string;
      reason_code: string | null;
      ip_hash: string | null;
      created_at: string;
      metadata_json: string;
      user_name: string | null;
    }>;

    return rows.map((r) => ({
      id: r.id,
      user_id: r.user_id,
      event_type: r.event_type,
      reason_code: r.reason_code,
      ip_hash: r.ip_hash,
      created_at: r.created_at,
      metadata: parseJsonSafe<Record<string, unknown>>(r.metadata_json, {}),
      user_name: r.user_id ? r.user_name ?? "—" : "النظام",
    }));
  }

  public addSecurityAlert(alert: SecurityAlertEntry): void {
    this.db
      .prepare(`
        INSERT INTO security_alerts (id, severity, event, request_id, ip_hash, created_at, details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        alert.id,
        alert.severity,
        alert.event,
        alert.request_id,
        alert.ip_hash,
        alert.created_at,
        JSON.stringify(alert.details),
      );
  }

  public listRecentSecurityAlerts(limit = 25): SecurityAlertEntry[] {
    const rows = this.db
      .prepare(`SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT ?`)
      .all(limit) as Array<{
      id: string;
      severity: SecurityAlertEntry["severity"];
      event: string;
      request_id: string | null;
      ip_hash: string | null;
      created_at: string;
      details_json: string;
    }>;
    return rows.map((r) => ({
      id: r.id,
      severity: r.severity,
      event: r.event,
      request_id: r.request_id,
      ip_hash: r.ip_hash,
      created_at: r.created_at,
      details: parseJsonSafe<Record<string, unknown>>(r.details_json, {}),
    }));
  }

  public cleanupExpiredAndAgedData(nowMs: number = Date.now()): void {
    const nowIso = new Date(nowMs).toISOString();
    const sevenDaysAgoIso = new Date(nowMs - 7 * 86_400_000).toISOString();
    const ninetyDaysAgoIso = new Date(nowMs - 90 * 86_400_000).toISOString();

    const tx = this.db.transaction(() => {
      this.db.prepare(`DELETE FROM revoked_jtis WHERE exp_ms <= ?`).run(nowMs);
      this.db
        .prepare(`DELETE FROM active_sessions WHERE absolute_expires_at <= ? OR idle_expires_at <= ?`)
        .run(nowIso, nowIso);
      this.db
        .prepare(`UPDATE qr_tokens SET status = 'expired' WHERE status = 'active' AND expires_at <= ?`)
        .run(nowIso);
      this.db.prepare(`DELETE FROM qr_tokens WHERE issued_at < ?`).run(sevenDaysAgoIso);
      this.db.prepare(`DELETE FROM security_logs WHERE created_at < ?`).run(ninetyDaysAgoIso);
      this.db.prepare(`DELETE FROM security_alerts WHERE created_at < ?`).run(ninetyDaysAgoIso);
      this.db
        .prepare(`UPDATE attendance_records SET distance_m = NULL, gps_meta_enc = NULL WHERE created_at < ? AND (distance_m IS NOT NULL OR gps_meta_enc IS NOT NULL)`)
        .run(ninetyDaysAgoIso);
    });
    tx();
  }

  public exportBackupPayload(): {
    exported_at: string;
    schema_version: number;
    settings: CompanySettings;
    security_policy: SecurityPolicySettings;
    rbac_roles: Record<string, RbacRoleDefinition>;
    users: Array<Omit<StoredUser, "mfa_secret_enc">>;
    kiosk_devices: KioskDevice[];
    attendance_records: AttendanceRecord[];
    security_logs: SecurityLog[];
    security_alerts: SecurityAlertEntry[];
  } {
    const users = (
      this.db.prepare(`SELECT * FROM users ORDER BY created_at ASC`).all() as RawUserRow[]
    ).map((r) => {
      const u = this.mapUserRow(r);
      return { ...u, mfa_secret_enc: undefined };
    });

    const kiosks = (
      this.db.prepare(`SELECT * FROM kiosk_devices ORDER BY created_at ASC`).all() as RawKioskRow[]
    ).map((r) => this.mapKioskRow(r));

    const records = (
      this.db
        .prepare(`SELECT * FROM attendance_records ORDER BY attendance_date DESC`)
        .all() as RawAttendanceRow[]
    ).map((r) => this.mapAttendanceRow(r));

    const logs = (
      this.db.prepare(`SELECT * FROM security_logs ORDER BY created_at DESC LIMIT 5000`).all() as Array<{
        id: string;
        user_id: string | null;
        event_type: string;
        reason_code: string | null;
        ip_hash: string | null;
        created_at: string;
        metadata_json: string;
      }>
    ).map((l) => ({
      id: l.id,
      user_id: l.user_id,
      event_type: l.event_type,
      reason_code: l.reason_code,
      ip_hash: l.ip_hash,
      created_at: l.created_at,
      metadata: parseJsonSafe<Record<string, unknown>>(l.metadata_json, {}),
    }));

    return {
      exported_at: new Date().toISOString(),
      schema_version: 3,
      settings: this.getSettings(),
      security_policy: this.getSecurityPolicy(),
      rbac_roles: this.getRbacRoles(),
      users,
      kiosk_devices: kiosks,
      attendance_records: records,
      security_logs: logs,
      security_alerts: this.listRecentSecurityAlerts(200),
    };
  }
}
