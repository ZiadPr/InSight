import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  buildDefaultRbacRoles,
  buildDefaultSecurityPolicy,
  decryptJsonPayload,
  SqliteAttendanceStore,
  type DatabaseState,
} from "../server/sqliteStore.ts";

export interface MigrationOptions {
  inputPath?: string;
  outputPath?: string;
  keyFilePath?: string;
  masterKey?: Buffer;
  overwriteOutput?: boolean;
}

export interface MigrationResult {
  inputPath: string;
  outputPath: string;
  backupPath: string;
  counts: {
    users: number;
    kiosks: number;
    attendanceRecords: number;
    securityLogs: number;
  };
}

function resolveMigrationMasterKey(keyFilePath: string, explicitKey?: Buffer): Buffer {
  if (explicitKey && explicitKey.length === 32) {
    return explicitKey;
  }
  const envHex = process.env.DATA_ENCRYPTION_KEY?.trim();
  if (envHex && /^[0-9a-fA-F]{64}$/.test(envHex)) {
    return Buffer.from(envHex, "hex");
  }
  if (fs.existsSync(keyFilePath)) {
    const fileHex = fs.readFileSync(keyFilePath, "utf8").trim();
    if (/^[0-9a-fA-F]{64}$/.test(fileHex)) {
      return Buffer.from(fileHex, "hex");
    }
  }
  throw new Error(
    `MISSING_ENCRYPTION_KEY: Set DATA_ENCRYPTION_KEY (64 hex chars) or ensure ${keyFilePath} exists.`,
  );
}

function normalizeLegacyStateForMigration(raw: DatabaseState): DatabaseState {
  if (!raw || !Array.isArray(raw.users) || !raw.settings) {
    throw new Error("INVALID_LEGACY_DB_FORMAT");
  }
  if (!Array.isArray(raw.revoked_jtis)) raw.revoked_jtis = [];
  if (!Array.isArray(raw.active_sessions)) raw.active_sessions = [];
  if (!Array.isArray(raw.security_alerts)) raw.security_alerts = [];
  if (!Array.isArray(raw.qr_tokens)) raw.qr_tokens = [];
  if (!Array.isArray(raw.attendance_records)) raw.attendance_records = [];
  if (!Array.isArray(raw.security_logs)) raw.security_logs = [];
  if (!Array.isArray(raw.kiosk_devices)) raw.kiosk_devices = [];
  if (typeof raw.settings.qr_schedule_enabled !== "boolean") {
    raw.settings.qr_schedule_enabled = false;
    raw.settings.qr_window_start = "07:30";
    raw.settings.qr_cutoff_time = "11:00";
    raw.settings.qr_reappear_time = "15:30";
    raw.settings.qr_window_end = "19:00";
  }
  raw.security_policy = {
    ...buildDefaultSecurityPolicy(),
    ...(raw.security_policy ?? {}),
  };
  raw.rbac_roles = {
    ...buildDefaultRbacRoles(),
    ...(raw.rbac_roles ?? {}),
  };
  for (const u of raw.users) {
    if (typeof u.token_version !== "number") u.token_version = 1;
    if (u.role === "admin" && !u.admin_role_key) {
      u.admin_role_key = "super_admin";
    }
  }
  return raw;
}

export function runJsonToSqliteMigration(options: MigrationOptions = {}): MigrationResult {
  const dataDir = path.resolve(process.cwd(), "data");
  const inputPath = path.resolve(options.inputPath ?? path.join(dataDir, "attendance-db.enc"));
  const outputPath = path.resolve(options.outputPath ?? path.join(dataDir, "attendance.db"));
  const keyFilePath = path.resolve(options.keyFilePath ?? path.join(dataDir, ".master.key"));

  if (!fs.existsSync(inputPath)) {
    throw new Error(`SOURCE_FILE_NOT_FOUND: ${inputPath}`);
  }

  const masterKey = resolveMigrationMasterKey(keyFilePath, options.masterKey);
  const encryptedContent = fs.readFileSync(inputPath, "utf8");
  const decryptedJson = decryptJsonPayload(encryptedContent, masterKey);
  const parsed = normalizeLegacyStateForMigration(JSON.parse(decryptedJson) as DatabaseState);

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = `${inputPath}.bak-${stamp}`;
  fs.copyFileSync(inputPath, backupPath);
  try {
    fs.chmodSync(backupPath, 0o600);
  } catch {
    // Ignore on filesystems without POSIX chmod
  }

  if (fs.existsSync(outputPath)) {
    if (!options.overwriteOutput) {
      throw new Error(
        `TARGET_ALREADY_EXISTS: ${outputPath} already exists. Pass --overwrite to upsert into existing SQLite DB.`,
      );
    }
    const dbBackupPath = `${outputPath}.bak-${stamp}`;
    fs.copyFileSync(outputPath, dbBackupPath);
  }

  const store = new SqliteAttendanceStore(outputPath, masterKey);
  try {
    const counts = store.importDatabaseState(parsed);
    return {
      inputPath,
      outputPath,
      backupPath,
      counts,
    };
  } finally {
    store.close();
  }
}

function parseCliArgs(argv: string[]): MigrationOptions {
  const opts: MigrationOptions = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--input" && argv[i + 1]) {
      opts.inputPath = argv[i + 1];
      i += 1;
    } else if (arg === "--output" && argv[i + 1]) {
      opts.outputPath = argv[i + 1];
      i += 1;
    } else if (arg === "--key-file" && argv[i + 1]) {
      opts.keyFilePath = argv[i + 1];
      i += 1;
    } else if (arg === "--overwrite") {
      opts.overwriteOutput = true;
    }
  }
  return opts;
}

const isDirectExecution =
  typeof process.argv[1] === "string" &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isDirectExecution) {
  try {
    const opts = parseCliArgs(process.argv.slice(2));
    const result = runJsonToSqliteMigration(opts);
    console.log(
      JSON.stringify(
        {
          ok: true,
          message: "Legacy encrypted JSON database migrated cleanly to SQLite (WAL + column AES-256-GCM).",
          ...result,
        },
        null,
        2,
      ),
    );
  } catch (err) {
    console.error(
      JSON.stringify({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      }),
    );
    process.exit(1);
  }
}
