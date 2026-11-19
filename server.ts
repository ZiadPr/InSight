import net from "node:net";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express from "express";
import type { NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import hpp from "hpp";
import { z } from "zod";
import {
  ALL_PERMISSION_KEYS,
  buildDefaultRbacRoles,
  buildDefaultSecurityPolicy,
  decryptJsonPayload,
  encryptJsonPayload,
  SqliteAttendanceStore,
  type ActiveSession,
  type AttendanceRecord,
  type AttendanceStatus,
  type CompanySettings,
  type DatabaseState,
  type KioskDevice,
  type PermissionKey,
  type RbacRoleDefinition,
  type SecurityAlertEntry,
  type SecurityPolicySettings,
  type StoredUser,
  type UserRole,
} from "./server/sqliteStore.ts";

interface SecChannel {
  id: string;
  key: Buffer;
  uaHash: string;
  ipHash: string;
  expiresAtMs: number;
}

interface AuthenticatedRequest extends Request {
  requestId?: string;
  authUser?: StoredUser;
  authSession?: ActiveSession;
  authIssuedAtSec?: number;
  authJti?: string;
  authExpMs?: number;
  secChannel?: SecChannel;
}

const IS_PRODUCTION = process.env.NODE_ENV === "production";

function resolveListenPort(): number {
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--port" && argv[i + 1]) {
      const parsed = Number(argv[i + 1]);
      if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65535) return parsed;
    } else if (argv[i].startsWith("--port=")) {
      const parsed = Number(argv[i].slice("--port=".length));
      if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65535) return parsed;
    }
  }
  const envPort = Number(process.env.PORT);
  const nginxPort = Number(process.env.NGINX_PORT);
  if (!IS_PRODUCTION && envPort && nginxPort && envPort === nginxPort) {
    return Number(process.env.DEFAULT_APP_PORT) || 3000;
  }
  return envPort || Number(process.env.DEFAULT_APP_PORT) || 3000;
}

const PORT = resolveListenPort();
const REQUIRE_ADMIN_MFA = process.env.REQUIRE_ADMIN_MFA
  ? process.env.REQUIRE_ADMIN_MFA === "true"
  : IS_PRODUCTION;
const REQUIRE_HTTPS = process.env.REQUIRE_HTTPS
  ? process.env.REQUIRE_HTTPS === "true"
  : IS_PRODUCTION;
const DATA_DIR = path.resolve(process.cwd(), "data");
const KEY_FILE = path.join(DATA_DIR, ".master.key");
const SQLITE_DB_FILE = path.join(DATA_DIR, "attendance.db");
const LEGACY_ENC_DB_FILE = path.join(DATA_DIR, "attendance-db.enc");
const LEGACY_DB_FILE = path.join(DATA_DIR, "attendance-db.json");

function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

const MANUAL_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function generateManualCode(): string {
  let chars = "";
  for (let i = 0; i < 8; i += 1) {
    chars += MANUAL_CODE_ALPHABET[crypto.randomInt(0, MANUAL_CODE_ALPHABET.length)];
  }
  return `${chars.slice(0, 4)}-${chars.slice(4)}`;
}

function normalizeManualCode(input: string): string {
  return input.replace(/[\s-]+/g, "").toUpperCase();
}

function hmacSha256Hex(secret: string, value: string): string {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}

function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 32).toString("hex");
}

function verifyPassword(password: string, salt: string, expectedHash: string): boolean {
  const actual = hashPassword(password, salt);
  return constantTimeEqual(actual, expectedHash);
}

function isStrongPassword(password: string): boolean {
  if (password.length < 8 || password.length > 128) return false;
  const hasLetter = /[A-Za-z]/.test(password);
  const hasDigit = /\d/.test(password);
  return hasLetter && hasDigit;
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function encodeBase32(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (let i = 0; i < bytes.length; i += 1) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function decodeBase32(input: string): Buffer {
  const cleaned = input.replace(/[\s=]+/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (let i = 0; i < cleaned.length; i += 1) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) throw new Error("INVALID_BASE32");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotpSecret(): string {
  return encodeBase32(crypto.randomBytes(20));
}

function computeTotpAtStep(secretKey: Buffer, counterStep: number): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counterStep));
  const hmac = crypto.createHmac("sha1", secretKey).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const codeInt =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(codeInt % 1_000_000).padStart(6, "0");
}

function verifyTotpCode(
  secretBase32: string,
  submittedCode: string,
  lastUsedStep?: number,
): { valid: boolean; matchedStep?: number } {
  const normalized = submittedCode.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(normalized)) {
    return { valid: false };
  }
  const secretBytes = decodeBase32(secretBase32);
  const currentStep = Math.floor(Date.now() / 1000 / 30);
  for (const offset of [-1, 0, 1]) {
    const step = currentStep + offset;
    if (typeof lastUsedStep === "number" && step <= lastUsedStep) {
      continue;
    }
    const candidate = computeTotpAtStep(secretBytes, step);
    if (constantTimeEqual(candidate, normalized)) {
      return { valid: true, matchedStep: step };
    }
  }
  return { valid: false };
}

function getOrCreateMasterKey(): Buffer {
  const envKey = process.env.DATA_ENCRYPTION_KEY?.trim();
  if (envKey && /^[0-9a-fA-F]{64}$/.test(envKey)) {
    return Buffer.from(envKey, "hex");
  }
  if (fs.existsSync(KEY_FILE)) {
    const hex = fs.readFileSync(KEY_FILE, "utf8").trim();
    if (/^[0-9a-fA-F]{64}$/.test(hex)) {
      if (IS_PRODUCTION) {
        console.warn(
          "[SECURITY WARNING] Using local key file because DATA_ENCRYPTION_KEY env var is not set. Configure DATA_ENCRYPTION_KEY in Secret Manager/KMS for production.",
        );
      }
      return Buffer.from(hex, "hex");
    }
  }
  if (IS_PRODUCTION && process.env.STRICT_PROD_SECRETS === "true") {
    throw new Error(
      "FATAL: DATA_ENCRYPTION_KEY (64 hex characters from KMS/Secret Manager) is mandatory when STRICT_PROD_SECRETS=true.",
    );
  }
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  }
  const generated = crypto.randomBytes(32);
  fs.writeFileSync(KEY_FILE, generated.toString("hex"), { mode: 0o600 });
  if (IS_PRODUCTION) {
    console.warn(
      "[SECURITY WARNING] DATA_ENCRYPTION_KEY not set; generated local 256-bit AES master key for this instance.",
    );
  }
  return generated;
}

function getDateInTimezone(date: Date, timeZone: string): string {
  try {
    return new Intl.DateTimeFormat("en-CA", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(date);
  } catch {
    return date.toISOString().slice(0, 10);
  }
}

function getMinutesOfDayInTimezone(date: Date, timeZone: string): number {
  try {
    const parts = new Intl.DateTimeFormat("en-GB", {
      timeZone,
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).formatToParts(date);
    const hour = Number(parts.find((p) => p.type === "hour")?.value ?? "0");
    const minute = Number(parts.find((p) => p.type === "minute")?.value ?? "0");
    return hour * 60 + minute;
  } catch {
    return date.getUTCHours() * 60 + date.getUTCMinutes();
  }
}

function parseHhMmToMinutes(hhmm: string): number {
  const [hStr, mStr] = hhmm.split(":");
  const h = Number(hStr);
  const m = Number(mStr);
  if (!Number.isFinite(h) || !Number.isFinite(m)) return 9 * 60;
  return h * 60 + m;
}

function evaluateQrCaptureSchedule(
  settings: CompanySettings,
  now: Date = new Date(),
): {
  open: boolean;
  next_reappear_time: string | null;
  window_cutoff_time: string | null;
} {
  if (!settings.qr_schedule_enabled) {
    return { open: true, next_reappear_time: null, window_cutoff_time: null };
  }

  const nowMins = getMinutesOfDayInTimezone(now, settings.timezone);
  const startMins = parseHhMmToMinutes(settings.qr_window_start || "07:30");
  const cutoffMins = parseHhMmToMinutes(settings.qr_cutoff_time || "11:00");
  const reappearMins = parseHhMmToMinutes(settings.qr_reappear_time || "15:30");
  const endMins = parseHhMmToMinutes(settings.qr_window_end || "19:00");

  if (nowMins >= startMins && nowMins <= cutoffMins) {
    return {
      open: true,
      next_reappear_time: null,
      window_cutoff_time: settings.qr_cutoff_time,
    };
  }
  if (nowMins >= reappearMins && nowMins <= endMins) {
    return {
      open: true,
      next_reappear_time: null,
      window_cutoff_time: settings.qr_window_end,
    };
  }

  if (nowMins < startMins) {
    return {
      open: false,
      next_reappear_time: settings.qr_window_start,
      window_cutoff_time: settings.qr_cutoff_time,
    };
  }
  if (nowMins > cutoffMins && nowMins < reappearMins) {
    return {
      open: false,
      next_reappear_time: settings.qr_reappear_time,
      window_cutoff_time: settings.qr_cutoff_time,
    };
  }
  return {
    open: false,
    next_reappear_time: settings.qr_window_start,
    window_cutoff_time: settings.qr_window_end,
  };
}

function haversineMeters(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const r = 6371000;
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(Math.max(0, 1 - a)));
  return r * c;
}

function sanitizeCsvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  let text = String(value);
  if (text.length > 0) {
    const first = text[0];
    if (
      first === "=" ||
      first === "+" ||
      first === "-" ||
      first === "@" ||
      first === "\t" ||
      first === "\r"
    ) {
      text = `'${text}`;
    }
  }
  const escaped = text.replace(/"/g, '""');
  return `"${escaped}"`;
}

function shiftIsoDateDays(baseDate: Date, deltaDays: number, timeZone: string): string {
  const target = new Date(baseDate.getTime() + deltaDays * 86_400_000);
  return getDateInTimezone(target, timeZone);
}

function buildSeedDatabase(): DatabaseState {
  const now = new Date();
  const nowIso = now.toISOString();
  const timezone = "Asia/Riyadh";
  const todayDate = getDateInTimezone(now, timezone);

  const authSecret = crypto.randomBytes(32).toString("hex");
  const kioskSalt = crypto.randomBytes(32).toString("hex");
  const ipSalt = crypto.randomBytes(32).toString("hex");

  const makeUser = (params: {
    id: string;
    email: string;
    password: string;
    full_name: string;
    employee_number: string | null;
    department: string | null;
    job_title: string | null;
    shift_start: string;
    shift_end: string;
    role: UserRole;
  }): StoredUser => {
    const salt = crypto.randomBytes(16).toString("hex");
    return {
      id: params.id,
      email: params.email,
      password_salt: salt,
      password_hash: hashPassword(params.password, salt),
      token_version: 1,
      full_name: params.full_name,
      employee_number: params.employee_number,
      department: params.department,
      job_title: params.job_title,
      shift_start: params.shift_start,
      shift_end: params.shift_end,
      role: params.role,
      admin_role_key: params.role === "admin" ? "super_admin" : null,
      is_active: true,
      created_at: nowIso,
      updated_at: nowIso,
    };
  };

  const hrUser = makeUser({
    id: "usr-hr-admin",
    email: "hr@company.com",
    password: "Admin@2026",
    full_name: "سارة عبد الله المنصور",
    employee_number: "EMP-1000",
    department: "الموارد البشرية",
    job_title: "مديرة الموارد البشرية",
    shift_start: "08:30",
    shift_end: "16:30",
    role: "admin",
  });

  const emp1 = makeUser({
    id: "usr-emp-1001",
    email: "ahmed@company.com",
    password: "Emp@2026",
    full_name: "أحمد خالد العتيبي",
    employee_number: "EMP-1001",
    department: "تطوير البرمجيات",
    job_title: "مهندس برمجيات أول",
    shift_start: "09:00",
    shift_end: "17:00",
    role: "employee",
  });

  const emp2 = makeUser({
    id: "usr-emp-1002",
    email: "noura@company.com",
    password: "Emp@2026",
    full_name: "نورة سعد القحطاني",
    employee_number: "EMP-1002",
    department: "العمليات",
    job_title: "أخصائية جودة العمليات",
    shift_start: "09:00",
    shift_end: "17:00",
    role: "employee",
  });

  const emp3 = makeUser({
    id: "usr-emp-1003",
    email: "omar@company.com",
    password: "Emp@2026",
    full_name: "عمر فهد الدوسري",
    employee_number: "EMP-1003",
    department: "المبيعات",
    job_title: "مدير حسابات كبار العملاء",
    shift_start: "09:00",
    shift_end: "17:00",
    role: "employee",
  });

  const emp4 = makeUser({
    id: "usr-emp-1004",
    email: "layla@company.com",
    password: "Emp@2026",
    full_name: "ليلى محمد الحربي",
    employee_number: "EMP-1004",
    department: "المالية",
    job_title: "محاسبة مالية أولى",
    shift_start: "09:00",
    shift_end: "17:00",
    role: "employee",
  });

  const emp5 = makeUser({
    id: "usr-emp-1005",
    email: "khalid@company.com",
    password: "Emp@2026",
    full_name: "خالد يوسف الغامدي",
    employee_number: "EMP-1005",
    department: "تطوير البرمجيات",
    job_title: "مصمم واجهات تجربة المستخدم",
    shift_start: "09:00",
    shift_end: "17:00",
    role: "employee",
  });

  const kioskUser = makeUser({
    id: "usr-kiosk-hq",
    email: "kiosk@company.com",
    password: "Kiosk@2026",
    full_name: "شاشة استقبال المقر الرئيسي",
    employee_number: null,
    department: "الاستقبال",
    job_title: "جهاز عرض QR",
    shift_start: "00:00",
    shift_end: "23:59",
    role: "kiosk",
  });

  const kioskDevice: KioskDevice = {
    id: "kiosk-hq-01",
    device_name: "بوابة الاستقبال الرئيسية — الطابق الأرضي",
    branch_name: "المقر الرئيسي — الرياض",
    auth_user_id: kioskUser.id,
    secret_hash: sha256Hex(`${kioskSalt}:KIOSK-HQ-2026`),
    is_active: true,
    last_seen_at: nowIso,
    revoked_before: null,
    created_at: nowIso,
  };

  const records: AttendanceRecord[] = [];
  const employees = [emp1, emp2, emp3, emp4, emp5];

  for (let d = 7; d >= 1; d -= 1) {
    const dayStr = shiftIsoDateDays(now, -d, timezone);
    const weekday = new Date(`${dayStr}T12:00:00Z`).getUTCDay();
    if (weekday === 5 || weekday === 6) continue;

    employees.forEach((emp, idx) => {
      if (d === 3 && idx === 3) {
        records.push({
          id: `att-seed-${dayStr}-${emp.id}`,
          employee_id: emp.id,
          attendance_date: dayStr,
          checked_in_at: null,
          checked_out_at: null,
          worked_minutes: null,
          late_minutes: 0,
          status: "excused",
          qr_token_id: null,
          idempotency_key: null,
          distance_m: null,
          notes: "إجازة مرضية معتمدة",
          created_at: `${dayStr}T09:00:00Z`,
        });
        return;
      }

      const isLate = (d + idx) % 5 === 0;
      const lateMins = isLate ? 22 : 0;
      const checkInMin = isLate ? "22" : String(2 + idx * 2).padStart(2, "0");
      const checkInIso = `${dayStr}T06:${checkInMin}:14.000Z`;
      const checkOutIso = `${dayStr}T14:${String(10 + idx * 3).padStart(2, "0")}:05.000Z`;
      const workedMinutes = Math.round(
        (Date.parse(checkOutIso) - Date.parse(checkInIso)) / 60000,
      );

      records.push({
        id: `att-seed-${dayStr}-${emp.id}`,
        employee_id: emp.id,
        attendance_date: dayStr,
        checked_in_at: checkInIso,
        checked_out_at: checkOutIso,
        worked_minutes: workedMinutes,
        late_minutes: lateMins,
        status: isLate ? "late" : "present",
        qr_token_id: null,
        idempotency_key: null,
        distance_m: 14 + idx * 5,
        notes: null,
        created_at: checkInIso,
      });
    });
  }

  const twoHoursAgo = new Date(now.getTime() - 125 * 60_000).toISOString();
  const ninetyMinsAgo = new Date(now.getTime() - 92 * 60_000).toISOString();

  records.push(
    {
      id: `att-today-${emp2.id}`,
      employee_id: emp2.id,
      attendance_date: todayDate,
      checked_in_at: twoHoursAgo,
      checked_out_at: null,
      worked_minutes: null,
      late_minutes: 0,
      status: "present",
      qr_token_id: null,
      idempotency_key: null,
      distance_m: 18,
      notes: null,
      created_at: twoHoursAgo,
    },
    {
      id: `att-today-${emp3.id}`,
      employee_id: emp3.id,
      attendance_date: todayDate,
      checked_in_at: ninetyMinsAgo,
      checked_out_at: null,
      worked_minutes: null,
      late_minutes: 28,
      status: "late",
      qr_token_id: null,
      idempotency_key: null,
      distance_m: 26,
      notes: null,
      created_at: ninetyMinsAgo,
    },
    {
      id: `att-today-${emp5.id}`,
      employee_id: emp5.id,
      attendance_date: todayDate,
      checked_in_at: null,
      checked_out_at: null,
      worked_minutes: null,
      late_minutes: 0,
      status: "excused",
      qr_token_id: null,
      idempotency_key: null,
      distance_m: null,
      notes: "مهمة عمل خارجية معتمدة",
      created_at: nowIso,
    },
  );

  return {
    auth_secret: authSecret,
    kiosk_salt: kioskSalt,
    ip_salt: ipSalt,
    users: [hrUser, emp1, emp2, emp3, emp4, emp5, kioskUser],
    settings: {
      id: "company-hq",
      company_name: "ان سايت",
      branch_name: "المقر الرئيسي — الرياض",
      latitude: 24.7136,
      longitude: 46.6753,
      allowed_radius_m: 300,
      max_gps_accuracy_m: 120,
      qr_ttl_seconds: 20,
      timezone,
      work_start_time: "09:00",
      work_end_time: "17:00",
      late_grace_minutes: 15,
      enforce_geofence: false,
      is_enabled: true,
      qr_schedule_enabled: false,
      qr_window_start: "07:30",
      qr_cutoff_time: "11:00",
      qr_reappear_time: "15:30",
      qr_window_end: "19:00",
      updated_at: nowIso,
    },
    security_policy: buildDefaultSecurityPolicy(),
    rbac_roles: buildDefaultRbacRoles(),
    kiosk_devices: [kioskDevice],
    qr_tokens: [],
    attendance_records: records,
    security_logs: [
      {
        id: "log-seed-1",
        user_id: emp2.id,
        event_type: "check_in_succeeded",
        reason_code: "OK",
        ip_hash: null,
        created_at: twoHoursAgo,
        metadata: { attendance_date: todayDate, distance_m: 18 },
      },
      {
        id: "log-seed-2",
        user_id: emp3.id,
        event_type: "check_in_succeeded",
        reason_code: "LATE_ARRIVAL",
        ip_hash: null,
        created_at: ninetyMinsAgo,
        metadata: { attendance_date: todayDate, late_minutes: 28 },
      },
    ],
    security_alerts: [],
    active_sessions: [],
    revoked_jtis: [],
  };
}

function buildProductionBootstrapDatabase(): DatabaseState {
  const envEmail = process.env.ADMIN_BOOTSTRAP_EMAIL?.trim().toLowerCase() ?? "";
  const envPassword = process.env.ADMIN_BOOTSTRAP_PASSWORD ?? "";
  const envKioskSecret = process.env.KIOSK_BOOTSTRAP_SECRET?.trim() ?? "";

  if (
    IS_PRODUCTION &&
    process.env.STRICT_PROD_SECRETS === "true" &&
    (!envEmail ||
      envPassword.length < 12 ||
      !isStrongPassword(envPassword) ||
      envKioskSecret.length < 12)
  ) {
    throw new Error(
      "FATAL: ADMIN_BOOTSTRAP_EMAIL, strong ADMIN_BOOTSTRAP_PASSWORD (12+ chars), and KIOSK_BOOTSTRAP_SECRET (12+ chars) are required when STRICT_PROD_SECRETS=true.",
    );
  }

  const adminEmail = envEmail || "admin@insight.local";
  const adminPassword =
    envPassword.length >= 12 && isStrongPassword(envPassword)
      ? envPassword
      : `${crypto.randomBytes(18).toString("base64url")}9A`;
  const kioskSecret =
    envKioskSecret.length >= 12
      ? envKioskSecret
      : crypto.randomBytes(18).toString("base64url");

  if (!envEmail || !envPassword || !envKioskSecret) {
    console.warn(
      `[SECURITY NOTICE] Bootstrapped production database with CSPRNG credentials for ${adminEmail}. Set ADMIN_BOOTSTRAP_EMAIL/ADMIN_BOOTSTRAP_PASSWORD/KIOSK_BOOTSTRAP_SECRET for custom bootstrap values.`,
    );
  }

  const nowIso = new Date().toISOString();
  const authSecret = crypto.randomBytes(32).toString("hex");
  const kioskSalt = crypto.randomBytes(32).toString("hex");
  const ipSalt = crypto.randomBytes(32).toString("hex");

  const adminSalt = crypto.randomBytes(16).toString("hex");
  const adminUser: StoredUser = {
    id: `usr-${crypto.randomUUID()}`,
    email: adminEmail,
    password_salt: adminSalt,
    password_hash: hashPassword(adminPassword, adminSalt),
    token_version: 1,
    full_name: "مدير الموارد البشرية",
    employee_number: "HR-001",
    department: "الموارد البشرية",
    job_title: "مدير الموارد البشرية",
    shift_start: "08:00",
    shift_end: "16:00",
    role: "admin",
    admin_role_key: "super_admin",
    is_active: true,
    mfa_enabled: false,
    mfa_secret_enc: null,
    must_change_password: false,
    created_at: nowIso,
    updated_at: nowIso,
  };

  const kioskSaltPwd = crypto.randomBytes(16).toString("hex");
  const kioskAccountPassword = crypto.randomBytes(24).toString("base64url");
  const kioskUser: StoredUser = {
    id: `usr-${crypto.randomUUID()}`,
    email: `kiosk-terminal@${adminEmail.split("@")[1] || "internal.local"}`,
    password_salt: kioskSaltPwd,
    password_hash: hashPassword(kioskAccountPassword, kioskSaltPwd),
    token_version: 1,
    full_name: "شاشة الاستقبال الرئيسية",
    employee_number: null,
    department: "الاستقبال",
    job_title: "جهاز عرض QR",
    shift_start: "00:00",
    shift_end: "23:59",
    role: "kiosk",
    is_active: true,
    created_at: nowIso,
    updated_at: nowIso,
  };

  const kioskDevice: KioskDevice = {
    id: "kiosk-hq-01",
    device_name: "بوابة الاستقبال الرئيسية",
    branch_name: "المقر الرئيسي",
    auth_user_id: kioskUser.id,
    secret_hash: sha256Hex(`${kioskSalt}:${kioskSecret}`),
    is_active: true,
    last_seen_at: null,
    revoked_before: null,
    created_at: nowIso,
  };

  return {
    auth_secret: authSecret,
    kiosk_salt: kioskSalt,
    ip_salt: ipSalt,
    users: [adminUser, kioskUser],
    settings: {
      id: "company-hq",
      company_name: "ان سايت",
      branch_name: "المقر الرئيسي",
      latitude: 24.7136,
      longitude: 46.6753,
      allowed_radius_m: 300,
      max_gps_accuracy_m: 120,
      qr_ttl_seconds: 20,
      timezone: "Asia/Riyadh",
      work_start_time: "09:00",
      work_end_time: "17:00",
      late_grace_minutes: 15,
      enforce_geofence: true,
      is_enabled: false,
      qr_schedule_enabled: false,
      qr_window_start: "07:30",
      qr_cutoff_time: "11:00",
      qr_reappear_time: "15:30",
      qr_window_end: "19:00",
      updated_at: nowIso,
    },
    security_policy: buildDefaultSecurityPolicy(),
    rbac_roles: buildDefaultRbacRoles(),
    kiosk_devices: [kioskDevice],
    qr_tokens: [],
    attendance_records: [],
    security_logs: [],
    security_alerts: [],
    active_sessions: [],
    revoked_jtis: [],
  };
}

function normalizeLegacyDatabaseState(raw: DatabaseState): DatabaseState {
  if (!raw.ip_salt) {
    raw.ip_salt = crypto.randomBytes(32).toString("hex");
  }
  if (!Array.isArray(raw.revoked_jtis)) raw.revoked_jtis = [];
  if (!Array.isArray(raw.active_sessions)) raw.active_sessions = [];
  if (!Array.isArray(raw.security_alerts)) raw.security_alerts = [];
  if (!Array.isArray(raw.qr_tokens)) raw.qr_tokens = [];
  if (!Array.isArray(raw.attendance_records)) raw.attendance_records = [];
  if (!Array.isArray(raw.security_logs)) raw.security_logs = [];

  if (typeof raw.settings.qr_schedule_enabled !== "boolean") {
    raw.settings.qr_schedule_enabled = false;
    raw.settings.qr_window_start = "07:30";
    raw.settings.qr_cutoff_time = "11:00";
    raw.settings.qr_reappear_time = "15:30";
    raw.settings.qr_window_end = "19:00";
  }
  raw.security_policy = { ...buildDefaultSecurityPolicy(), ...(raw.security_policy ?? {}) };
  raw.rbac_roles = { ...buildDefaultRbacRoles(), ...(raw.rbac_roles ?? {}) };

  for (const u of raw.users) {
    if (typeof u.token_version !== "number") u.token_version = 1;
    if (u.role === "admin" && !u.admin_role_key) {
      u.admin_role_key = "super_admin";
    }
  }
  return raw;
}

const masterKey = getOrCreateMasterKey();

function initializeSqliteStore(): SqliteAttendanceStore {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  }
  const sqliteStore = new SqliteAttendanceStore(SQLITE_DB_FILE, masterKey);

  if (!sqliteStore.isInitialized()) {
    let importedFromLegacy = false;

    if (fs.existsSync(LEGACY_ENC_DB_FILE)) {
      try {
        const encrypted = fs.readFileSync(LEGACY_ENC_DB_FILE, "utf8");
        const decrypted = decryptJsonPayload(encrypted, masterKey);
        const parsed = normalizeLegacyDatabaseState(JSON.parse(decrypted) as DatabaseState);
        const stamp = new Date().toISOString().replace(/[:.]/g, "-");
        const backupPath = `${LEGACY_ENC_DB_FILE}.bak-${stamp}`;
        fs.copyFileSync(LEGACY_ENC_DB_FILE, backupPath);
        sqliteStore.importDatabaseState(parsed);
        importedFromLegacy = true;
        console.log(
          `[STORAGE] Automatically migrated legacy ${path.basename(LEGACY_ENC_DB_FILE)} to SQLite WAL (${path.basename(SQLITE_DB_FILE)}). Backup saved at ${path.basename(backupPath)}.`,
        );
      } catch (err) {
        if (IS_PRODUCTION) {
          throw new Error(
            `FATAL: Could not decrypt or verify legacy production database (${err instanceof Error ? err.message : "unknown"}). Refusing to overwrite with seed.`,
          );
        }
      }
    }

    if (!importedFromLegacy && !IS_PRODUCTION && fs.existsSync(LEGACY_DB_FILE)) {
      try {
        const raw = normalizeLegacyDatabaseState(
          JSON.parse(fs.readFileSync(LEGACY_DB_FILE, "utf8")) as DatabaseState,
        );
        sqliteStore.importDatabaseState(raw);
        fs.unlinkSync(LEGACY_DB_FILE);
        importedFromLegacy = true;
      } catch {
        // Fall through to seed
      }
    }

    if (!importedFromLegacy) {
      const bootstrapState = IS_PRODUCTION
        ? buildProductionBootstrapDatabase()
        : buildSeedDatabase();
      sqliteStore.importDatabaseState(bootstrapState);
    }
  }

  return sqliteStore;
}

const store = initializeSqliteStore();
const runtimeSecrets = store.getRuntimeSecrets();
store.assertNoDefaultCredentialsInProduction(
  IS_PRODUCTION,
  verifyPassword,
  hashPassword,
  sha256Hex,
  constantTimeEqual,
  runtimeSecrets.kiosk_salt,
);

const serverSigningPrivateKey = crypto.createPrivateKey(runtimeSecrets.signing_private_pem);
const serverSigningPublicSpki = runtimeSecrets.signing_public_spki;
const serverSigningKeyId = sha256Hex(serverSigningPublicSpki).slice(0, 16);

store.cleanupExpiredAndAgedData();
setInterval(() => store.cleanupExpiredAndAgedData(), 6 * 3600 * 1000).unref();

process.on("SIGINT", () => {
  store.close();
  process.exit(0);
});
process.on("SIGTERM", () => {
  store.close();
  process.exit(0);
});

function extractClientIp(req: Request): string {
  // Use Cloudflare's validated edge header ONLY when Cloudflare proxy protection is explicitly active and CF-Ray is present.
  const policy = store.getSecurityPolicy();
  if (policy.cloudflare_enabled && policy.trust_cf_headers && req.header("cf-ray")) {
    const cfIp = (req.header("cf-connecting-ip") ?? "").trim();
    if (cfIp && net.isIP(cfIp) !== 0) {
      return cfIp;
    }
  }
  // Otherwise rely exclusively on Express req.ip governed by configured "trust proxy".
  return req.ip || req.socket.remoteAddress || "unknown";
}

function getIpHash(req: Request): string {
  return hmacSha256Hex(runtimeSecrets.ip_salt, extractClientIp(req));
}

function getUaHash(req: Request): string {
  const ua = typeof req.headers["user-agent"] === "string" ? req.headers["user-agent"] : "";
  return sha256Hex(ua).slice(0, 16);
}

// Ephemeral in-memory ECDH P-256 + HKDF-SHA256 + AES-256-GCM transport channels
const secChannels = new Map<string, SecChannel>();

setInterval(() => {
  const now = Date.now();
  for (const [id, ch] of secChannels.entries()) {
    if (ch.expiresAtMs <= now) {
      secChannels.delete(id);
    }
  }
}, 60_000).unref();

function encryptTransportFrame(
  key: Buffer,
  channelId: string,
  method: string,
  pathname: string,
  payload: unknown,
) {
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(`${channelId}:${method.toUpperCase()}:${pathname}`, "utf8");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encrypted: true as const,
    alg: "AES-256-GCM" as const,
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    ciphertext: encrypted.toString("base64url"),
  };
}

function decryptTransportFrame(
  key: Buffer,
  channelId: string,
  method: string,
  pathname: string,
  body: Record<string, unknown>,
): unknown {
  const iv = Buffer.from(String(body.iv ?? ""), "base64url");
  const tag = Buffer.from(String(body.tag ?? ""), "base64url");
  const ciphertext = Buffer.from(String(body.ciphertext ?? ""), "base64url");
  const aad = Buffer.from(`${channelId}:${method.toUpperCase()}:${pathname}`, "utf8");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  return JSON.parse(decrypted);
}

// Deep prototype-pollution sanitizer & SQLi / XSS detector
const PASSWORD_KEYS = new Set(["password", "current_password", "new_password", "new_secret"]);
const SQLI_XSS_PATTERNS = [
  /(\bunion\b\s+(all\s+)?\bselect\b)/i,
  /(;\s*(drop|delete|truncate|alter|exec|execute)\b)/i,
  /(--\s*$|\/\*[\s\S]*?\*\/)/,
  /(\b(or|and)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+)/i,
  /(\bpg_sleep\s*\(|\bwaitfor\s+delay\b|\bxp_cmdshell\b|\binto\s+outfile\b)/i,
  /(<\s*script\b|javascript:|on(error|load|click|mouseover)\s*=)/i,
];

function sanitizeAndInspectValue(value: unknown, keyName = "", depth = 0): { safe: boolean; cleaned: unknown } {
  if (depth > 6) return { safe: false, cleaned: null };
  if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number") {
    return { safe: true, cleaned: value };
  }
  if (typeof value === "string") {
    if (value.includes("\0")) return { safe: false, cleaned: null };
    if (!PASSWORD_KEYS.has(keyName)) {
      for (const pat of SQLI_XSS_PATTERNS) {
        if (pat.test(value)) {
          return { safe: false, cleaned: null };
        }
      }
    }
    return { safe: true, cleaned: value };
  }
  if (Array.isArray(value)) {
    if (value.length > 100) return { safe: false, cleaned: null };
    const out: unknown[] = [];
    for (const item of value) {
      const res = sanitizeAndInspectValue(item, keyName, depth + 1);
      if (!res.safe) return { safe: false, cleaned: null };
      out.push(res.cleaned);
    }
    return { safe: true, cleaned: out };
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);
    if (keys.length > 60) return { safe: false, cleaned: null };
    const cleanObj: Record<string, unknown> = {};
    for (const k of keys) {
      if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
      const res = sanitizeAndInspectValue(obj[k], k, depth + 1);
      if (!res.safe) return { safe: false, cleaned: null };
      cleanObj[k] = res.cleaned;
    }
    return { safe: true, cleaned: cleanObj };
  }
  return { safe: false, cleaned: null };
}

const SESSION_POLICIES: Record<
  UserRole,
  { idleMs: number; absoluteMs: number; maxConcurrent: number }
> = {
  admin: { idleMs: 15 * 60_000, absoluteMs: 2 * 3600_000, maxConcurrent: 1 },
  employee: { idleMs: 60 * 60_000, absoluteMs: 8 * 3600_000, maxConcurrent: 2 },
  kiosk: { idleMs: 12 * 3600_000, absoluteMs: 12 * 3600_000, maxConcurrent: 1 },
};

function signSessionToken(user: StoredUser, uaHash: string, ipHash: string): string {
  const nowMs = Date.now();
  const iat = Math.floor(nowMs / 1000);
  const policy = SESSION_POLICIES[user.role];
  const expMs = nowMs + policy.absoluteMs;
  const exp = Math.floor(expMs / 1000);
  const jti = crypto.randomUUID();
  const nowIso = new Date(nowMs).toISOString();

  store.createActiveSessionWithEviction(
    {
      jti,
      user_id: user.id,
      role: user.role,
      aal: "aal1",
      ua_hash: uaHash,
      ip_hash: ipHash,
      created_at: nowIso,
      last_active_at: nowIso,
      idle_expires_at: new Date(nowMs + policy.idleMs).toISOString(),
      absolute_expires_at: new Date(expMs).toISOString(),
    },
    policy.maxConcurrent,
    nowIso,
  );

  const payload = Buffer.from(
    JSON.stringify({
      sub: user.id,
      role: user.role,
      tv: user.token_version,
      ua: uaHash,
      jti,
      iat,
      exp,
    }),
  ).toString("base64url");
  const sig = crypto
    .createHmac("sha256", runtimeSecrets.auth_secret)
    .update(payload)
    .digest("base64url");
  return `${payload}.${sig}`;
}

function signAdminStepUpToken(
  user: StoredUser,
  uaHash: string,
  aal: "aal1" | "aal2",
): { token: string; expiresAt: string } {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 15 * 60;
  const jti = crypto.randomUUID();
  const payload = Buffer.from(
    JSON.stringify({
      sub: user.id,
      tv: user.token_version,
      ua: uaHash,
      aal,
      stepUp: true,
      jti,
      iat,
      exp,
    }),
  ).toString("base64url");
  const sig = crypto
    .createHmac("sha256", runtimeSecrets.auth_secret)
    .update(payload)
    .digest("base64url");
  return {
    token: `${payload}.${sig}`,
    expiresAt: new Date(exp * 1000).toISOString(),
  };
}

function verifyAdminStepUpToken(
  token: string,
  user: StoredUser,
  uaHash: string,
): { valid: boolean; aal?: "aal1" | "aal2" } {
  const parts = token.split(".");
  if (parts.length !== 2) return { valid: false };
  const [payload, sig] = parts;
  const expectedSig = crypto
    .createHmac("sha256", runtimeSecrets.auth_secret)
    .update(payload)
    .digest("base64url");
  if (!constantTimeEqual(sig, expectedSig)) return { valid: false };
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
      sub?: string;
      tv?: number;
      ua?: string;
      aal?: "aal1" | "aal2";
      stepUp?: boolean;
      jti?: string;
      exp?: number;
    };
    if (
      decoded.stepUp !== true ||
      decoded.sub !== user.id ||
      decoded.tv !== user.token_version ||
      !decoded.ua ||
      !constantTimeEqual(decoded.ua, uaHash) ||
      !decoded.jti ||
      !decoded.exp ||
      decoded.exp * 1000 <= Date.now()
    ) {
      return { valid: false };
    }
    if (store.isJtiRevoked(decoded.jti)) return { valid: false };
    return { valid: true, aal: decoded.aal ?? "aal1" };
  } catch {
    return { valid: false };
  }
}

function verifySessionToken(token: string, uaHash?: string): {
  sub: string;
  role: UserRole;
  tv: number;
  ua?: string;
  jti: string;
  iat: number;
  exp: number;
} | null {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expectedSig = crypto
    .createHmac("sha256", runtimeSecrets.auth_secret)
    .update(payload)
    .digest("base64url");
  if (!constantTimeEqual(sig, expectedSig)) return null;
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
      sub?: string;
      role?: UserRole;
      tv?: number;
      ua?: string;
      jti?: string;
      iat?: number;
      exp?: number;
    };
    if (
      !decoded.sub ||
      !decoded.role ||
      typeof decoded.tv !== "number" ||
      !decoded.jti ||
      !decoded.exp ||
      !decoded.iat
    ) {
      return null;
    }
    if (decoded.exp * 1000 <= Date.now()) return null;
    if (store.isJtiRevoked(decoded.jti)) return null;
    if (uaHash && decoded.ua && !constantTimeEqual(decoded.ua, uaHash)) {
      return null;
    }
    return {
      sub: decoded.sub,
      role: decoded.role,
      tv: decoded.tv,
      ua: decoded.ua,
      jti: decoded.jti,
      iat: decoded.iat,
      exp: decoded.exp,
    };
  } catch {
    return null;
  }
}

function resolveUserPermissions(
  u: StoredUser,
  rolesMap?: Record<string, RbacRoleDefinition>,
): PermissionKey[] {
  if (u.role !== "admin" || !u.is_active) return [];
  if (Array.isArray(u.permissions) && u.permissions.length > 0) {
    return u.permissions.filter((p): p is PermissionKey => ALL_PERMISSION_KEYS.includes(p));
  }
  const roleKey = u.admin_role_key || "super_admin";
  const resolvedMap = rolesMap ?? store.getRbacRoles();
  const def = resolvedMap[roleKey];
  if (def) {
    return def.permissions.filter((p): p is PermissionKey => ALL_PERMISSION_KEYS.includes(p));
  }
  return roleKey === "super_admin" ? [...ALL_PERMISSION_KEYS] : ["view_overview"];
}

function toPublicProfile(u: StoredUser, rolesMap?: Record<string, RbacRoleDefinition>) {
  return {
    id: u.id,
    email: u.email,
    full_name: u.full_name,
    employee_number: u.employee_number,
    department: u.department,
    job_title: u.job_title,
    shift_start: u.shift_start,
    shift_end: u.shift_end,
    role: u.role,
    admin_role_key: u.admin_role_key ?? null,
    permissions: u.role === "admin" ? resolveUserPermissions(u, rolesMap) : undefined,
    is_active: u.is_active,
    mfa_enabled: Boolean(u.mfa_enabled),
    created_at: u.created_at,
    updated_at: u.updated_at,
  };
}

function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  if (!token) {
    res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
    return;
  }
  const verified = verifySessionToken(token, getUaHash(req));
  if (!verified) {
    res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
    return;
  }
  const user = store.getUserById(verified.sub);
  if (!user || user.token_version !== verified.tv) {
    res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
    return;
  }
  if (!user.is_active) {
    res.status(403).json({ ok: false, error: "ACCOUNT_UNAVAILABLE" });
    return;
  }

  const nowMs = Date.now();
  const activeSession = store.getActiveSession(verified.jti, user.id);
  if (
    !activeSession ||
    Date.parse(activeSession.absolute_expires_at) <= nowMs ||
    Date.parse(activeSession.idle_expires_at) <= nowMs
  ) {
    if (activeSession) store.revokeSessionByJti(activeSession.jti);
    res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
    return;
  }

  const policy = SESSION_POLICIES[user.role];
  const lastActiveIso = new Date(nowMs).toISOString();
  const nextIdleIso = new Date(nowMs + policy.idleMs).toISOString();
  store.touchActiveSession(activeSession.jti, lastActiveIso, nextIdleIso);
  activeSession.last_active_at = lastActiveIso;
  activeSession.idle_expires_at = nextIdleIso;

  req.authUser = user;
  req.authSession = activeSession;
  req.authIssuedAtSec = verified.iat;
  req.authJti = verified.jti;
  req.authExpMs = verified.exp * 1000;
  next();
}

function requireEncryptedChannel(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  if (!req.secChannel) {
    res.status(428).json({ ok: false, error: "ENCRYPTED_CHANNEL_REQUIRED" });
    return;
  }
  next();
}

function verifyAdminStepUpGate(
  req: AuthenticatedRequest,
  res: Response,
  enforceMfa: boolean,
): boolean {
  const user = req.authUser;
  if (!user || user.role !== "admin" || !user.is_active) {
    res.status(403).json({ ok: false, error: "FORBIDDEN" });
    return false;
  }
  const stepUpHeader = String(req.headers["x-admin-stepup"] ?? "").trim();
  const stepUp = stepUpHeader
    ? verifyAdminStepUpToken(stepUpHeader, user, getUaHash(req))
    : { valid: false };
  if (!stepUp.valid) {
    res.status(403).json({ ok: false, error: "ADMIN_STEP_UP_REQUIRED" });
    return false;
  }
  if (enforceMfa && (user.mfa_enabled || REQUIRE_ADMIN_MFA) && stepUp.aal !== "aal2") {
    res.status(403).json({
      ok: false,
      error: user.mfa_enabled ? "MFA_REQUIRED" : "MFA_SETUP_REQUIRED",
    });
    return false;
  }
  return true;
}

function requireAdminWithStepUp(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  if (!verifyAdminStepUpGate(req, res, true)) return;
  next();
}

function requireAdminStepUpForMfaSetup(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  if (!verifyAdminStepUpGate(req, res, false)) return;
  next();
}

function requirePermission(permission: PermissionKey) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const user = req.authUser;
    if (!user || user.role !== "admin" || !user.is_active) {
      res.status(403).json({ ok: false, error: "FORBIDDEN" });
      return;
    }
    const perms = resolveUserPermissions(user);
    if (!perms.includes(permission)) {
      store.addSecurityLog(user.id, "permission_denied", `MISSING_${permission.toUpperCase()}`, getIpHash(req), {
        required_permission: permission,
        path: req.path,
      });
      res.status(403).json({ ok: false, error: "PERMISSION_DENIED", missing_permission: permission });
      return;
    }
    next();
  };
}

function emitSecurityAlert(
  severity: SecurityAlertEntry["severity"],
  event: string,
  requestId: string | null,
  ipHash: string | null,
  details: Record<string, unknown> = {},
): void {
  const alert: SecurityAlertEntry = {
    id: `alert-${crypto.randomUUID()}`,
    severity,
    event,
    request_id: requestId,
    ip_hash: ipHash,
    created_at: new Date().toISOString(),
    details,
  };
  store.addSecurityAlert(alert);

  if (severity === "critical" || severity === "high") {
    console.warn(JSON.stringify({ level: "SECURITY_ALERT", ...alert }));
  }

  const webhook = process.env.ALERT_WEBHOOK_URL?.trim();
  if (webhook && /^https:\/\//i.test(webhook)) {
    void fetch(webhook, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(alert),
      signal: AbortSignal.timeout(4000),
    }).catch(() => undefined);
  }
}

// Bounded in-memory sliding window + lockout rate limiter (with optional distributed Redis REST store)
const MAX_RATE_MAP_SIZE = 10_000;
const rateMap = new Map<string, { attempts: number; windowStart: number; blockedUntil: number }>();

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateMap.entries()) {
    if (v.blockedUntil <= now && now - v.windowStart > 3600_000) {
      rateMap.delete(k);
    }
  }
}, 120_000).unref();

function checkRateLimit(
  key: string,
  maxAttempts: number,
  windowMs: number,
  blockMs: number,
): { allowed: true } | { allowed: false; retryAfterSeconds: number } {
  const now = Date.now();
  if (rateMap.size >= MAX_RATE_MAP_SIZE) {
    const oldest = rateMap.keys().next().value;
    if (oldest) rateMap.delete(oldest);
  }
  const entry = rateMap.get(key);
  if (entry && entry.blockedUntil > now) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((entry.blockedUntil - now) / 1000)),
    };
  }
  if (!entry || now - entry.windowStart >= windowMs) {
    rateMap.set(key, { attempts: 1, windowStart: now, blockedUntil: 0 });
    return { allowed: true };
  }
  if (entry.attempts + 1 > maxAttempts) {
    entry.attempts += 1;
    entry.blockedUntil = now + blockMs;
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil(blockMs / 1000),
    };
  }
  entry.attempts += 1;
  return { allowed: true };
}

async function checkDistributedRateLimit(
  key: string,
  maxAttempts: number,
  windowMs: number,
  blockMs: number,
): Promise<{ allowed: true } | { allowed: false; retryAfterSeconds: number; unavailable?: boolean }> {
  const redisUrl = process.env.REDIS_REST_URL?.trim();
  const redisToken = process.env.REDIS_REST_TOKEN?.trim();
  const requireDistributed = process.env.REQUIRE_DISTRIBUTED_RATE_LIMIT === "true";

  if (redisUrl && redisToken) {
    try {
      const res = await fetch(`${redisUrl.replace(/\/+$/, "")}/pipeline`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${redisToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify([
          ["INCR", `rl:${key}`],
          ["PEXPIRE", `rl:${key}`, String(windowMs), "NX"],
        ]),
        signal: AbortSignal.timeout(2500),
      });
      if (!res.ok) throw new Error(`REDIS_HTTP_${res.status}`);
      const results = (await res.json()) as Array<{ result?: number }>;
      const count = Number(results?.[0]?.result ?? 0);
      if (count > maxAttempts) {
        return { allowed: false, retryAfterSeconds: Math.ceil(blockMs / 1000) };
      }
      return { allowed: true };
    } catch {
      if (requireDistributed) {
        return { allowed: false, retryAfterSeconds: 30, unavailable: true };
      }
    }
  } else if (requireDistributed) {
    return { allowed: false, retryAfterSeconds: 30, unavailable: true };
  }

  return checkRateLimit(key, maxAttempts, windowMs, blockMs);
}

function resetRateLimit(key: string): void {
  rateMap.delete(key);
}

async function verifyKioskAuth(
  req: AuthenticatedRequest,
  ipHash: string,
): Promise<{ ok: true; device: KioskDevice } | { ok: false; status: number; error: string }> {
  const user = req.authUser;
  if (!user || user.role !== "kiosk" || !user.is_active) {
    return { ok: false, status: 403, error: "FORBIDDEN" };
  }
  const device = store.getKioskByAuthUserId(user.id);
  if (!device || !device.is_active) {
    return { ok: false, status: 403, error: "KIOSK_NOT_AUTHORIZED" };
  }
  if (device.revoked_before) {
    const revokedMs = Date.parse(device.revoked_before);
    const issuedMs = (req.authIssuedAtSec ?? 0) * 1000;
    if (!Number.isFinite(issuedMs) || issuedMs <= revokedMs) {
      return { ok: false, status: 401, error: "KIOSK_SESSION_REVOKED" };
    }
  }
  const providedSecret = String(req.headers["x-kiosk-secret"] ?? "").trim();
  if (!providedSecret) {
    return { ok: false, status: 403, error: "DEVICE_SECRET_REQUIRED" };
  }
  const failLimit = await checkDistributedRateLimit(
    `kiosk-secret:${device.id}:${ipHash}`,
    8,
    300_000,
    900_000,
  );
  if (!failLimit.allowed) {
    return {
      ok: false,
      status: failLimit.unavailable ? 503 : 429,
      error: failLimit.unavailable ? "RATE_LIMIT_UNAVAILABLE" : "RATE_LIMITED",
    };
  }
  const providedHash = sha256Hex(`${runtimeSecrets.kiosk_salt}:${providedSecret}`);
  if (!constantTimeEqual(providedHash, device.secret_hash)) {
    store.addSecurityLog(user.id, "kiosk_auth_failed", "DEVICE_SECRET_INVALID", ipHash);
    return { ok: false, status: 403, error: "DEVICE_SECRET_INVALID" };
  }
  resetRateLimit(`kiosk-secret:${device.id}:${ipHash}`);
  return { ok: true, device };
}

function validateGpsTimestamp(clientCapturedAt: unknown): boolean {
  if (typeof clientCapturedAt !== "string" || clientCapturedAt.trim().length === 0) {
    return false;
  }
  const capturedMs = Date.parse(clientCapturedAt);
  if (!Number.isFinite(capturedMs)) return false;
  const ageMs = Date.now() - capturedMs;
  return ageMs <= 30_000 && ageMs >= -10_000;
}

async function startServer(): Promise<void> {
  const app = express();
  app.disable("x-powered-by");

  const isCloudRun = Boolean(process.env.K_SERVICE || process.env.CLOUD_RUN_JOB);
  const trustProxyEnv = process.env.TRUST_PROXY?.trim();
  let trustProxySetting: boolean | number | string | string[] = isCloudRun
    ? 1
    : IS_PRODUCTION
      ? false
      : 1;
  if (trustProxyEnv) {
    if (trustProxyEnv === "false") trustProxySetting = false;
    else if (trustProxyEnv === "true") trustProxySetting = true;
    else if (/^\d+$/.test(trustProxyEnv)) trustProxySetting = Number(trustProxyEnv);
    else if (trustProxyEnv.includes(",")) {
      trustProxySetting = trustProxyEnv.split(",").map((s) => s.trim()).filter(Boolean);
    } else {
      trustProxySetting = trustProxyEnv;
    }
  }
  app.set("trust proxy", trustProxySetting);

  // Assign correlation Request ID and enforce 15s request timeout
  app.use((req: AuthenticatedRequest, res, next) => {
    const reqId = crypto.randomUUID();
    req.requestId = reqId;
    res.setHeader("X-Request-Id", reqId);
    req.setTimeout(15_000);
    res.setTimeout(15_000);
    next();
  });

  // Mandatory HTTPS enforcement for API traffic in production (allow Cloud Run internal HTTP health & SPA shell probes)
  if (IS_PRODUCTION && REQUIRE_HTTPS) {
    app.use((req, res, next) => {
      if (req.path === "/api/health" || !req.path.startsWith("/api/")) {
        next();
        return;
      }
      const forwardedProto = String(req.headers["x-forwarded-proto"] ?? "")
        .split(",")[0]
        .trim()
        .toLowerCase();
      if (!req.secure && forwardedProto !== "https") {
        res.status(426).json({ ok: false, error: "HTTPS_REQUIRED" });
        return;
      }
      next();
    });
  }

  const allowedFrameAncestors = process.env.ALLOWED_FRAME_ANCESTORS?.trim()
    ? process.env.ALLOWED_FRAME_ANCESTORS.split(",").map((s) => s.trim()).filter(Boolean)
    : IS_PRODUCTION
      ? ["'none'"]
      : [
          "'self'",
          "https://aistudio.google.com",
          "https://*.aistudio.google.com",
          "https://*.googleusercontent.com",
        ];

  // Helmet security headers with full CSP and environment-aware framing policy
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: IS_PRODUCTION
            ? ["'self'", "https://challenges.cloudflare.com"]
            : ["'self'", "'unsafe-inline'", "https://challenges.cloudflare.com"],
          frameSrc: ["'self'", "https://challenges.cloudflare.com"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
          imgSrc: ["'self'", "data:", "blob:"],
          connectSrc: ["'self'", "https:", "wss:"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          frameAncestors: allowedFrameAncestors,
          ...(IS_PRODUCTION ? {} : { upgradeInsecureRequests: null }),
        },
      },
      frameguard: IS_PRODUCTION ? { action: "deny" } : false,
      hsts: IS_PRODUCTION
        ? { maxAge: 31_536_000, includeSubDomains: true, preload: true }
        : false,
      crossOriginEmbedderPolicy: false,
      crossOriginResourcePolicy: { policy: "same-site" },
      referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    }),
  );

  // Additional strict security, CORS, Method-Override, JSON Content-Type & Cloudflare Free WAF guards
  const allowedCorsOrigins = new Set(
    (process.env.ALLOWED_ORIGINS ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const configuredAppUrl = process.env.APP_URL?.trim();
  if (configuredAppUrl) {
    try {
      allowedCorsOrigins.add(new URL(configuredAppUrl).origin);
    } catch {
      // Ignore malformed APP_URL
    }
  }

  app.use((req: AuthenticatedRequest, res, next) => {
    res.setHeader("Permissions-Policy", "camera=(self), geolocation=(self), microphone=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    if (req.path.startsWith("/api/")) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("X-Robots-Tag", "noindex, nofollow");

      const policy = store.getSecurityPolicy();

      // 1. Block HTTP Method-Override smuggling headers
      if (
        policy.block_method_override &&
        (req.headers["x-http-method-override"] ||
          req.headers["x-method-override"] ||
          req.headers["x-original-method"])
      ) {
        res.status(405).json({ ok: false, error: "METHOD_OVERRIDE_BLOCKED" });
        return;
      }

      // 2. Strict CORS origin check for API traffic (supports trusted reverse proxies rewriting Host)
      const origin = typeof req.headers.origin === "string" ? req.headers.origin.trim() : "";
      if (origin) {
        let parsedOrigin: URL | null = null;
        try {
          parsedOrigin = new URL(origin);
        } catch {
          parsedOrigin = null;
        }
        const originValid =
          Boolean(parsedOrigin) &&
          (parsedOrigin!.protocol === "https:" || parsedOrigin!.protocol === "http:") &&
          parsedOrigin!.origin === origin;

        const hostHeader = (req.header("host") ?? "").trim().toLowerCase();
        const trustProxyActive = Boolean(app.get("trust proxy"));
        const rawForwardedHost = trustProxyActive
          ? String(req.header("x-forwarded-host") ?? "")
              .split(",")[0]
              .trim()
              .toLowerCase()
          : "";
        const forwardedHost = /^[a-z0-9.-]+(:\d{1,5})?$/i.test(rawForwardedHost)
          ? rawForwardedHost.replace(/:(443|80)$/, "")
          : "";

        const originHost = parsedOrigin?.host.toLowerCase() ?? "";
        const isSameOrigin =
          originValid &&
          ((hostHeader.length > 0 && originHost === hostHeader) ||
            (forwardedHost.length > 0 && originHost === forwardedHost));

        const isDevLocalhost =
          !IS_PRODUCTION &&
          originValid &&
          /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin);
        const isExplicitlyAllowed = originValid && allowedCorsOrigins.has(origin);

        if (!originValid || (!isSameOrigin && !isDevLocalhost && !isExplicitlyAllowed)) {
          res.status(403).json({ ok: false, error: "CORS_ORIGIN_REJECTED" });
          return;
        }
        res.setHeader("Vary", "Origin");
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
        res.setHeader(
          "Access-Control-Allow-Headers",
          "Authorization, Content-Type, X-Sec-Channel, X-Admin-Stepup, X-Kiosk-Secret",
        );
      }

      if (req.method === "OPTIONS") {
        res.status(204).end();
        return;
      }

      // 3. Enforce application/json Content-Type on state-changing requests with a payload
      if (
        policy.enforce_json_content_type &&
        (req.method === "POST" || req.method === "PUT" || req.method === "PATCH")
      ) {
        const contentLen = Number(req.header("content-length") ?? "0");
        const contentType = (req.header("content-type") ?? "").toLowerCase();
        if (contentLen > 0 && !contentType.includes("application/json")) {
          res.status(415).json({ ok: false, error: "UNSUPPORTED_MEDIA_TYPE" });
          return;
        }
      }

      // 4. Cloudflare Free Edge WAF Controls (Country Allowlist + CF-Threat-Score guard)
      if (policy.cloudflare_enabled && req.path !== "/api/health") {
        const ipHash = getIpHash(req);
        const cfCountry = (req.header("cf-ipcountry") ?? "").trim().toUpperCase();
        if (
          policy.allowed_countries.length > 0 &&
          cfCountry &&
          cfCountry !== "XX" &&
          cfCountry !== "T1" &&
          !policy.allowed_countries.includes(cfCountry)
        ) {
          store.addSecurityLog(null, "cf_country_blocked", "COUNTRY_BLOCKED", ipHash, {
            country: cfCountry,
            path: req.path,
          });
          emitSecurityAlert("high", "cf_country_blocked", req.requestId ?? null, ipHash, {
            country: cfCountry,
          });
          res.status(403).json({ ok: false, error: "COUNTRY_BLOCKED" });
          return;
        }

        const threatRaw = req.header("cf-threat-score");
        if (threatRaw !== undefined) {
          const score = Number(threatRaw);
          if (Number.isFinite(score) && score >= policy.max_cf_threat_score) {
            store.addSecurityLog(null, "cf_waf_threat_blocked", "WAF_THREAT_BLOCKED", ipHash, {
              cf_threat_score: score,
              path: req.path,
            });
            emitSecurityAlert("critical", "cf_waf_threat_blocked", req.requestId ?? null, ipHash, {
              cf_threat_score: score,
            });
            res.status(403).json({ ok: false, error: "WAF_THREAT_BLOCKED" });
            return;
          }
        }
      }
    }
    next();
  });

  app.use(express.json({ limit: "64kb", strict: true }));
  app.use(hpp());

  // Layered express-rate-limit protection
  const globalApiLimiter = rateLimit({
    windowMs: 60_000,
    max: 180,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => getIpHash(req),
    message: { ok: false, error: "RATE_LIMITED" },
  });

  const handshakeLimiter = rateLimit({
    windowMs: 60_000,
    max: 40,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => getIpHash(req),
    message: { ok: false, error: "RATE_LIMITED" },
  });

  const hrAdminLimiter = rateLimit({
    windowMs: 60_000,
    max: 80,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => getIpHash(req),
    message: { ok: false, error: "RATE_LIMITED" },
  });

  const hrExportLimiter = rateLimit({
    windowMs: 3_600_000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => getIpHash(req),
    message: { ok: false, error: "EXPORT_RATE_LIMITED" },
  });

  app.use("/api/", globalApiLimiter);
  app.use("/api/hr/", hrAdminLimiter);

  app.get("/api/health", (_req, res) => {
    const policy = store.getSecurityPolicy();
    res.json({
      ok: true,
      mode: "express-attendance",
      storage_engine: "sqlite-wal",
      encrypted_storage: true,
      payload_transport: "ECDH-P256-ECDSA-AES-256-GCM (complementary to HTTPS/TLS)",
      waf_sqli_guard: true,
      cloudflare_waf_active: Boolean(policy.cloudflare_enabled),
      admin_mfa_required: REQUIRE_ADMIN_MFA,
    });
  });

  app.get("/api/auth/public-config", (_req, res) => {
    const policy = store.getSecurityPolicy();
    const hasSecret = Boolean(process.env.TURNSTILE_SECRET_KEY?.trim());
    res.json({
      ok: true,
      turnstile_enabled: Boolean(policy.turnstile_enabled && hasSecret && policy.turnstile_site_key),
      turnstile_site_key: policy.turnstile_enabled && hasSecret ? policy.turnstile_site_key : "",
    });
  });

  app.get("/api/security/public-key", (_req, res) => {
    res.json({
      ok: true,
      alg: "ECDSA-P256-SHA256",
      key_id: serverSigningKeyId,
      signing_public_key: serverSigningPublicSpki,
    });
  });

  // Ephemeral ECDH P-256 + HKDF-SHA256 + ECDSA P-256 Signed Key Exchange (complementary to TLS)
  const handshakeSchema = z
    .object({
      client_public_key: z.string().min(40).max(512),
      client_nonce: z.string().min(12).max(128),
    })
    .strict();

  app.post("/api/security/handshake", handshakeLimiter, (req, res) => {
    const parsed = handshakeSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ ok: false, error: "INVALID_HANDSHAKE" });
      return;
    }

    try {
      const clientPubDer = Buffer.from(parsed.data.client_public_key, "base64url");
      const clientPublicKey = crypto.createPublicKey({
        key: clientPubDer,
        format: "der",
        type: "spki",
      });

      const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "prime256v1",
      });
      const sharedSecret = crypto.diffieHellman({ privateKey, publicKey: clientPublicKey });
      const channelId = crypto.randomUUID();
      const salt = Buffer.from(`${parsed.data.client_nonce}:${channelId}`, "utf8");
      const aesKey = Buffer.from(
        crypto.hkdfSync("sha256", sharedSecret, salt, Buffer.from("insight-e2ee-v1", "utf8"), 32),
      );

      if (secChannels.size > 2000) {
        const oldestKey = secChannels.keys().next().value;
        if (oldestKey) secChannels.delete(oldestKey);
      }

      const expiresAtMs = Date.now() + 15 * 60_000;
      const expiresAtIso = new Date(expiresAtMs).toISOString();
      secChannels.set(channelId, {
        id: channelId,
        key: aesKey,
        uaHash: getUaHash(req),
        ipHash: getIpHash(req),
        expiresAtMs,
      });

      const serverPublicKey = publicKey.export({ format: "der", type: "spki" }).toString("base64url");
      const transcript = `${channelId}|${serverPublicKey}|${parsed.data.client_public_key}|${parsed.data.client_nonce}|${expiresAtIso}`;
      const signature = crypto
        .sign("sha256", Buffer.from(transcript, "utf8"), {
          key: serverSigningPrivateKey,
          dsaEncoding: "ieee-p1363",
        })
        .toString("base64url");

      res.json({
        ok: true,
        channel_id: channelId,
        server_public_key: serverPublicKey,
        expires_at: expiresAtIso,
        key_id: serverSigningKeyId,
        signing_public_key: serverSigningPublicSpki,
        signature,
      });
    } catch {
      res.status(400).json({ ok: false, error: "INVALID_HANDSHAKE" });
    }
  });

  // Decrypt inbound E2EE envelopes, sanitize & inspect against SQLi/XSS, and encrypt outbound JSON
  app.use("/api/", (req: AuthenticatedRequest, res, next) => {
    if (
      req.path === "/health" ||
      req.path === "/security/handshake" ||
      req.path === "/security/public-key"
    ) {
      next();
      return;
    }

    const channelHeader = req.headers["x-sec-channel"];
    const channelId = typeof channelHeader === "string" ? channelHeader.trim() : "";

    if (channelId) {
      const channel = secChannels.get(channelId);
      const strictIp = Boolean(store.getSecurityPolicy().strict_ip_binding);
      if (
        !channel ||
        channel.expiresAtMs <= Date.now() ||
        !constantTimeEqual(channel.uaHash, getUaHash(req)) ||
        (strictIp && !constantTimeEqual(channel.ipHash, getIpHash(req)))
      ) {
        secChannels.delete(channelId);
        res.status(428).json({ ok: false, error: "ENCRYPTED_CHANNEL_EXPIRED" });
        return;
      }

      req.secChannel = channel;

      // Wrap res.json to encrypt every JSON response over the active channel
      const originalJson = res.json.bind(res);
      res.json = ((payload: unknown) => {
        const envelope = encryptTransportFrame(
          channel.key,
          channel.id,
          req.method,
          req.originalUrl.split("?")[0],
          payload,
        );
        return originalJson(envelope);
      }) as typeof res.json;

      // Decrypt inbound body if sent as an encrypted envelope
      if (
        req.body &&
        typeof req.body === "object" &&
        (req.body as Record<string, unknown>).encrypted === true
      ) {
        try {
          const decryptedBody = decryptTransportFrame(
            channel.key,
            channel.id,
            req.method,
            req.originalUrl.split("?")[0],
            req.body as Record<string, unknown>,
          );
          req.body = decryptedBody;
        } catch {
          res.status(400).json({ ok: false, error: "DECRYPTION_FAILED" });
          return;
        }
      }
    }

    // Prototype pollution sanitization + SQLi / XSS pattern guard across query, params, and body
    const bodyCheck = sanitizeAndInspectValue(req.body);
    const queryCheck = sanitizeAndInspectValue(req.query);
    if (!bodyCheck.safe || !queryCheck.safe) {
      const ipHash = getIpHash(req);
      store.addSecurityLog(null, "sqli_or_xss_blocked", "MALICIOUS_INPUT_DETECTED", ipHash, {
        path: req.path,
        method: req.method,
      });
      emitSecurityAlert("high", "sqli_or_xss_blocked", req.requestId ?? null, ipHash, {
        path: req.path,
        method: req.method,
      });
      res.status(400).json({ ok: false, error: "MALICIOUS_INPUT_DETECTED" });
      return;
    }
    req.body = bodyCheck.cleaned;
    next();
  });

  // Zod schemas for strict runtime validation
  const loginSchema = z
    .object({
      email: z.string().trim().email().max(254),
      password: z.string().min(1).max(128),
      turnstile_token: z.string().trim().max(2048).optional(),
    })
    .strict();

  // Rate-limited Login with distributed limiter, optional Cloudflare Turnstile verification & alerting
  app.post("/api/auth/login", async (req: AuthenticatedRequest, res) => {
    const ipHash = getIpHash(req);
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ ok: false, error: "INVALID_CREDENTIALS" });
      return;
    }

    const policy = store.getSecurityPolicy();
    const turnstileSecret = process.env.TURNSTILE_SECRET_KEY?.trim() ?? "";
    if (policy.turnstile_enabled && turnstileSecret && policy.turnstile_site_key) {
      const cfToken = parsed.data.turnstile_token ?? "";
      if (!cfToken) {
        res.status(403).json({ ok: false, error: "CAPTCHA_REQUIRED" });
        return;
      }
      try {
        const form = new URLSearchParams();
        form.set("secret", turnstileSecret);
        form.set("response", cfToken);
        form.set("remoteip", extractClientIp(req));
        const verifyRes = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
          method: "POST",
          body: form,
          signal: AbortSignal.timeout(4000),
        });
        const verifyJson = (await verifyRes.json()) as { success?: boolean };
        if (!verifyJson.success) {
          store.addSecurityLog(null, "turnstile_failed", "CAPTCHA_FAILED", ipHash);
          res.status(403).json({ ok: false, error: "CAPTCHA_FAILED" });
          return;
        }
      } catch {
        res.status(503).json({ ok: false, error: "CAPTCHA_UNAVAILABLE" });
        return;
      }
    }

    const email = parsed.data.email.toLowerCase();
    const password = parsed.data.password;

    const rateKey = `login:${email}:${ipHash}`;
    const rate = await checkDistributedRateLimit(rateKey, 5, 300_000, 600_000);
    if (!rate.allowed) {
      if (rate.unavailable) {
        res.status(503).json({ ok: false, error: "RATE_LIMIT_UNAVAILABLE" });
        return;
      }
      store.addSecurityLog(null, "login_rate_limited", "RATE_LIMITED", ipHash, {
        email_hash: sha256Hex(email).slice(0, 12),
      });
      emitSecurityAlert("high", "login_rate_limited", req.requestId ?? null, ipHash, {
        email_hash: sha256Hex(email).slice(0, 12),
      });
      res.status(429).json({
        ok: false,
        error: "RATE_LIMITED",
        retry_after_seconds: rate.retryAfterSeconds,
      });
      return;
    }

    const user = store.getUserByEmail(email);
    if (!user || !verifyPassword(password, user.password_salt, user.password_hash)) {
      store.addSecurityLog(user?.id ?? null, "login_failed", "INVALID_CREDENTIALS", ipHash, {
        email_hash: sha256Hex(email).slice(0, 12),
      });
      res.status(401).json({ ok: false, error: "INVALID_CREDENTIALS" });
      return;
    }

    if (!user.is_active) {
      store.addSecurityLog(user.id, "login_failed", "ACCOUNT_DISABLED", ipHash);
      res.status(403).json({ ok: false, error: "ACCOUNT_UNAVAILABLE" });
      return;
    }

    resetRateLimit(rateKey);
    const token = signSessionToken(user, getUaHash(req), ipHash);
    store.addSecurityLog(user.id, "login_succeeded", "OK", ipHash, { role: user.role });

    res.json({
      ok: true,
      token,
      profile: toPublicProfile(user),
    });
  });

  app.get("/api/auth/me", requireAuth, (req: AuthenticatedRequest, res) => {
    const settings = store.getSettings();
    res.json({
      ok: true,
      profile: toPublicProfile(req.authUser!),
      session: req.authSession
        ? {
            aal: req.authSession.aal,
            idle_expires_at: req.authSession.idle_expires_at,
            absolute_expires_at: req.authSession.absolute_expires_at,
          }
        : null,
      company: {
        company_name: settings.company_name,
        branch_name: settings.branch_name,
        work_start_time: settings.work_start_time,
        work_end_time: settings.work_end_time,
        late_grace_minutes: settings.late_grace_minutes,
        enforce_geofence: settings.enforce_geofence,
      },
    });
  });

  app.post("/api/auth/logout", (req, res) => {
    const authHeader = req.headers.authorization ?? "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
    if (token) {
      const verified = verifySessionToken(token, getUaHash(req));
      if (verified) {
        store.revokeSessionByJti(verified.jti);
        store.addSecurityLog(verified.sub, "logout_succeeded", "SESSION_REVOKED", getIpHash(req));
      }
    }
    res.json({ ok: true });
  });

  const changePasswordSchema = z
    .object({
      current_password: z.string().min(1).max(128),
      new_password: z.string().min(8).max(128),
    })
    .strict();

  // Change own password (invalidates ALL previous sessions & step-up tokens immediately)
  app.post("/api/auth/change-password", requireAuth, (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    const ipHash = getIpHash(req);
    const parsed = changePasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ ok: false, error: "WEAK_PASSWORD" });
      return;
    }

    if (!verifyPassword(parsed.data.current_password, user.password_salt, user.password_hash)) {
      store.addSecurityLog(user.id, "password_change_failed", "INVALID_CURRENT_PASSWORD", ipHash);
      res.status(400).json({ ok: false, error: "INVALID_CURRENT_PASSWORD" });
      return;
    }

    if (!isStrongPassword(parsed.data.new_password)) {
      res.status(400).json({ ok: false, error: "WEAK_PASSWORD" });
      return;
    }

    const newSalt = crypto.randomBytes(16).toString("hex");
    const newHash = hashPassword(parsed.data.new_password, newSalt);
    const updatedUser = store.updateUserPassword(user.id, newSalt, newHash, new Date().toISOString());

    const freshToken = signSessionToken(updatedUser ?? user, getUaHash(req), ipHash);
    store.addSecurityLog(user.id, "password_changed", "OK", ipHash);

    res.json({ ok: true, token: freshToken });
  });

  // Kiosk token issuance
  app.post("/api/kiosk/issue-token", requireAuth, async (req: AuthenticatedRequest, res) => {
    const ipHash = getIpHash(req);
    const auth = await verifyKioskAuth(req, ipHash);
    if (!auth.ok) {
      res.status(auth.status).json({ ok: false, error: auth.error });
      return;
    }

    const settings = store.getSettings();
    if (!settings.is_enabled) {
      res.status(400).json({ ok: false, error: "SERVICE_DISABLED" });
      return;
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const schedule = evaluateQrCaptureSchedule(settings, now);

    if (!schedule.open) {
      store.closeKioskQrWindow(auth.device.id, nowIso);
      res.status(200).json({
        ok: false,
        error: "QR_WINDOW_CLOSED",
        schedule_status: "closed",
        next_reappear_time: schedule.next_reappear_time,
        window_cutoff_time: schedule.window_cutoff_time,
        company_name: settings.company_name,
        branch_name: auth.device.branch_name,
        device_name: auth.device.device_name,
      });
      return;
    }

    const rawToken = crypto.randomBytes(24).toString("base64url");
    const tokenHash = sha256Hex(rawToken);
    const manualCode = generateManualCode();
    const manualCodeHash = sha256Hex(normalizeManualCode(manualCode));
    const ttl = settings.qr_ttl_seconds || 20;
    const expiresAt = new Date(now.getTime() + ttl * 1000).toISOString();
    const tokenId = crypto.randomUUID();

    store.issueQrToken(
      auth.device.id,
      {
        id: tokenId,
        token_hash: tokenHash,
        manual_code_hash: manualCodeHash,
        kiosk_device_id: auth.device.id,
        issued_at: nowIso,
        expires_at: expiresAt,
        consumed_at: null,
        consumed_by: null,
        consumed_action: null,
        status: "active",
      },
      nowIso,
    );

    res.json({
      ok: true,
      token: rawToken,
      manual_code: manualCode,
      token_id: tokenId,
      issued_at: nowIso,
      expires_at: expiresAt,
      ttl_seconds: ttl,
      company_name: settings.company_name,
      branch_name: auth.device.branch_name,
      device_name: auth.device.device_name,
      is_local_demo: process.env.NODE_ENV !== "production",
      schedule_status: "open",
      window_cutoff_time: schedule.window_cutoff_time,
    });
  });

  app.post("/api/kiosk/token-status", requireAuth, async (req: AuthenticatedRequest, res) => {
    const ipHash = getIpHash(req);
    const auth = await verifyKioskAuth(req, ipHash);
    if (!auth.ok) {
      res.status(auth.status).json({ ok: false, error: auth.error });
      return;
    }

    const settings = store.getSettings();
    const now = new Date();
    const schedule = evaluateQrCaptureSchedule(settings, now);
    const tokenId = typeof req.body?.token_id === "string" ? req.body.token_id.trim() : "";
    const tokenRow = store.getQrTokenForKiosk(tokenId, auth.device.id);
    if (!tokenRow) {
      res.status(404).json({ ok: false, error: "TOKEN_NOT_FOUND" });
      return;
    }

    if (!schedule.open && tokenRow.status === "active") {
      tokenRow.status = "revoked";
      store.updateQrTokenStatus(tokenRow.id, "revoked");
    } else if (tokenRow.status === "active" && Date.parse(tokenRow.expires_at) <= now.getTime()) {
      tokenRow.status = "expired";
      store.updateQrTokenStatus(tokenRow.id, "expired");
    }

    const prevSeenMs = auth.device.last_seen_at ? Date.parse(auth.device.last_seen_at) : 0;
    if (!prevSeenMs || now.getTime() - prevSeenMs >= 30_000) {
      store.touchKioskLastSeen(auth.device.id, now.toISOString());
    }

    res.json({
      ok: true,
      status: tokenRow.status,
      consumed_action: tokenRow.consumed_action,
      expires_at: tokenRow.expires_at,
      consumed_at: tokenRow.consumed_at,
      server_now: now.toISOString(),
      schedule_status: schedule.open ? "open" : "closed",
      next_reappear_time: schedule.next_reappear_time,
    });
  });

  app.get("/api/attendance/me", requireAuth, (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    const settings = store.getSettings();
    const todayDate = getDateInTimezone(new Date(), settings.timezone);
    const records = store.getEmployeeAttendanceHistory(user.id, 60);

    res.json({
      ok: true,
      today_date: todayDate,
      records,
      settings: {
        company_name: settings.company_name,
        branch_name: settings.branch_name,
        work_start_time: user.shift_start || settings.work_start_time,
        work_end_time: user.shift_end || settings.work_end_time,
        late_grace_minutes: settings.late_grace_minutes,
        enforce_geofence: settings.enforce_geofence,
      },
    });
  });

  // Employee Check-In & Check-Out QR Scan (single-row atomic SQLite transaction, zero full-DB rewrite)
  app.post("/api/attendance/scan", requireAuth, async (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    const ipHash = getIpHash(req);

    if (user.role !== "employee" || !user.is_active) {
      store.addSecurityLog(user.id, "check_in_rejected", "ACCOUNT_UNAVAILABLE", ipHash);
      res.status(403).json({ ok: false, error: "ACCOUNT_UNAVAILABLE" });
      return;
    }

    const userLimit = await checkDistributedRateLimit(`emp-scan:${user.id}`, 10, 60_000, 120_000);
    if (!userLimit.allowed) {
      if (userLimit.unavailable) {
        res.status(503).json({ ok: false, error: "RATE_LIMIT_UNAVAILABLE" });
        return;
      }
      res.status(429).json({
        ok: false,
        error: "RATE_LIMITED",
        retry_after_seconds: userLimit.retryAfterSeconds,
      });
      return;
    }

    const ipLimit = await checkDistributedRateLimit(`ip-scan:${ipHash}`, 40, 60_000, 120_000);
    if (!ipLimit.allowed) {
      if (ipLimit.unavailable) {
        res.status(503).json({ ok: false, error: "RATE_LIMIT_UNAVAILABLE" });
        return;
      }
      res.status(429).json({
        ok: false,
        error: "RATE_LIMITED",
        retry_after_seconds: ipLimit.retryAfterSeconds,
      });
      return;
    }

    const settings = store.getSettings();
    if (!settings.is_enabled) {
      store.addSecurityLog(user.id, "check_in_rejected", "SERVICE_DISABLED", ipHash);
      res.status(400).json({ ok: false, error: "SERVICE_DISABLED" });
      return;
    }

    const qrSchedule = evaluateQrCaptureSchedule(settings, new Date());
    if (!qrSchedule.open) {
      store.addSecurityLog(user.id, "check_in_rejected", "QR_WINDOW_CLOSED", ipHash, {
        next_reappear_time: qrSchedule.next_reappear_time,
      });
      res.status(403).json({
        ok: false,
        error: "QR_WINDOW_CLOSED",
        next_reappear_time: qrSchedule.next_reappear_time,
      });
      return;
    }

    const rawToken = typeof req.body?.qr_token === "string" ? req.body.qr_token.trim() : "";
    const idempotencyKey =
      typeof req.body?.idempotency_key === "string"
        ? req.body.idempotency_key.trim().slice(0, 128)
        : null;
    const requestedAction =
      req.body?.action === "check_in" || req.body?.action === "check_out"
        ? req.body.action
        : "auto";

    if (rawToken.length < 8 || rawToken.length > 512) {
      res.status(400).json({ ok: false, error: "QR_INVALID" });
      return;
    }

    // Deduplicate identical idempotency key for same employee
    if (idempotencyKey && store.hasAttendanceIdempotencyKey(user.id, idempotencyKey)) {
      res.status(409).json({ ok: false, error: "QR_INVALID" });
      return;
    }

    const tokenHash = sha256Hex(rawToken);
    const normalizedManual = normalizeManualCode(rawToken);
    const manualCodeHash =
      normalizedManual.length === 8 && /^[A-Z0-9]{8}$/.test(normalizedManual)
        ? sha256Hex(normalizedManual)
        : null;

    const tokenLookup = store.findQrTokenForScan(tokenHash, manualCodeHash);
    if (!tokenLookup) {
      store.addSecurityLog(user.id, "check_in_rejected", "QR_UNKNOWN", ipHash, {
        attempted_manual: Boolean(manualCodeHash),
      });
      res.status(400).json({ ok: false, error: "QR_INVALID" });
      return;
    }

    const { token: tokenRow, entryMethod } = tokenLookup;
    const kiosk = store.getKioskById(tokenRow.kiosk_device_id);
    if (!kiosk || !kiosk.is_active) {
      store.addSecurityLog(user.id, "check_in_rejected", "KIOSK_INACTIVE", ipHash);
      res.status(400).json({ ok: false, error: "QR_INVALID" });
      return;
    }

    const now = new Date();
    const nowIso = now.toISOString();

    if (tokenRow.status !== "active") {
      store.addSecurityLog(
        user.id,
        "check_in_rejected",
        `QR_NOT_ACTIVE_${tokenRow.status.toUpperCase()}`,
        ipHash,
      );
      res.status(400).json({ ok: false, error: "QR_INVALID" });
      return;
    }

    if (Date.parse(tokenRow.expires_at) <= now.getTime()) {
      store.updateQrTokenStatus(tokenRow.id, "expired");
      store.addSecurityLog(user.id, "check_in_rejected", "QR_EXPIRED", ipHash);
      res.status(400).json({ ok: false, error: "QR_EXPIRED" });
      return;
    }

    const lat = req.body?.latitude;
    const lon = req.body?.longitude;
    const acc = req.body?.accuracy;
    let distanceM: number | null = null;

    const hasCoords = lat !== null && lat !== undefined && lon !== null && lon !== undefined;
    const hasValidCoords =
      typeof lat === "number" &&
      typeof lon === "number" &&
      typeof acc === "number" &&
      Number.isFinite(lat) &&
      Number.isFinite(lon) &&
      Number.isFinite(acc) &&
      lat >= -90 &&
      lat <= 90 &&
      lon >= -180 &&
      lon <= 180 &&
      acc > 0;

    if (hasCoords && !hasValidCoords) {
      store.addSecurityLog(user.id, "check_in_rejected", "GPS_INVALID_COORDS", ipHash);
      res.status(400).json({ ok: false, error: "LOCATION_INVALID" });
      return;
    }

    if (hasValidCoords) {
      if (!validateGpsTimestamp(req.body?.client_captured_at)) {
        store.addSecurityLog(user.id, "check_in_rejected", "GPS_STALE", ipHash);
        res.status(400).json({ ok: false, error: "GPS_STALE" });
        return;
      }
      distanceM = Math.round(haversineMeters(lat, lon, settings.latitude, settings.longitude));
    }

    if (settings.enforce_geofence) {
      if (!hasValidCoords) {
        store.addSecurityLog(user.id, "check_in_rejected", "GPS_REQUIRED", ipHash);
        res.status(400).json({ ok: false, error: "LOCATION_INVALID" });
        return;
      }
      if (acc > settings.max_gps_accuracy_m) {
        store.addSecurityLog(user.id, "check_in_rejected", "GPS_POOR_ACCURACY", ipHash, {
          accuracy_m: acc,
        });
        res.status(400).json({ ok: false, error: "GPS_POOR_ACCURACY" });
        return;
      }
      if ((distanceM ?? 0) > settings.allowed_radius_m) {
        store.addSecurityLog(user.id, "check_in_rejected", "OUTSIDE_OFFICE_RADIUS", ipHash, {
          distance_m: distanceM,
        });
        res.status(400).json({ ok: false, error: "OUTSIDE_CAMPUS" });
        return;
      }
    }

    const todayDate = getDateInTimezone(now, settings.timezone);
    const existingRecord = store.getAttendanceByEmployeeAndDate(user.id, todayDate);

    let resolvedAction: "check_in" | "check_out";
    if (!existingRecord) {
      if (requestedAction === "check_out") {
        res.status(400).json({ ok: false, error: "NOT_CHECKED_IN_YET" });
        return;
      }
      resolvedAction = "check_in";
    } else if (existingRecord.checked_in_at && !existingRecord.checked_out_at) {
      if (requestedAction === "check_in") {
        res.status(400).json({ ok: false, error: "ALREADY_CHECKED_IN" });
        return;
      }
      resolvedAction = "check_out";
    } else {
      res.status(400).json({ ok: false, error: "ALREADY_COMPLETED_TODAY" });
      return;
    }

    if (resolvedAction === "check_in") {
      // Anomaly check: another employee checked in from same IP+UA within last 120s
      const uaHash = getUaHash(req);
      const anomalyCutoffIso = new Date(now.getTime() - 120_000).toISOString();
      const recentSameDevice = store.findRecentCheckInAnomaly(
        user.id,
        ipHash,
        uaHash,
        anomalyCutoffIso,
      );
      let anomalyNote: string | null = null;
      if (recentSameDevice) {
        anomalyNote = "تنبيه مراجعة: تسجيل من نفس الجهاز/الشبكة لموظف آخر خلال دقيقتين";
        emitSecurityAlert("high", "attendance_anomaly_detected", req.requestId ?? null, ipHash, {
          employee_id: user.id,
          other_employee_id: recentSameDevice.user_id,
          entry_method: entryMethod,
        });
      }

      const shiftStart = user.shift_start || settings.work_start_time || "09:00";
      const shiftStartMins = parseHhMmToMinutes(shiftStart);
      const currentMins = getMinutesOfDayInTimezone(now, settings.timezone);
      const grace = settings.late_grace_minutes ?? 15;
      const lateMinutes = currentMins > shiftStartMins + grace ? currentMins - shiftStartMins : 0;
      const status: AttendanceStatus = lateMinutes > 0 ? "late" : "present";

      const newRecord: AttendanceRecord = {
        id: `att-${crypto.randomUUID()}`,
        employee_id: user.id,
        attendance_date: todayDate,
        checked_in_at: nowIso,
        checked_out_at: null,
        worked_minutes: null,
        late_minutes: lateMinutes,
        status,
        qr_token_id: tokenRow.id,
        idempotency_key: idempotencyKey,
        distance_m: distanceM,
        notes: anomalyNote,
        created_at: nowIso,
      };

      try {
        store.commitCheckInScan({
          tokenId: tokenRow.id,
          employeeId: user.id,
          nowIso,
          record: newRecord,
          securityLog: {
            id: `log-${crypto.randomUUID()}`,
            user_id: user.id,
            event_type: "check_in_succeeded",
            reason_code: lateMinutes > 0 ? "LATE_ARRIVAL" : "OK",
            ip_hash: ipHash,
            created_at: nowIso,
            metadata: {
              attendance_date: todayDate,
              late_minutes: lateMinutes,
              distance_m: distanceM,
              entry_method: entryMethod,
              ua_hash: uaHash,
            },
          },
        });
      } catch (err) {
        if (err instanceof Error && err.message === "QR_ALREADY_CONSUMED") {
          res.status(400).json({ ok: false, error: "QR_INVALID" });
          return;
        }
        throw err;
      }

      res.json({
        ok: true,
        action: "check_in",
        attendance_date: todayDate,
        checked_in_at: nowIso,
        checked_out_at: null,
        worked_minutes: null,
        late_minutes: lateMinutes,
        status,
        distance_m: distanceM,
      });
      return;
    }

    const checkInMs = existingRecord!.checked_in_at
      ? Date.parse(existingRecord!.checked_in_at)
      : now.getTime();
    const workedMinutes = Math.max(1, Math.round((now.getTime() - checkInMs) / 60000));

    try {
      store.commitCheckOutScan({
        tokenId: tokenRow.id,
        employeeId: user.id,
        recordId: existingRecord!.id,
        nowIso,
        workedMinutes,
        securityLog: {
          id: `log-${crypto.randomUUID()}`,
          user_id: user.id,
          event_type: "check_out_succeeded",
          reason_code: "OK",
          ip_hash: ipHash,
          created_at: nowIso,
          metadata: {
            attendance_date: todayDate,
            worked_minutes: workedMinutes,
            distance_m: distanceM,
            entry_method: entryMethod,
          },
        },
      });
    } catch (err) {
      if (err instanceof Error && err.message === "QR_ALREADY_CONSUMED") {
        res.status(400).json({ ok: false, error: "QR_INVALID" });
        return;
      }
      throw err;
    }

    res.json({
      ok: true,
      action: "check_out",
      attendance_date: todayDate,
      checked_in_at: existingRecord!.checked_in_at,
      checked_out_at: nowIso,
      worked_minutes: workedMinutes,
      late_minutes: existingRecord!.late_minutes,
      status: existingRecord!.status,
      distance_m: distanceM,
    });
  });

  // Require authenticated application-layer payload channel for ALL /api/hr/* Admin routes
  app.use("/api/hr", requireEncryptedChannel);

  const pendingTotpEnrollments = new Map<string, { secret: string; expiresAtMs: number }>();

  // HR Admin Step-Up Verification (password + RFC 6238 TOTP MFA when enabled)
  const adminStepUpSchema = z
    .object({
      password: z.string().min(1).max(128),
      totp_code: z.string().trim().max(16).optional(),
    })
    .strict();

  app.post("/api/hr/security/step-up", requireAuth, async (req: AuthenticatedRequest, res) => {
    const user = req.authUser;
    if (!user || user.role !== "admin" || !user.is_active) {
      res.status(403).json({ ok: false, error: "FORBIDDEN" });
      return;
    }

    const ipHash = getIpHash(req);
    const rateKey = `admin-stepup:${user.id}:${ipHash}`;
    const rate = await checkDistributedRateLimit(rateKey, 5, 300_000, 900_000);
    if (!rate.allowed) {
      store.addSecurityLog(user.id, "admin_step_up_rate_limited", "RATE_LIMITED", ipHash);
      emitSecurityAlert("critical", "admin_step_up_rate_limited", req.requestId ?? null, ipHash, {
        admin_id: user.id,
      });
      res.status(429).json({
        ok: false,
        error: "RATE_LIMITED",
        retry_after_seconds: rate.retryAfterSeconds,
      });
      return;
    }

    const parsed = adminStepUpSchema.safeParse(req.body);
    if (!parsed.success || !verifyPassword(parsed.data.password, user.password_salt, user.password_hash)) {
      store.addSecurityLog(user.id, "admin_step_up_failed", "INVALID_CREDENTIALS", ipHash);
      emitSecurityAlert("high", "admin_step_up_failed", req.requestId ?? null, ipHash, {
        admin_id: user.id,
      });
      res.status(401).json({ ok: false, error: "INVALID_CREDENTIALS" });
      return;
    }

    let grantedAal: "aal1" | "aal2" = "aal1";
    if (user.mfa_enabled && user.mfa_secret_enc) {
      const submittedTotp = (parsed.data.totp_code ?? "").trim();
      if (!submittedTotp) {
        res.status(401).json({ ok: false, error: "MFA_CODE_REQUIRED", mfa_enabled: true });
        return;
      }
      const secretBase32 = store.decryptUserMfaSecret(user);
      if (!secretBase32) {
        res.status(500).json({ ok: false, error: "MFA_STATE_INVALID" });
        return;
      }
      const totpRes = verifyTotpCode(secretBase32, submittedTotp, user.last_used_totp_step);
      if (!totpRes.valid || totpRes.matchedStep === undefined) {
        store.addSecurityLog(user.id, "admin_mfa_failed", "INVALID_MFA_CODE", ipHash);
        emitSecurityAlert("high", "admin_mfa_failed", req.requestId ?? null, ipHash, {
          admin_id: user.id,
        });
        res.status(401).json({ ok: false, error: "INVALID_MFA_CODE", mfa_enabled: true });
        return;
      }
      store.updateUserLastTotpStep(user.id, totpRes.matchedStep);
      grantedAal = "aal2";
    }

    resetRateLimit(rateKey);
    if (req.authSession) {
      req.authSession.aal = grantedAal;
      store.updateSessionAal(req.authSession.jti, grantedAal);
    }
    const stepUp = signAdminStepUpToken(user, getUaHash(req), grantedAal);
    store.addSecurityLog(user.id, "admin_step_up_verified", grantedAal.toUpperCase(), ipHash);

    res.json({
      ok: true,
      step_up_token: stepUp.token,
      expires_at: stepUp.expiresAt,
      aal: grantedAal,
      mfa_enabled: Boolean(user.mfa_enabled),
      mfa_setup_required: REQUIRE_ADMIN_MFA && !user.mfa_enabled,
    });
  });

  // TOTP MFA Enrollment & Activation for Admin accounts
  app.get(
    "/api/hr/security/mfa/status",
    requireAuth,
    requireAdminStepUpForMfaSetup,
    (req: AuthenticatedRequest, res) => {
      const user = req.authUser!;
      res.json({
        ok: true,
        mfa_enabled: Boolean(user.mfa_enabled),
        mfa_required: REQUIRE_ADMIN_MFA,
        aal: req.authSession?.aal ?? "aal1",
      });
    },
  );

  app.post(
    "/api/hr/security/mfa/enroll",
    requireAuth,
    requireAdminStepUpForMfaSetup,
    (req: AuthenticatedRequest, res) => {
      const user = req.authUser!;
      const secret = generateTotpSecret();
      pendingTotpEnrollments.set(user.id, {
        secret,
        expiresAtMs: Date.now() + 10 * 60_000,
      });
      const label = encodeURIComponent(`InSight:${user.email}`);
      const otpauthUri = `otpauth://totp/${label}?secret=${secret}&issuer=InSight&algorithm=SHA1&digits=6&period=30`;
      store.addSecurityLog(user.id, "admin_mfa_enroll_started", "OK", getIpHash(req));

      res.json({
        ok: true,
        secret,
        otpauth_uri: otpauthUri,
      });
    },
  );

  const activateMfaSchema = z
    .object({
      totp_code: z.string().trim().regex(/^\d{6}$/),
    })
    .strict();

  app.post(
    "/api/hr/security/mfa/activate",
    requireAuth,
    requireAdminStepUpForMfaSetup,
    (req: AuthenticatedRequest, res) => {
      const user = req.authUser!;
      const ipHash = getIpHash(req);
      const parsed = activateMfaSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ ok: false, error: "INVALID_MFA_CODE" });
        return;
      }
      const pending = pendingTotpEnrollments.get(user.id);
      if (!pending || pending.expiresAtMs <= Date.now()) {
        pendingTotpEnrollments.delete(user.id);
        res.status(400).json({ ok: false, error: "MFA_ENROLLMENT_EXPIRED" });
        return;
      }

      const verified = verifyTotpCode(pending.secret, parsed.data.totp_code);
      if (!verified.valid || verified.matchedStep === undefined) {
        res.status(401).json({ ok: false, error: "INVALID_MFA_CODE" });
        return;
      }

      pendingTotpEnrollments.delete(user.id);
      store.activateUserMfa(
        user.id,
        pending.secret,
        verified.matchedStep,
        new Date().toISOString(),
      );
      if (req.authSession) {
        req.authSession.aal = "aal2";
        store.updateSessionAal(req.authSession.jti, "aal2");
      }

      const upgradedStepUp = signAdminStepUpToken(user, getUaHash(req), "aal2");
      store.addSecurityLog(user.id, "admin_mfa_activated", "AAL2_ENABLED", ipHash);

      res.json({
        ok: true,
        mfa_enabled: true,
        aal: "aal2",
        step_up_token: upgradedStepUp.token,
        expires_at: upgradedStepUp.expiresAt,
      });
    },
  );

  // HR Admin Overview (requires E2EE channel + Step-Up verification + AAL2 + RBAC permission scoping)
  app.get(
    "/api/hr/overview",
    requireAuth,
    requireAdminWithStepUp,
    (req: AuthenticatedRequest, res) => {
      const rolesMap = store.getRbacRoles();
      const currentPerms = resolveUserPermissions(req.authUser!, rolesMap);
      if (currentPerms.length === 0) {
        res.status(403).json({ ok: false, error: "PERMISSION_DENIED" });
        return;
      }

      const canViewRecords = currentPerms.includes("view_records");
      const canManageEmployees = currentPerms.includes("manage_employees");
      const canManageKiosks = currentPerms.includes("manage_kiosks");
      const canManageSettings = currentPerms.includes("manage_settings");
      const canManageSecurity = currentPerms.includes("manage_security");
      const canManagePermissions = currentPerms.includes("manage_permissions");

      const settings = store.getSettings();
      const todayDate = getDateInTimezone(new Date(), settings.timezone);
      const stats = store.getTodayStats(todayDate);

      const enrichedRecords = canViewRecords ? store.listEnrichedAttendanceRecords(500) : [];
      const logs = canManageSecurity ? store.listRecentSecurityLogs(40) : [];
      const activeSessions = canManageSecurity
        ? store.listActiveSessionsWithUser(new Date().toISOString(), req.authJti)
        : [];

      const employees =
        canManageEmployees || canViewRecords || currentPerms.includes("manage_excuses")
          ? store.listUsersByRole("employee").map((u) => toPublicProfile(u, rolesMap))
          : [];

      const staffUsers = canManagePermissions
        ? store.listStaffUsers().map((u) => toPublicProfile(u, rolesMap))
        : undefined;

      res.json({
        ok: true,
        today_date: todayDate,
        current_permissions: currentPerms,
        stats,
        employees,
        staff_users: staffUsers,
        records: enrichedRecords,
        settings,
        security_policy:
          canManageSecurity || canManageSettings ? store.getSecurityPolicy() : undefined,
        rbac_roles: canManagePermissions ? rolesMap : undefined,
        kiosk_devices:
          canManageKiosks || canManageSettings || canManageSecurity
            ? store.listKiosksWithEmail()
            : [],
        security_logs: logs,
        security_alerts: canManageSecurity ? store.listRecentSecurityAlerts(25) : [],
        active_sessions: activeSessions,
        mfa_status: {
          enabled: Boolean(req.authUser!.mfa_enabled),
          required: REQUIRE_ADMIN_MFA,
          aal: req.authSession?.aal ?? "aal1",
        },
      });
    },
  );

  // HR Admin: Create Employee (Zod validated + E2EE + Step-Up + strict password policy)
  const createEmployeeSchema = z
    .object({
      full_name: z.string().trim().min(2).max(160),
      email: z.string().trim().email().max(254),
      password: z.string().min(8).max(128),
      employee_number: z.string().trim().min(1).max(64),
      department: z.string().trim().max(120).optional().default("عام"),
      job_title: z.string().trim().max(120).optional().default("موظف"),
      shift_start: z.string().trim().regex(/^\d{2}:\d{2}$/).optional().default("09:00"),
      shift_end: z.string().trim().regex(/^\d{2}:\d{2}$/).optional().default("17:00"),
    })
    .strict();

  app.post(
    "/api/hr/employees",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_employees"),
    (req: AuthenticatedRequest, res) => {
      const parsed = createEmployeeSchema.safeParse(req.body);
      if (!parsed.success) {
        const pwdIssue = parsed.error.issues.some((i) => i.path[0] === "password");
        res
          .status(400)
          .json({ ok: false, error: pwdIssue ? "WEAK_PASSWORD" : "INVALID_EMPLOYEE_INPUT" });
        return;
      }

      const fullName = parsed.data.full_name;
      const email = parsed.data.email.toLowerCase();
      const password = parsed.data.password;
      const employeeNumber = parsed.data.employee_number;

      if (!isStrongPassword(password)) {
        res.status(400).json({ ok: false, error: "WEAK_PASSWORD" });
        return;
      }

      if (store.getUserByEmail(email)) {
        res.status(409).json({ ok: false, error: "EMAIL_ALREADY_EXISTS" });
        return;
      }

      if (store.getUserByEmployeeNumber(employeeNumber)) {
        res.status(409).json({ ok: false, error: "EMPLOYEE_NUMBER_EXISTS" });
        return;
      }

      const nowIso = new Date().toISOString();
      const salt = crypto.randomBytes(16).toString("hex");
      const newEmployee: StoredUser = {
        id: `usr-${crypto.randomUUID()}`,
        email,
        password_salt: salt,
        password_hash: hashPassword(password, salt),
        token_version: 1,
        full_name: fullName,
        employee_number: employeeNumber,
        department: parsed.data.department || "عام",
        job_title: parsed.data.job_title || "موظف",
        shift_start: parsed.data.shift_start || "09:00",
        shift_end: parsed.data.shift_end || "17:00",
        role: "employee",
        is_active: true,
        created_at: nowIso,
        updated_at: nowIso,
      };

      store.createUser(newEmployee);
      store.addSecurityLog(req.authUser!.id, "employee_created", "HR_PROVISIONED", getIpHash(req), {
        employee_number: employeeNumber,
      });

      res.status(201).json({ ok: true, employee: toPublicProfile(newEmployee) });
    },
  );

  // HR Admin: Update Employee (suspending immediately revokes active tokens)
  const updateEmployeeSchema = z
    .object({
      full_name: z.string().trim().min(2).max(160).optional(),
      department: z.string().trim().max(120).optional(),
      job_title: z.string().trim().max(120).optional(),
      shift_start: z.string().trim().regex(/^\d{2}:\d{2}$/).optional(),
      shift_end: z.string().trim().regex(/^\d{2}:\d{2}$/).optional(),
      is_active: z.boolean().optional(),
    })
    .strict();

  app.patch(
    "/api/hr/employees/:id",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_employees"),
    (req: AuthenticatedRequest, res) => {
      const parsed = updateEmployeeSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ ok: false, error: "INVALID_EMPLOYEE_INPUT" });
        return;
      }

      const updated = store.updateEmployee(
        String(req.params.id),
        parsed.data,
        new Date().toISOString(),
      );
      if (!updated) {
        res.status(404).json({ ok: false, error: "EMPLOYEE_NOT_FOUND" });
        return;
      }

      store.addSecurityLog(req.authUser!.id, "employee_updated", "HR_UPDATED", getIpHash(req), {
        target_employee_id: updated.id,
        is_active: updated.is_active,
      });

      res.json({ ok: true, employee: toPublicProfile(updated) });
    },
  );

  // HR Admin: Log Excused Absence
  const excuseSchema = z
    .object({
      employee_id: z.string().trim().min(1).max(128),
      attendance_date: z.string().trim().regex(/^\d{4}-\d{2}-\d{2}$/),
      notes: z.string().trim().max(300).optional().default("عذر رسمي معتمد"),
    })
    .strict();

  app.post(
    "/api/hr/attendance/excuse",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_excuses"),
    (req: AuthenticatedRequest, res) => {
      const parsed = excuseSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ ok: false, error: "INVALID_EXCUSE_INPUT" });
        return;
      }

      const { employee_id: employeeId, attendance_date: attendanceDate, notes } = parsed.data;
      const emp = store.getUserById(employeeId);
      if (!emp || emp.role !== "employee") {
        res.status(404).json({ ok: false, error: "EMPLOYEE_NOT_FOUND" });
        return;
      }

      store.upsertExcuseRecord(employeeId, attendanceDate, notes, new Date().toISOString());
      store.addSecurityLog(req.authUser!.id, "attendance_excused", "HR_EXCUSE_LOGGED", getIpHash(req), {
        employee_number: emp.employee_number,
        attendance_date: attendanceDate,
      });

      res.json({ ok: true });
    },
  );

  // HR Admin: Update Company Settings (including QR capture cutoff & reappear windows)
  const updateSettingsSchema = z
    .object({
      id: z.string().optional(),
      company_name: z.string().trim().min(2).max(160).optional(),
      branch_name: z.string().trim().min(2).max(160).optional(),
      latitude: z.number().min(-90).max(90).optional(),
      longitude: z.number().min(-180).max(180).optional(),
      allowed_radius_m: z.number().min(20).max(10000).optional(),
      max_gps_accuracy_m: z.number().min(10).max(1000).optional(),
      qr_ttl_seconds: z.number().min(10).max(120).optional(),
      timezone: z.string().trim().max(64).optional(),
      work_start_time: z.string().trim().regex(/^\d{2}:\d{2}$/).optional(),
      work_end_time: z.string().trim().regex(/^\d{2}:\d{2}$/).optional(),
      late_grace_minutes: z.number().min(0).max(120).optional(),
      enforce_geofence: z.boolean().optional(),
      is_enabled: z.boolean().optional(),
      qr_schedule_enabled: z.boolean().optional(),
      qr_window_start: z.string().trim().regex(/^\d{2}:\d{2}$/).optional(),
      qr_cutoff_time: z.string().trim().regex(/^\d{2}:\d{2}$/).optional(),
      qr_reappear_time: z.string().trim().regex(/^\d{2}:\d{2}$/).optional(),
      qr_window_end: z.string().trim().regex(/^\d{2}:\d{2}$/).optional(),
      updated_at: z.string().optional(),
    })
    .strict();

  app.put(
    "/api/hr/settings",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_settings"),
    (req: AuthenticatedRequest, res) => {
      const parsed = updateSettingsSchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        res.status(400).json({ ok: false, error: "INVALID_SETTINGS_INPUT" });
        return;
      }

      const body = parsed.data;
      const current = store.getSettings();
      const next: CompanySettings = { ...current };

      if (body.timezone !== undefined) {
        try {
          new Intl.DateTimeFormat("en-GB", { timeZone: body.timezone }).format(new Date());
          next.timezone = body.timezone;
        } catch {
          res.status(400).json({ ok: false, error: "INVALID_TIMEZONE" });
          return;
        }
      }
      if (body.company_name !== undefined) next.company_name = body.company_name;
      if (body.branch_name !== undefined) next.branch_name = body.branch_name;
      if (body.latitude !== undefined) next.latitude = body.latitude;
      if (body.longitude !== undefined) next.longitude = body.longitude;
      if (body.allowed_radius_m !== undefined) {
        next.allowed_radius_m = Math.round(body.allowed_radius_m);
      }
      if (body.max_gps_accuracy_m !== undefined) {
        next.max_gps_accuracy_m = Math.round(body.max_gps_accuracy_m);
      }
      if (body.qr_ttl_seconds !== undefined) {
        next.qr_ttl_seconds = Math.round(body.qr_ttl_seconds);
      }
      if (body.work_start_time !== undefined) next.work_start_time = body.work_start_time;
      if (body.work_end_time !== undefined) next.work_end_time = body.work_end_time;
      if (body.late_grace_minutes !== undefined) {
        next.late_grace_minutes = Math.round(body.late_grace_minutes);
      }
      if (body.enforce_geofence !== undefined) next.enforce_geofence = body.enforce_geofence;
      if (body.is_enabled !== undefined) next.is_enabled = body.is_enabled;
      if (body.qr_schedule_enabled !== undefined) {
        next.qr_schedule_enabled = body.qr_schedule_enabled;
      }
      if (body.qr_window_start !== undefined) next.qr_window_start = body.qr_window_start;
      if (body.qr_cutoff_time !== undefined) next.qr_cutoff_time = body.qr_cutoff_time;
      if (body.qr_reappear_time !== undefined) next.qr_reappear_time = body.qr_reappear_time;
      if (body.qr_window_end !== undefined) next.qr_window_end = body.qr_window_end;

      const startM = parseHhMmToMinutes(next.qr_window_start);
      const cutM = parseHhMmToMinutes(next.qr_cutoff_time);
      const reapM = parseHhMmToMinutes(next.qr_reappear_time);
      const endM = parseHhMmToMinutes(next.qr_window_end);
      if (next.qr_schedule_enabled && !(startM <= cutM && cutM <= reapM && reapM <= endM)) {
        res.status(400).json({ ok: false, error: "INVALID_QR_SCHEDULE_ORDER" });
        return;
      }

      next.updated_at = new Date().toISOString();
      store.updateSettings(next);

      store.addSecurityLog(req.authUser!.id, "company_settings_updated", "HR_UPDATED", getIpHash(req), {
        enforce_geofence: next.enforce_geofence,
        is_enabled: next.is_enabled,
        qr_schedule_enabled: next.qr_schedule_enabled,
      });

      res.json({ ok: true, settings: next });
    },
  );

  // HR Admin: Create / Authorize an Additional Reception Kiosk Terminal
  const createKioskSchema = z
    .object({
      device_name: z.string().trim().min(2).max(160),
      branch_name: z.string().trim().min(2).max(160),
      email: z.string().trim().email().max(254),
      password: z.string().min(8).max(128),
      device_secret: z.string().trim().min(8).max(128),
    })
    .strict();

  app.post(
    "/api/hr/kiosks",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_kiosks"),
    (req: AuthenticatedRequest, res) => {
      const parsed = createKioskSchema.safeParse(req.body);
      if (!parsed.success) {
        const pwdIssue = parsed.error.issues.some((i) => i.path[0] === "password");
        const secIssue = parsed.error.issues.some((i) => i.path[0] === "device_secret");
        res.status(400).json({
          ok: false,
          error: pwdIssue ? "WEAK_PASSWORD" : secIssue ? "WEAK_SECRET" : "INVALID_KIOSK_INPUT",
        });
        return;
      }

      const email = parsed.data.email.toLowerCase();
      if (!isStrongPassword(parsed.data.password)) {
        res.status(400).json({ ok: false, error: "WEAK_PASSWORD" });
        return;
      }
      if (store.getUserByEmail(email)) {
        res.status(409).json({ ok: false, error: "EMAIL_ALREADY_EXISTS" });
        return;
      }

      const nowIso = new Date().toISOString();
      const salt = crypto.randomBytes(16).toString("hex");
      const kioskUser: StoredUser = {
        id: `usr-kiosk-${crypto.randomUUID()}`,
        email,
        password_salt: salt,
        password_hash: hashPassword(parsed.data.password, salt),
        token_version: 1,
        full_name: parsed.data.device_name,
        employee_number: null,
        department: "الاستقبال",
        job_title: "جهاز عرض QR",
        shift_start: "00:00",
        shift_end: "23:59",
        role: "kiosk",
        is_active: true,
        created_at: nowIso,
        updated_at: nowIso,
      };
      const newDevice: KioskDevice = {
        id: `kiosk-${crypto.randomUUID().slice(0, 8)}`,
        device_name: parsed.data.device_name,
        branch_name: parsed.data.branch_name,
        auth_user_id: kioskUser.id,
        secret_hash: sha256Hex(`${runtimeSecrets.kiosk_salt}:${parsed.data.device_secret}`),
        is_active: true,
        last_seen_at: null,
        revoked_before: null,
        created_at: nowIso,
      };

      store.createKioskWithUser(kioskUser, newDevice);
      store.addSecurityLog(req.authUser!.id, "kiosk_device_created", "ADMIN_AUTHORIZED", getIpHash(req), {
        device_id: newDevice.id,
        branch_name: newDevice.branch_name,
      });

      res.status(201).json({
        ok: true,
        device: {
          id: newDevice.id,
          device_name: newDevice.device_name,
          branch_name: newDevice.branch_name,
          auth_email: kioskUser.email,
          is_active: newDevice.is_active,
          last_seen_at: newDevice.last_seen_at,
          revoked_before: newDevice.revoked_before,
          created_at: newDevice.created_at,
        },
      });
    },
  );

  // HR Admin: Enable / Suspend / Edit an Authorized Kiosk Device
  const updateKioskSchema = z
    .object({
      device_name: z.string().trim().min(2).max(160).optional(),
      branch_name: z.string().trim().min(2).max(160).optional(),
      is_active: z.boolean().optional(),
    })
    .strict();

  app.patch(
    "/api/hr/kiosks/:id",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_kiosks"),
    (req: AuthenticatedRequest, res) => {
      const parsed = updateKioskSchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        res.status(400).json({ ok: false, error: "INVALID_KIOSK_INPUT" });
        return;
      }

      const updated = store.updateKioskDevice(
        String(req.params.id),
        parsed.data,
        new Date().toISOString(),
      );
      if (!updated) {
        res.status(404).json({ ok: false, error: "KIOSK_NOT_FOUND" });
        return;
      }

      store.addSecurityLog(req.authUser!.id, "kiosk_device_updated", "ADMIN_UPDATED", getIpHash(req), {
        device_id: updated.id,
        is_active: updated.is_active,
      });

      res.json({ ok: true, device: updated });
    },
  );

  // HR Admin: Revoke Kiosk Session & optionally rotate secret
  const revokeKioskSchema = z
    .object({
      device_id: z.string().trim().min(1).max(128).optional().default("kiosk-hq-01"),
      new_secret: z.string().trim().max(128).optional(),
    })
    .strict();

  app.post(
    "/api/hr/kiosk/revoke",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_kiosks"),
    (req: AuthenticatedRequest, res) => {
      const parsed = revokeKioskSchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        res.status(400).json({ ok: false, error: "INVALID_KIOSK_INPUT" });
        return;
      }

      const deviceId = parsed.data.device_id;
      const newSecret = parsed.data.new_secret ?? "";
      if (newSecret.length > 0 && newSecret.length < 8) {
        res.status(400).json({ ok: false, error: "WEAK_SECRET" });
        return;
      }

      const nowIso = new Date().toISOString();
      const rotatedHash =
        newSecret.length >= 8
          ? sha256Hex(`${runtimeSecrets.kiosk_salt}:${newSecret}`)
          : undefined;
      const found = store.revokeKioskSession(deviceId, nowIso, rotatedHash);
      if (!found) {
        res.status(404).json({ ok: false, error: "KIOSK_NOT_FOUND" });
        return;
      }

      store.addSecurityLog(req.authUser!.id, "kiosk_session_revoked", "ADMIN_REVOKED", getIpHash(req), {
        device_id: deviceId,
        secret_rotated: newSecret.length >= 8,
      });

      res.json({ ok: true, revoked_before: nowIso });
    },
  );

  // HR Admin: Update Cloudflare Free WAF & Runtime Security Policy
  const updateSecurityPolicySchema = z
    .object({
      cloudflare_enabled: z.boolean().optional(),
      trust_cf_headers: z.boolean().optional(),
      allowed_countries: z
        .array(z.string().trim().regex(/^[A-Za-z]{2}$/))
        .max(50)
        .optional(),
      max_cf_threat_score: z.number().int().min(1).max(100).optional(),
      turnstile_enabled: z.boolean().optional(),
      turnstile_site_key: z.string().trim().max(160).optional(),
      strict_ip_binding: z.boolean().optional(),
      block_method_override: z.boolean().optional(),
      enforce_json_content_type: z.boolean().optional(),
    })
    .strict();

  app.put(
    "/api/hr/security/policy",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_security"),
    (req: AuthenticatedRequest, res) => {
      const parsed = updateSecurityPolicySchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        res.status(400).json({ ok: false, error: "INVALID_SECURITY_POLICY" });
        return;
      }

      const current = store.getSecurityPolicy();
      const d = parsed.data;
      const updated: SecurityPolicySettings = {
        cloudflare_enabled: d.cloudflare_enabled ?? current.cloudflare_enabled,
        trust_cf_headers: d.trust_cf_headers ?? current.trust_cf_headers,
        allowed_countries: d.allowed_countries
          ? d.allowed_countries.map((c) => c.toUpperCase())
          : current.allowed_countries,
        max_cf_threat_score: d.max_cf_threat_score ?? current.max_cf_threat_score,
        turnstile_enabled: d.turnstile_enabled ?? current.turnstile_enabled,
        turnstile_site_key: d.turnstile_site_key ?? current.turnstile_site_key,
        strict_ip_binding: d.strict_ip_binding ?? current.strict_ip_binding,
        block_method_override: d.block_method_override ?? current.block_method_override,
        enforce_json_content_type: d.enforce_json_content_type ?? current.enforce_json_content_type,
      };
      store.updateSecurityPolicy(updated);

      store.addSecurityLog(req.authUser!.id, "security_policy_updated", "ADMIN_UPDATED", getIpHash(req), {
        cloudflare_enabled: updated.cloudflare_enabled,
        turnstile_enabled: updated.turnstile_enabled,
        strict_ip_binding: updated.strict_ip_binding,
      });

      res.json({ ok: true, security_policy: updated });
    },
  );

  // HR Admin: DB-Persisted RBAC Role Permissions Update
  const updateRbacRoleSchema = z
    .object({
      permissions: z.array(z.enum(ALL_PERMISSION_KEYS as [PermissionKey, ...PermissionKey[]])).min(1).max(20),
    })
    .strict();

  app.put(
    "/api/hr/rbac/roles/:roleKey",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_permissions"),
    (req: AuthenticatedRequest, res) => {
      const roleKey = String(req.params.roleKey ?? "").trim();
      const rolesMap = store.getRbacRoles();
      if (!rolesMap[roleKey]) {
        res.status(404).json({ ok: false, error: "ROLE_NOT_FOUND" });
        return;
      }

      const parsed = updateRbacRoleSchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        res.status(400).json({ ok: false, error: "INVALID_PERMISSIONS_INPUT" });
        return;
      }

      const uniquePerms = Array.from(new Set(parsed.data.permissions));
      if (roleKey === "super_admin" && !uniquePerms.includes("manage_permissions")) {
        uniquePerms.push("manage_permissions");
      }
      const nextRoles = store.updateRbacRolePermissions(roleKey, uniquePerms) ?? rolesMap;

      store.addSecurityLog(req.authUser!.id, "rbac_role_updated", "ADMIN_UPDATED", getIpHash(req), {
        role_key: roleKey,
        permissions_count: uniquePerms.length,
      });

      res.json({ ok: true, rbac_roles: nextRoles });
    },
  );

  // HR Admin: Assign User Role / Custom Permissions (DB-Persisted RBAC)
  const assignUserRbacSchema = z
    .object({
      role: z.enum(["employee", "admin"]),
      admin_role_key: z.string().trim().min(1).max(64).nullable().optional(),
      permissions: z
        .array(z.enum(ALL_PERMISSION_KEYS as [PermissionKey, ...PermissionKey[]]))
        .max(20)
        .optional(),
    })
    .strict();

  app.put(
    "/api/hr/rbac/users/:userId",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_permissions"),
    (req: AuthenticatedRequest, res) => {
      const targetUser = store.getUserById(String(req.params.userId));
      if (!targetUser || targetUser.role === "kiosk") {
        res.status(404).json({ ok: false, error: "USER_NOT_FOUND" });
        return;
      }

      const parsed = assignUserRbacSchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        res.status(400).json({ ok: false, error: "INVALID_PERMISSIONS_INPUT" });
        return;
      }

      const rolesMap = store.getRbacRoles();
      const adminUsers = store.listUsersByRole("admin");
      const activeSuperAdmins = adminUsers.filter(
        (u) => u.is_active && resolveUserPermissions(u, rolesMap).includes("manage_permissions"),
      );
      if (
        targetUser.id === req.authUser!.id &&
        activeSuperAdmins.length <= 1 &&
        (parsed.data.role !== "admin" ||
          (parsed.data.permissions && !parsed.data.permissions.includes("manage_permissions")) ||
          (parsed.data.admin_role_key &&
            !(rolesMap[parsed.data.admin_role_key]?.permissions ?? []).includes("manage_permissions")))
      ) {
        res.status(400).json({ ok: false, error: "CANNOT_DEMOTE_LAST_SUPER_ADMIN" });
        return;
      }

      let nextAdminRoleKey: string | null = null;
      let nextPermissions: PermissionKey[] | undefined = undefined;
      if (parsed.data.role === "admin") {
        const chosenRole = parsed.data.admin_role_key || "attendance_supervisor";
        if (!rolesMap[chosenRole]) {
          res.status(400).json({ ok: false, error: "ROLE_NOT_FOUND" });
          return;
        }
        nextAdminRoleKey = chosenRole;
        nextPermissions =
          parsed.data.permissions && parsed.data.permissions.length > 0
            ? Array.from(new Set(parsed.data.permissions))
            : undefined;
      }

      const updatedUser = store.updateUserRbac(
        targetUser.id,
        parsed.data.role,
        nextAdminRoleKey,
        nextPermissions,
        new Date().toISOString(),
      );

      store.addSecurityLog(req.authUser!.id, "user_permissions_updated", "ADMIN_UPDATED", getIpHash(req), {
        target_user_id: targetUser.id,
        role: parsed.data.role,
        admin_role_key: nextAdminRoleKey,
      });

      res.json({ ok: true, user: toPublicProfile(updatedUser ?? targetUser, rolesMap) });
    },
  );

  // HR Admin: Revoke an individual active session by JTI
  app.delete(
    "/api/hr/security/sessions/:jti",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_security"),
    (req: AuthenticatedRequest, res) => {
      const targetJti = String(req.params.jti ?? "").trim();
      const target = store.getActiveSessionByJti(targetJti);
      if (!target) {
        res.status(404).json({ ok: false, error: "SESSION_NOT_FOUND" });
        return;
      }
      store.revokeSessionByJti(targetJti);
      store.addSecurityLog(req.authUser!.id, "session_revoked_by_admin", "ADMIN_REVOKED", getIpHash(req), {
        target_user_id: target.user_id,
      });
      res.json({ ok: true });
    },
  );

  // HR Admin: Emergency global session revocation (invalidates all employee & kiosk sessions)
  app.post(
    "/api/hr/security/revoke-all-sessions",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_security"),
    (req: AuthenticatedRequest, res) => {
      const nowIso = new Date().toISOString();
      const affected = store.emergencyLockdownOtherUsers(req.authUser!.id, nowIso);

      const ipHash = getIpHash(req);
      store.addSecurityLog(
        req.authUser!.id,
        "global_sessions_revoked",
        "ADMIN_EMERGENCY_LOCKDOWN",
        ipHash,
        { affected_accounts: affected },
      );
      emitSecurityAlert("critical", "global_sessions_revoked", req.requestId ?? null, ipHash, {
        admin_id: req.authUser!.id,
        affected_accounts: affected,
      });

      res.json({ ok: true, affected_accounts: affected });
    },
  );

  // HR Admin: Encrypted Isolated Backup Export (uses admin-supplied passphrase; NEVER exports .master.key)
  const backupSchema = z
    .object({
      passphrase: z.string().min(12).max(128),
    })
    .strict();

  app.post(
    "/api/hr/security/backup",
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("manage_security"),
    (req: AuthenticatedRequest, res) => {
      const parsed = backupSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ ok: false, error: "WEAK_BACKUP_PASSPHRASE" });
        return;
      }
      const salt = crypto.randomBytes(16);
      const derivedKey = crypto.pbkdf2Sync(parsed.data.passphrase, salt, 210_000, 32, "sha256");
      const backupPayload = store.exportBackupPayload();
      const sealedEnvelope = JSON.parse(encryptJsonPayload(JSON.stringify(backupPayload), derivedKey));
      store.addSecurityLog(req.authUser!.id, "encrypted_backup_exported", "OK", getIpHash(req));

      res.json({
        ok: true,
        filename: `insight-encrypted-backup-${new Date().toISOString().slice(0, 10)}.json`,
        backup: {
          format: "insight-backup-v2",
          kdf: "PBKDF2-SHA256-210000",
          salt: salt.toString("base64url"),
          ...sealedEnvelope,
        },
      });
    },
  );

  // HR Admin: Encrypted CSV Export with rate limit, 366-day range cap, and 50,000-row cap
  app.get(
    "/api/hr/export",
    hrExportLimiter,
    requireAuth,
    requireAdminWithStepUp,
    requirePermission("export_reports"),
    (req: AuthenticatedRequest, res) => {
      const fromDate = typeof req.query.from === "string" ? req.query.from : "";
      const toDate = typeof req.query.to === "string" ? req.query.to : "";
      const department = typeof req.query.department === "string" ? req.query.department : "";
      const statusFilter = typeof req.query.status === "string" ? req.query.status : "";

      if (fromDate && toDate) {
        const diffDays = Math.ceil((Date.parse(toDate) - Date.parse(fromDate)) / 86_400_000);
        if (!Number.isFinite(diffDays) || diffDays < 0 || diffDays > 366) {
          res.status(400).json({ ok: false, error: "EXPORT_RANGE_EXCEEDED" });
          return;
        }
      }

      const filtered = store.queryAttendanceForExport({
        fromDate: fromDate || undefined,
        toDate: toDate || undefined,
        department: department || undefined,
        statusFilter: statusFilter || undefined,
        limit: 50_001,
      });

      if (filtered.length > 50_000) {
        res.status(400).json({ ok: false, error: "EXPORT_LIMIT_EXCEEDED" });
        return;
      }

      const settings = store.getSettings();
      const header = [
        "الرقم الوظيفي",
        "اسم الموظف",
        "القسم",
        "المسمى الوظيفي",
        "التاريخ",
        "وقت الحضور",
        "وقت الانصراف",
        "ساعات العمل (دقيقة)",
        "التأخير (دقيقة)",
        "الحالة",
        "ملاحظات",
      ]
        .map(sanitizeCsvCell)
        .join(",");

      const formatClock = (iso: string | null) => {
        if (!iso) return "";
        try {
          return new Intl.DateTimeFormat("en-GB", {
            timeZone: settings.timezone,
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false,
          }).format(new Date(iso));
        } catch {
          return iso;
        }
      };

      const statusAr = (s: AttendanceStatus) => {
        if (s === "present") return "حاضر";
        if (s === "late") return "متأخر";
        return "بعذر";
      };

      const lines = filtered.map((r) =>
        [
          r.employee_number ?? "",
          r.employee_name ?? "",
          r.department ?? "",
          r.job_title ?? "",
          r.attendance_date,
          formatClock(r.checked_in_at),
          formatClock(r.checked_out_at),
          r.worked_minutes ?? "",
          r.late_minutes ?? 0,
          statusAr(r.status),
          r.notes ?? "",
        ]
          .map(sanitizeCsvCell)
          .join(","),
      );

      store.addSecurityLog(req.authUser!.id, "export_downloaded", "OK", getIpHash(req), {
        row_count: filtered.length,
        from: fromDate || null,
        to: toDate || null,
      });

      const csv = `\uFEFF${[header, ...lines].join("\r\n")}`;
      const filename = `insight-attendance-${fromDate || "all"}-to-${toDate || "today"}.csv`;

      res.json({ ok: true, filename, csv });
    },
  );

  // Global error handler — never expose stack traces or SQL/environment details to clients
  app.use((err: unknown, req: AuthenticatedRequest, res: Response, _next: NextFunction) => {
    const reqId = req.requestId ?? crypto.randomUUID();
    console.error(`[${reqId}] Unhandled server error:`, err instanceof Error ? err.message : err);
    if (!res.headersSent) {
      res.status(500).json({
        ok: false,
        error: "INTERNAL_SERVER_ERROR",
        request_id: reqId,
      });
    }
  });

  if (process.env.NODE_ENV === "production") {
    const distDir = path.resolve(process.cwd(), "dist");
    app.use(express.static(distDir));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distDir, "index.html"));
    });
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`InSight Attendance Server running on http://0.0.0.0:${PORT}`);
    });
    return;
  }

  let viteMiddleware: NextFunction | null = null;
  const viteReadyPromise = (async () => {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    viteMiddleware = vite.middlewares as unknown as NextFunction;
  })();

  app.use(async (req, res, next) => {
    if (!viteMiddleware) {
      await viteReadyPromise;
    }
    if (viteMiddleware) {
      (viteMiddleware as unknown as (req: Request, res: Response, next: NextFunction) => void)(
        req,
        res,
        next,
      );
      return;
    }
    next();
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`InSight Attendance Server running on http://0.0.0.0:${PORT}`);
  });
}

void startServer();
