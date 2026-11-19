import crypto from "node:crypto";
export type UserRole = "employee" | "kiosk" | "admin";
export type AttendanceStatus = "present" | "late" | "excused";
export type PermissionKey =
  | "view_overview"
  | "view_records"
  | "export_reports"
  | "manage_excuses"
  | "manage_employees"
  | "manage_kiosks"
  | "manage_settings"
  | "manage_security"
  | "manage_permissions";

export interface RbacRoleDefinition {
  label_ar: string;
  label_en: string;
  permissions: PermissionKey[];
}

export interface SecurityPolicySettings {
  cloudflare_enabled: boolean;
  trust_cf_headers: boolean;
  allowed_countries: string[];
  max_cf_threat_score: number;
  turnstile_enabled: boolean;
  turnstile_site_key: string;
  strict_ip_binding: boolean;
  block_method_override: boolean;
  enforce_json_content_type: boolean;
}

export const ALL_PERMISSION_KEYS: PermissionKey[] = [
  "view_overview",
  "view_records",
  "export_reports",
  "manage_excuses",
  "manage_employees",
  "manage_kiosks",
  "manage_settings",
  "manage_security",
  "manage_permissions",
];

export function buildDefaultRbacRoles(): Record<string, RbacRoleDefinition> {
  return {
    super_admin: {
      label_ar: "مدير النظام الأعلى",
      label_en: "Super Administrator",
      permissions: [...ALL_PERMISSION_KEYS],
    },
    hr_manager: {
      label_ar: "مدير الموارد البشرية",
      label_en: "HR Manager",
      permissions: [
        "view_overview",
        "view_records",
        "export_reports",
        "manage_excuses",
        "manage_employees",
        "manage_kiosks",
        "manage_settings",
      ],
    },
    attendance_supervisor: {
      label_ar: "مشرف الحضور والانصراف",
      label_en: "Attendance Supervisor",
      permissions: ["view_overview", "view_records", "export_reports", "manage_excuses"],
    },
    security_auditor: {
      label_ar: "مدقق الأمن السيبراني",
      label_en: "Security Auditor",
      permissions: ["view_overview", "manage_security", "manage_kiosks"],
    },
  };
}

export function buildDefaultSecurityPolicy(): SecurityPolicySettings {
  return {
    cloudflare_enabled: false,
    trust_cf_headers: false,
    allowed_countries: [],
    max_cf_threat_score: 25,
    turnstile_enabled: false,
    turnstile_site_key: "",
    strict_ip_binding: false,
    block_method_override: true,
    enforce_json_content_type: true,
  };
}

export interface StoredUser {
  id: string;
  email: string;
  password_salt: string;
  password_hash: string;
  token_version: number;
  full_name: string;
  employee_number: string | null;
  department: string | null;
  job_title: string | null;
  shift_start: string;
  shift_end: string;
  role: UserRole;
  admin_role_key?: string | null;
  permissions?: PermissionKey[];
  is_active: boolean;
  mfa_enabled?: boolean;
  mfa_secret_enc?: string | null;
  last_used_totp_step?: number;
  must_change_password?: boolean;
  created_at: string;
  updated_at: string;
}

export interface CompanySettings {
  id: string;
  company_name: string;
  branch_name: string;
  latitude: number;
  longitude: number;
  allowed_radius_m: number;
  max_gps_accuracy_m: number;
  qr_ttl_seconds: number;
  timezone: string;
  work_start_time: string;
  work_end_time: string;
  late_grace_minutes: number;
  enforce_geofence: boolean;
  is_enabled: boolean;
  qr_schedule_enabled: boolean;
  qr_window_start: string;
  qr_cutoff_time: string;
  qr_reappear_time: string;
  qr_window_end: string;
  updated_at: string;
}

export interface KioskDevice {
  id: string;
  device_name: string;
  branch_name: string;
  auth_user_id: string;
  secret_hash: string;
  is_active: boolean;
  last_seen_at: string | null;
  revoked_before: string | null;
  created_at: string;
}

export interface QrToken {
  id: string;
  token_hash: string;
  manual_code_hash?: string | null;
  kiosk_device_id: string;
  issued_at: string;
  expires_at: string;
  consumed_at: string | null;
  consumed_by: string | null;
  consumed_action: "check_in" | "check_out" | null;
  status: "active" | "consumed" | "expired" | "revoked";
}

export interface AttendanceRecord {
  id: string;
  employee_id: string;
  attendance_date: string;
  checked_in_at: string | null;
  checked_out_at: string | null;
  worked_minutes: number | null;
  late_minutes: number;
  status: AttendanceStatus;
  qr_token_id: string | null;
  idempotency_key: string | null;
  distance_m: number | null;
  notes: string | null;
  created_at: string;
}

export interface SecurityLog {
  id: string;
  user_id: string | null;
  event_type: string;
  reason_code: string | null;
  ip_hash: string | null;
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface RevokedJti {
  jti: string;
  exp_ms: number;
}

export interface ActiveSession {
  jti: string;
  user_id: string;
  role: UserRole;
  aal: "aal1" | "aal2";
  ua_hash: string;
  ip_hash: string;
  created_at: string;
  last_active_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
}

export interface SecurityAlertEntry {
  id: string;
  severity: "critical" | "high" | "medium";
  event: string;
  request_id: string | null;
  ip_hash: string | null;
  created_at: string;
  details: Record<string, unknown>;
}

export interface DatabaseState {
  auth_secret: string;
  kiosk_salt: string;
  ip_salt: string;
  signing_private_pem?: string;
  signing_public_spki?: string;
  users: StoredUser[];
  settings: CompanySettings;
  security_policy?: SecurityPolicySettings;
  rbac_roles?: Record<string, RbacRoleDefinition>;
  kiosk_devices: KioskDevice[];
  qr_tokens: QrToken[];
  attendance_records: AttendanceRecord[];
  security_logs: SecurityLog[];
  security_alerts?: SecurityAlertEntry[];
  active_sessions?: ActiveSession[];
  revoked_jtis: RevokedJti[];
}

export interface RuntimeSecrets {
  auth_secret: string;
  kiosk_salt: string;
  ip_salt: string;
  signing_private_pem: string;
  signing_public_spki: string;
}

export function encryptJsonPayload(plaintext: string, key: Buffer): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: 1,
    alg: "aes-256-gcm",
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    data: encrypted.toString("base64url"),
  });
}

export function decryptJsonPayload(raw: string, key: Buffer): string {
  const parsed = JSON.parse(raw) as {
    v?: number;
    iv?: string;
    tag?: string;
    data?: string;
  };
  if (!parsed.iv || !parsed.tag || !parsed.data) {
    throw new Error("INVALID_ENCRYPTED_ENVELOPE");
  }
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(parsed.iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(parsed.tag, "base64url"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(parsed.data, "base64url")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

export function parseJsonSafe<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export interface RawUserRow {
  id: string;
  email: string;
  password_salt: string;
  password_hash: string;
  token_version: number;
  full_name: string;
  employee_number: string | null;
  department: string | null;
  job_title: string | null;
  shift_start: string;
  shift_end: string;
  role: UserRole;
  admin_role_key: string | null;
  permissions_json: string | null;
  is_active: number;
  mfa_enabled: number;
  mfa_secret_enc: string | null;
  last_used_totp_step: number | null;
  must_change_password: number;
  created_at: string;
  updated_at: string;
}

export interface RawAttendanceRow {
  id: string;
  employee_id: string;
  attendance_date: string;
  checked_in_at: string | null;
  checked_out_at: string | null;
  worked_minutes: number | null;
  late_minutes: number;
  status: AttendanceStatus;
  qr_token_id: string | null;
  idempotency_key: string | null;
  distance_m: number | null;
  gps_meta_enc: string | null;
  notes: string | null;
  created_at: string;
}

export interface RawSettingsRow {
  id: string;
  company_name: string;
  branch_name: string;
  latitude: number;
  longitude: number;
  allowed_radius_m: number;
  max_gps_accuracy_m: number;
  qr_ttl_seconds: number;
  timezone: string;
  work_start_time: string;
  work_end_time: string;
  late_grace_minutes: number;
  enforce_geofence: number;
  is_enabled: number;
  qr_schedule_enabled: number;
  qr_window_start: string;
  qr_cutoff_time: string;
  qr_reappear_time: string;
  qr_window_end: string;
  updated_at: string;
}

export interface RawKioskRow {
  id: string;
  device_name: string;
  branch_name: string;
  auth_user_id: string;
  secret_hash: string;
  is_active: number;
  last_seen_at: string | null;
  revoked_before: string | null;
  created_at: string;
  auth_email?: string;
}

