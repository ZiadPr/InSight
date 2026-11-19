import { sql } from "drizzle-orm";
import { pgTable, text, integer, doublePrecision, bigint, index, uniqueIndex, check } from "drizzle-orm/pg-core";

export const system_secrets = pgTable("system_secrets", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  is_encrypted: integer("is_encrypted").notNull().default(1),
  updated_at: text("updated_at").notNull(),
});

export const company_settings = pgTable("company_settings", {
  id: text("id").primaryKey(),
  company_name: text("company_name").notNull(),
  branch_name: text("branch_name").notNull(),
  latitude: doublePrecision("latitude").notNull(),
  longitude: doublePrecision("longitude").notNull(),
  allowed_radius_m: integer("allowed_radius_m").notNull(),
  max_gps_accuracy_m: integer("max_gps_accuracy_m").notNull(),
  qr_ttl_seconds: integer("qr_ttl_seconds").notNull(),
  timezone: text("timezone").notNull(),
  work_start_time: text("work_start_time").notNull(),
  work_end_time: text("work_end_time").notNull(),
  late_grace_minutes: integer("late_grace_minutes").notNull(),
  enforce_geofence: integer("enforce_geofence").notNull(),
  is_enabled: integer("is_enabled").notNull(),
  qr_schedule_enabled: integer("qr_schedule_enabled").notNull().default(0),
  qr_window_start: text("qr_window_start").notNull().default("07:30"),
  qr_cutoff_time: text("qr_cutoff_time").notNull().default("11:00"),
  qr_reappear_time: text("qr_reappear_time").notNull().default("15:30"),
  qr_window_end: text("qr_window_end").notNull().default("19:00"),
  updated_at: text("updated_at").notNull(),
});

export const security_policy = pgTable("security_policy", {
  id: integer("id").primaryKey(),
  cloudflare_enabled: integer("cloudflare_enabled").notNull().default(0),
  trust_cf_headers: integer("trust_cf_headers").notNull().default(0),
  allowed_countries_json: text("allowed_countries_json").notNull().default("[]"),
  max_cf_threat_score: integer("max_cf_threat_score").notNull().default(25),
  turnstile_enabled: integer("turnstile_enabled").notNull().default(0),
  turnstile_site_key: text("turnstile_site_key").notNull().default(""),
  strict_ip_binding: integer("strict_ip_binding").notNull().default(0),
  block_method_override: integer("block_method_override").notNull().default(1),
  enforce_json_content_type: integer("enforce_json_content_type").notNull().default(1),
}, (t) => [
  check("security_policy_id_check", sql`id = 1`),
]);

export const rbac_roles = pgTable("rbac_roles", {
  role_key: text("role_key").primaryKey(),
  label_ar: text("label_ar").notNull(),
  label_en: text("label_en").notNull(),
  permissions_json: text("permissions_json").notNull(),
});

export const users = pgTable("users", {
  id: text("id").primaryKey(),
  email: text("email").notNull().unique(),
  password_salt: text("password_salt").notNull(),
  password_hash: text("password_hash").notNull(),
  token_version: integer("token_version").notNull().default(1),
  full_name: text("full_name").notNull(),
  employee_number: text("employee_number").unique(),
  department: text("department"),
  job_title: text("job_title"),
  shift_start: text("shift_start").notNull().default("09:00"),
  shift_end: text("shift_end").notNull().default("17:00"),
  role: text("role").notNull(),
  admin_role_key: text("admin_role_key"),
  permissions_json: text("permissions_json"),
  is_active: integer("is_active").notNull().default(1),
  mfa_enabled: integer("mfa_enabled").notNull().default(0),
  mfa_secret_enc: text("mfa_secret_enc"),
  last_used_totp_step: integer("last_used_totp_step"),
  must_change_password: integer("must_change_password").notNull().default(0),
  created_at: text("created_at").notNull(),
  updated_at: text("updated_at").notNull(),
}, (t) => [
  index("idx_users_role_active").on(t.role, t.is_active),
  uniqueIndex("idx_users_email_lower").on(sql`lower(${t.email})`),
  check("users_role_check", sql`role IN ('employee', 'kiosk', 'admin')`),
]);

export const kiosk_devices = pgTable("kiosk_devices", {
  id: text("id").primaryKey(),
  device_name: text("device_name").notNull(),
  branch_name: text("branch_name").notNull(),
  auth_user_id: text("auth_user_id").notNull().unique().references(() => users.id, { onDelete: "cascade" }),
  secret_hash: text("secret_hash").notNull(),
  is_active: integer("is_active").notNull().default(1),
  last_seen_at: text("last_seen_at"),
  revoked_before: text("revoked_before"),
  created_at: text("created_at").notNull(),
});

export const qr_tokens = pgTable("qr_tokens", {
  id: text("id").primaryKey(),
  token_hash: text("token_hash").notNull().unique(),
  manual_code_hash: text("manual_code_hash"),
  kiosk_device_id: text("kiosk_device_id").notNull().references(() => kiosk_devices.id, { onDelete: "cascade" }),
  issued_at: text("issued_at").notNull(),
  expires_at: text("expires_at").notNull(),
  consumed_at: text("consumed_at"),
  consumed_by: text("consumed_by"),
  consumed_action: text("consumed_action"),
  status: text("status").notNull(),
}, (t) => [
  index("idx_qr_tokens_kiosk_status").on(t.kiosk_device_id, t.status),
  index("idx_qr_tokens_manual").on(t.manual_code_hash),
  index("idx_qr_tokens_issued").on(t.issued_at),
  check("qr_tokens_consumed_action_check", sql`consumed_action IN ('check_in', 'check_out') OR consumed_action IS NULL`),
  check("qr_tokens_status_check", sql`status IN ('active', 'consumed', 'expired', 'revoked')`),
]);

export const attendance_records = pgTable("attendance_records", {
  id: text("id").primaryKey(),
  employee_id: text("employee_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  attendance_date: text("attendance_date").notNull(),
  checked_in_at: text("checked_in_at"),
  checked_out_at: text("checked_out_at"),
  worked_minutes: integer("worked_minutes"),
  late_minutes: integer("late_minutes").notNull().default(0),
  status: text("status").notNull(),
  qr_token_id: text("qr_token_id").unique(),
  idempotency_key: text("idempotency_key"),
  distance_m: integer("distance_m"),
  gps_meta_enc: text("gps_meta_enc"),
  notes: text("notes"),
  created_at: text("created_at").notNull(),
}, (t) => [
  uniqueIndex("idx_attendance_emp_date").on(t.employee_id, t.attendance_date),
  index("idx_attendance_date").on(t.attendance_date),
  index("idx_attendance_emp_idempotency").on(t.employee_id, t.idempotency_key),
  check("attendance_records_status_check", sql`status IN ('present', 'late', 'excused')`),
]);

export const active_sessions = pgTable("active_sessions", {
  jti: text("jti").primaryKey(),
  user_id: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  role: text("role").notNull(),
  aal: text("aal").notNull(),
  ua_hash: text("ua_hash").notNull(),
  ip_hash: text("ip_hash").notNull(),
  created_at: text("created_at").notNull(),
  last_active_at: text("last_active_at").notNull(),
  idle_expires_at: text("idle_expires_at").notNull(),
  absolute_expires_at: text("absolute_expires_at").notNull(),
}, (t) => [
  index("idx_active_sessions_user").on(t.user_id),
]);

export const revoked_jtis = pgTable("revoked_jtis", {
  jti: text("jti").primaryKey(),
  exp_ms: bigint("exp_ms", { mode: "number" }).notNull(),
}, (t) => [
  index("idx_revoked_jtis_exp").on(t.exp_ms),
]);

export const security_logs = pgTable("security_logs", {
  id: text("id").primaryKey(),
  user_id: text("user_id"),
  event_type: text("event_type").notNull(),
  reason_code: text("reason_code"),
  ip_hash: text("ip_hash"),
  created_at: text("created_at").notNull(),
  metadata_json: text("metadata_json").notNull(),
}, (t) => [
  index("idx_security_logs_created").on(t.created_at.desc()),
  index("idx_security_logs_anomaly").on(t.event_type, t.ip_hash, t.created_at),
]);

export const security_alerts = pgTable("security_alerts", {
  id: text("id").primaryKey(),
  severity: text("severity").notNull(),
  event: text("event").notNull(),
  request_id: text("request_id"),
  ip_hash: text("ip_hash"),
  created_at: text("created_at").notNull(),
  details_json: text("details_json").notNull(),
}, (t) => [
  index("idx_security_alerts_created").on(t.created_at.desc()),
]);

export const rate_limits = pgTable("rate_limits", {
  key: text("key").primaryKey(),
  attempts: integer("attempts").notNull(),
  window_start: bigint("window_start", { mode: "number" }).notNull(),
  blocked_until: bigint("blocked_until", { mode: "number" }).notNull(),
}, (t) => [index("idx_rate_limits_window_start").on(t.window_start)]);
