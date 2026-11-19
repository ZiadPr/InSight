export type UserRole = "employee" | "kiosk" | "admin";

export type AppLanguage = "ar" | "en";

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

export interface Profile {
  id: string;
  email: string;
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

export interface AttendanceRecord {
  id: string;
  employee_id: string;
  employee_name?: string;
  employee_number?: string | null;
  department?: string | null;
  job_title?: string | null;
  attendance_date: string;
  checked_in_at: string | null;
  checked_out_at: string | null;
  worked_minutes: number | null;
  late_minutes: number;
  status: AttendanceStatus;
  notes?: string | null;
  distance_m?: number | null;
}

export interface KioskDeviceInfo {
  id: string;
  device_name: string;
  branch_name: string;
  auth_email?: string;
  is_active: boolean;
  last_seen_at: string | null;
  revoked_before: string | null;
  created_at?: string;
}

export interface SecurityLogEntry {
  id: string;
  user_id: string | null;
  user_name?: string;
  event_type: string;
  reason_code: string | null;
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface KioskTokenResponse {
  ok: boolean;
  token?: string;
  manual_code?: string;
  token_id?: string;
  issued_at?: string;
  expires_at?: string;
  ttl_seconds?: number;
  company_name?: string;
  branch_name?: string;
  device_name?: string;
  is_local_demo?: boolean;
  schedule_status?: "open" | "closed";
  next_reappear_time?: string | null;
  window_cutoff_time?: string | null;
  error?: string;
}

export interface KioskTokenStatusResponse {
  ok: boolean;
  status?: "active" | "consumed" | "expired" | "revoked";
  consumed_action?: "check_in" | "check_out" | null;
  expires_at?: string;
  consumed_at?: string | null;
  server_now?: string;
  schedule_status?: "open" | "closed";
  next_reappear_time?: string | null;
  error?: string;
}

export interface CheckInRequestPayload {
  qr_token: string;
  action?: "auto" | "check_in" | "check_out";
  latitude: number | null;
  longitude: number | null;
  accuracy: number | null;
  client_captured_at: string;
  idempotency_key: string;
}

export interface CheckInResponse {
  ok: boolean;
  action?: "check_in" | "check_out";
  attendance_date?: string;
  checked_in_at?: string | null;
  checked_out_at?: string | null;
  worked_minutes?: number | null;
  late_minutes?: number;
  status?: AttendanceStatus;
  distance_m?: number | null;
  error?: string;
  next_reappear_time?: string | null;
  retry_after_seconds?: number;
}

export interface HrOverviewStats {
  total_active_employees: number;
  checked_in_today: number;
  on_shift_now: number;
  checked_out_today: number;
  late_today: number;
  excused_today: number;
  not_checked_in_today: number;
}

export interface ActiveSessionInfo {
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
}

export interface SecurityAlertEntry {
  id: string;
  severity: "medium" | "high" | "critical";
  event: string;
  request_id: string | null;
  ip_hash: string | null;
  created_at: string;
  details: Record<string, unknown>;
}

export interface MfaStatusInfo {
  enabled: boolean;
  required: boolean;
  aal: "aal1" | "aal2";
}

export interface HrOverviewResponse {
  ok: boolean;
  today_date: string;
  stats: HrOverviewStats;
  employees: Profile[];
  staff_users?: Profile[];
  records: AttendanceRecord[];
  settings: CompanySettings;
  security_policy?: SecurityPolicySettings;
  rbac_roles?: Record<string, RbacRoleDefinition>;
  current_permissions?: PermissionKey[];
  kiosk_devices: KioskDeviceInfo[];
  security_logs: SecurityLogEntry[];
  security_alerts?: SecurityAlertEntry[];
  active_sessions?: ActiveSessionInfo[];
  mfa_status?: MfaStatusInfo;
  error?: string;
}
