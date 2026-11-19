import {
  clearAdminStepUpToken,
  secureFetchJson,
  setAdminStepUpToken,
} from "../lib/secureTransport";
import type {
  CompanySettings,
  HrOverviewResponse,
  KioskDeviceInfo,
  PermissionKey,
  Profile,
  RbacRoleDefinition,
  SecurityPolicySettings,
} from "../types/attendance";

export async function verifyAdminStepUp(
  password: string,
  totpCode?: string,
): Promise<{
  ok: boolean;
  expires_at?: string;
  aal?: "aal1" | "aal2";
  mfa_enabled?: boolean;
  mfa_setup_required?: boolean;
  error?: string;
}> {
  try {
    const payload: { password: string; totp_code?: string } = { password };
    if (totpCode && totpCode.trim().length > 0) {
      payload.totp_code = totpCode.trim();
    }
    const res = await secureFetchJson<{
      ok: boolean;
      step_up_token?: string;
      expires_at?: string;
      aal?: "aal1" | "aal2";
      mfa_enabled?: boolean;
      mfa_setup_required?: boolean;
      error?: string;
    }>("/api/hr/security/step-up", {
      method: "POST",
      body: payload,
    });
    if (!res.ok || !res.data?.ok || !res.data.step_up_token || !res.data.expires_at) {
      return {
        ok: false,
        mfa_enabled: res.data?.mfa_enabled,
        error: res.data?.error ?? "INVALID_CREDENTIALS",
      };
    }
    setAdminStepUpToken(res.data.step_up_token, res.data.expires_at);
    return {
      ok: true,
      expires_at: res.data.expires_at,
      aal: res.data.aal,
      mfa_enabled: res.data.mfa_enabled,
      mfa_setup_required: res.data.mfa_setup_required,
    };
  } catch {
    return { ok: false, error: "NETWORK_ERROR" };
  }
}

export async function enrollAdminMfa(): Promise<{
  ok: boolean;
  secret?: string;
  otpauth_uri?: string;
  error?: string;
}> {
  try {
    const res = await secureFetchJson<{
      ok: boolean;
      secret?: string;
      otpauth_uri?: string;
      error?: string;
    }>("/api/hr/security/mfa/enroll", {
      method: "POST",
      includeStepUp: true,
    });
    return res.data ?? { ok: false, error: "NETWORK_ERROR" };
  } catch {
    return { ok: false, error: "NETWORK_ERROR" };
  }
}

export async function activateAdminMfa(totpCode: string): Promise<{
  ok: boolean;
  mfa_enabled?: boolean;
  aal?: "aal2";
  expires_at?: string;
  error?: string;
}> {
  try {
    const res = await secureFetchJson<{
      ok: boolean;
      mfa_enabled?: boolean;
      aal?: "aal2";
      step_up_token?: string;
      expires_at?: string;
      error?: string;
    }>("/api/hr/security/mfa/activate", {
      method: "POST",
      body: { totp_code: totpCode.trim() },
      includeStepUp: true,
    });
    if (!res.ok || !res.data?.ok) {
      return { ok: false, error: res.data?.error ?? "INVALID_MFA_CODE" };
    }
    if (res.data.step_up_token && res.data.expires_at) {
      setAdminStepUpToken(res.data.step_up_token, res.data.expires_at);
    }
    return {
      ok: true,
      mfa_enabled: res.data.mfa_enabled,
      aal: res.data.aal,
      expires_at: res.data.expires_at,
    };
  } catch {
    return { ok: false, error: "NETWORK_ERROR" };
  }
}

export function lockAdminSessionNow(): void {
  clearAdminStepUpToken();
}

function emptyOverview(error: string): HrOverviewResponse {
  return {
    ok: false,
    today_date: "",
    stats: {
      total_active_employees: 0,
      checked_in_today: 0,
      on_shift_now: 0,
      checked_out_today: 0,
      late_today: 0,
      excused_today: 0,
      not_checked_in_today: 0,
    },
    employees: [],
    records: [],
    settings: {
      id: "",
      company_name: "",
      branch_name: "",
      latitude: 24.7136,
      longitude: 46.6753,
      allowed_radius_m: 300,
      max_gps_accuracy_m: 120,
      qr_ttl_seconds: 20,
      timezone: "Asia/Riyadh",
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
      updated_at: "",
    },
    kiosk_devices: [],
    security_logs: [],
    error,
  };
}

export async function fetchHrOverview(): Promise<HrOverviewResponse> {
  try {
    const res = await secureFetchJson<HrOverviewResponse>("/api/hr/overview", {
      method: "GET",
      includeStepUp: true,
    });
    if (!res.ok || !res.data) {
      return emptyOverview(res.data?.error ?? "FETCH_FAILED");
    }
    return res.data;
  } catch {
    return emptyOverview("NETWORK_ERROR");
  }
}

export async function createEmployee(payload: {
  full_name: string;
  email: string;
  password: string;
  employee_number: string;
  department: string;
  job_title: string;
  shift_start: string;
  shift_end: string;
}): Promise<{ ok: boolean; employee?: Profile; error?: string }> {
  const res = await secureFetchJson<{ ok: boolean; employee?: Profile; error?: string }>(
    "/api/hr/employees",
    {
      method: "POST",
      body: payload,
      includeStepUp: true,
    },
  );
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function updateEmployee(
  id: string,
  payload: Partial<
    Pick<Profile, "full_name" | "department" | "job_title" | "shift_start" | "shift_end" | "is_active">
  >,
): Promise<{ ok: boolean; employee?: Profile; error?: string }> {
  const res = await secureFetchJson<{ ok: boolean; employee?: Profile; error?: string }>(
    `/api/hr/employees/${encodeURIComponent(id)}`,
    {
      method: "PATCH",
      body: payload,
      includeStepUp: true,
    },
  );
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function logEmployeeExcuse(payload: {
  employee_id: string;
  attendance_date: string;
  notes: string;
}): Promise<{ ok: boolean; error?: string }> {
  const res = await secureFetchJson<{ ok: boolean; error?: string }>(
    "/api/hr/attendance/excuse",
    {
      method: "POST",
      body: payload,
      includeStepUp: true,
    },
  );
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function updateCompanySettings(
  payload: Partial<CompanySettings>,
): Promise<{ ok: boolean; settings?: CompanySettings; error?: string }> {
  const res = await secureFetchJson<{ ok: boolean; settings?: CompanySettings; error?: string }>(
    "/api/hr/settings",
    {
      method: "PUT",
      body: payload,
      includeStepUp: true,
    },
  );
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function createKioskDevice(payload: {
  device_name: string;
  branch_name: string;
  email: string;
  password: string;
  device_secret: string;
}): Promise<{ ok: boolean; device?: KioskDeviceInfo; error?: string }> {
  const res = await secureFetchJson<{ ok: boolean; device?: KioskDeviceInfo; error?: string }>(
    "/api/hr/kiosks",
    {
      method: "POST",
      body: payload,
      includeStepUp: true,
    },
  );
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function updateKioskDevice(
  id: string,
  payload: { device_name?: string; branch_name?: string; is_active?: boolean },
): Promise<{ ok: boolean; device?: KioskDeviceInfo; error?: string }> {
  const res = await secureFetchJson<{ ok: boolean; device?: KioskDeviceInfo; error?: string }>(
    `/api/hr/kiosks/${encodeURIComponent(id)}`,
    {
      method: "PATCH",
      body: payload,
      includeStepUp: true,
    },
  );
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function revokeKioskDevice(payload: {
  device_id: string;
  new_secret?: string;
}): Promise<{ ok: boolean; error?: string }> {
  const res = await secureFetchJson<{ ok: boolean; error?: string }>("/api/hr/kiosk/revoke", {
    method: "POST",
    body: payload,
    includeStepUp: true,
  });
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function updateSecurityPolicy(
  payload: Partial<SecurityPolicySettings>,
): Promise<{ ok: boolean; security_policy?: SecurityPolicySettings; error?: string }> {
  const res = await secureFetchJson<{
    ok: boolean;
    security_policy?: SecurityPolicySettings;
    error?: string;
  }>("/api/hr/security/policy", {
    method: "PUT",
    body: payload,
    includeStepUp: true,
  });
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function updateRbacRole(
  roleKey: string,
  permissions: PermissionKey[],
): Promise<{ ok: boolean; rbac_roles?: Record<string, RbacRoleDefinition>; error?: string }> {
  const res = await secureFetchJson<{
    ok: boolean;
    rbac_roles?: Record<string, RbacRoleDefinition>;
    error?: string;
  }>(`/api/hr/rbac/roles/${encodeURIComponent(roleKey)}`, {
    method: "PUT",
    body: { permissions },
    includeStepUp: true,
  });
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function assignUserRbac(
  userId: string,
  payload: {
    role: "employee" | "admin";
    admin_role_key?: string | null;
    permissions?: PermissionKey[];
  },
): Promise<{ ok: boolean; user?: Profile; error?: string }> {
  const res = await secureFetchJson<{ ok: boolean; user?: Profile; error?: string }>(
    `/api/hr/rbac/users/${encodeURIComponent(userId)}`,
    {
      method: "PUT",
      body: payload,
      includeStepUp: true,
    },
  );
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function changeOwnPassword(payload: {
  current_password: string;
  new_password: string;
}): Promise<{ ok: boolean; token?: string; error?: string }> {
  const res = await secureFetchJson<{ ok: boolean; token?: string; error?: string }>(
    "/api/auth/change-password",
    {
      method: "POST",
      body: payload,
    },
  );
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function revokeSessionByJti(
  jti: string,
): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await secureFetchJson<{ ok: boolean; error?: string }>(
      `/api/hr/security/sessions/${encodeURIComponent(jti)}`,
      {
        method: "DELETE",
        includeStepUp: true,
      },
    );
    return res.data ?? { ok: false, error: "NETWORK_ERROR" };
  } catch {
    return { ok: false, error: "NETWORK_ERROR" };
  }
}

export async function exportEncryptedBackup(
  passphrase: string,
): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await secureFetchJson<{
      ok: boolean;
      filename?: string;
      backup?: Record<string, unknown>;
      error?: string;
    }>("/api/hr/security/backup", {
      method: "POST",
      body: { passphrase },
      includeStepUp: true,
    });
    if (!res.ok || !res.data?.ok || !res.data.backup) {
      return { ok: false, error: res.data?.error ?? "BACKUP_FAILED" };
    }
    const blob = new Blob([JSON.stringify(res.data.backup, null, 2)], {
      type: "application/json;charset=utf-8;",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download =
      res.data.filename ?? `insight-encrypted-backup-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    return { ok: true };
  } catch {
    return { ok: false, error: "NETWORK_ERROR" };
  }
}

export async function revokeAllSessions(): Promise<{
  ok: boolean;
  affected_accounts?: number;
  error?: string;
}> {
  const res = await secureFetchJson<{
    ok: boolean;
    affected_accounts?: number;
    error?: string;
  }>("/api/hr/security/revoke-all-sessions", {
    method: "POST",
    includeStepUp: true,
  });
  return res.data ?? { ok: false, error: "NETWORK_ERROR" };
}

export async function downloadHrCsvExport(params: {
  from?: string;
  to?: string;
  department?: string;
  status?: string;
}): Promise<{ ok: boolean; error?: string }> {
  const qs = new URLSearchParams();
  if (params.from) qs.set("from", params.from);
  if (params.to) qs.set("to", params.to);
  if (params.department) qs.set("department", params.department);
  if (params.status) qs.set("status", params.status);

  try {
    const res = await secureFetchJson<{ ok: boolean; filename?: string; csv?: string; error?: string }>(
      `/api/hr/export?${qs.toString()}`,
      {
        method: "GET",
        includeStepUp: true,
      },
    );
    if (!res.ok || !res.data?.ok || !res.data.csv) {
      return { ok: false, error: res.data?.error ?? "EXPORT_FAILED" };
    }

    const blob = new Blob([res.data.csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download =
      res.data.filename ?? `insight-attendance-${params.from || "all"}-to-${params.to || "today"}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    return { ok: true };
  } catch {
    return { ok: false, error: "NETWORK_ERROR" };
  }
}
