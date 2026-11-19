export interface CorsDecision {
  allowed: boolean;
  allowOrigin?: string;
}

export function evaluateCorsOrigin(
  origin: string | null,
  rawAllowedOrigins: string | undefined,
): CorsDecision {
  const allowedList = (rawAllowedOrigins ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  // Non-browser / same-origin server-to-server requests without Origin header
  if (!origin) {
    return { allowed: true };
  }

  if (allowedList.length > 0) {
    if (allowedList.includes(origin)) {
      return { allowed: true, allowOrigin: origin };
    }
    return { allowed: false };
  }

  // Only allow localhost origins when ALLOWED_ORIGINS is unset (local dev)
  if (origin.startsWith("http://localhost:") || origin.startsWith("https://localhost:")) {
    return { allowed: true, allowOrigin: origin };
  }

  return { allowed: false };
}

export function requireStrongSalt(value: string | undefined, name: string): string {
  const trimmed = value?.trim() ?? "";
  if (trimmed.length < 32) {
    throw new Error(`Missing or weak server secret: ${name}`);
  }
  return trimmed;
}

export async function sha256HexWeb(value: string): Promise<string> {
  const encoded = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function constantTimeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export function validateGpsFreshness(
  clientCapturedAt: unknown,
  serverNowMs = Date.now(),
  maxAgeMs = 30_000,
  maxFutureSkewMs = 10_000,
): { ok: true; capturedMs: number } | { ok: false; error: "GPS_STALE" | "LOCATION_INVALID" } {
  if (typeof clientCapturedAt !== "string" || clientCapturedAt.trim().length === 0) {
    return { ok: false, error: "LOCATION_INVALID" };
  }
  const capturedMs = Date.parse(clientCapturedAt);
  if (!Number.isFinite(capturedMs)) {
    return { ok: false, error: "LOCATION_INVALID" };
  }
  const ageMs = serverNowMs - capturedMs;
  if (ageMs > maxAgeMs || ageMs < -maxFutureSkewMs) {
    return { ok: false, error: "GPS_STALE" };
  }
  return { ok: true, capturedMs };
}

export function evaluateRateLimitResult(
  rpcData: unknown,
  rpcError: unknown,
):
  | { allowed: true }
  | { allowed: false; status: 429 | 503; error: string; retryAfterSeconds?: number } {
  if (rpcError || !rpcData || typeof rpcData !== "object") {
    return { allowed: false, status: 503, error: "RATE_LIMIT_UNAVAILABLE" };
  }
  const record = rpcData as { allowed?: unknown; retry_after_seconds?: unknown };
  if (typeof record.allowed !== "boolean") {
    return { allowed: false, status: 503, error: "RATE_LIMIT_UNAVAILABLE" };
  }
  if (!record.allowed) {
    return {
      allowed: false,
      status: 429,
      error: "RATE_LIMITED",
      retryAfterSeconds:
        typeof record.retry_after_seconds === "number" ? record.retry_after_seconds : 60,
    };
  }
  return { allowed: true };
}

export function decodeVerifiedJwtClaims(
  jwt: string,
): { aal?: string; iat?: number; sub?: string } | null {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    const json = new TextDecoder().decode(
      Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)),
    );
    return JSON.parse(json) as { aal?: string; iat?: number; sub?: string };
  } catch {
    return null;
  }
}

export function requireAal2Mfa(jwt: string): boolean {
  const claims = decodeVerifiedJwtClaims(jwt);
  return claims?.aal === "aal2";
}

export interface KioskDeviceSecurityRecord {
  is_active: boolean;
  secret_hash: string | null;
  revoked_before: string | null;
}

export async function verifyKioskAuthorization(params: {
  device: KioskDeviceSecurityRecord | null;
  providedSecret: string;
  deviceSecretSalt: string | undefined;
  jwtIssuedAtSec: number | undefined;
}): Promise<{ ok: true } | { ok: false; status: 401 | 403 | 500; error: string }> {
  const { device, providedSecret, deviceSecretSalt, jwtIssuedAtSec } = params;

  if (!device || device.is_active !== true) {
    return { ok: false, status: 403, error: "KIOSK_NOT_AUTHORIZED" };
  }

  if (!device.secret_hash || device.secret_hash.trim().length < 32) {
    return { ok: false, status: 403, error: "DEVICE_SECRET_NOT_CONFIGURED" };
  }

  let salt: string;
  try {
    salt = requireStrongSalt(deviceSecretSalt, "KIOSK_DEVICE_SECRET_SALT");
  } catch {
    return { ok: false, status: 500, error: "SERVER_MISCONFIGURED" };
  }

  if (device.revoked_before) {
    const revokedMs = Date.parse(device.revoked_before);
    const issuedMs = typeof jwtIssuedAtSec === "number" ? jwtIssuedAtSec * 1000 : 0;
    if (!Number.isFinite(issuedMs) || issuedMs <= revokedMs) {
      return { ok: false, status: 401, error: "KIOSK_SESSION_REVOKED" };
    }
  }

  const secret = providedSecret.trim();
  if (!secret) {
    return { ok: false, status: 403, error: "DEVICE_SECRET_REQUIRED" };
  }

  const providedHash = await sha256HexWeb(`${salt}:${secret}`);
  if (!constantTimeEqualStr(providedHash, device.secret_hash)) {
    return { ok: false, status: 403, error: "DEVICE_SECRET_INVALID" };
  }

  return { ok: true };
}

export interface ExportStudentRow {
  id: string;
  full_name: string;
  student_number: string | null;
}

export interface ExportAttendanceRow {
  student_id: string;
  attendance_date: string;
  checked_in_at: string;
  status: "present" | "excused";
}

export interface StudentSummaryRow {
  student_id: string;
  student_number: string;
  full_name: string;
  present_days: number;
  excused_days: number;
  absent_days: number | string;
  attendance_rate: number | string;
}

export function buildAttendanceSummaryRows(
  students: ExportStudentRow[],
  allRecordsInRange: ExportAttendanceRow[],
  totalStudyDays: number,
): StudentSummaryRow[] {
  const counts = new Map<string, { present: number; excused: number }>();

  for (const rec of allRecordsInRange) {
    const entry = counts.get(rec.student_id) ?? { present: 0, excused: 0 };
    if (rec.status === "present") {
      entry.present += 1;
    } else if (rec.status === "excused") {
      entry.excused += 1;
    }
    counts.set(rec.student_id, entry);
  }

  return students.map((student) => {
    const entry = counts.get(student.id) ?? { present: 0, excused: 0 };
    const accountedDays = entry.present + entry.excused;
    const absent = totalStudyDays > 0 ? Math.max(0, totalStudyDays - accountedDays) : 0;
    const rate =
      totalStudyDays > 0
        ? Number(((entry.present / totalStudyDays) * 100).toFixed(1))
        : 0;

    return {
      student_id: student.id,
      student_number: student.student_number ?? "",
      full_name: student.full_name,
      present_days: entry.present,
      excused_days: entry.excused,
      absent_days: totalStudyDays > 0 ? absent : "غير محدد (بدون تقويم)",
      attendance_rate: totalStudyDays > 0 ? rate : "غير محدد",
    };
  });
}
