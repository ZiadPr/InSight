import { enforceCors, jsonResponse } from "../_shared/cors.ts";
import { extractIpHash, sha256Hex } from "../_shared/crypto.ts";
import {
  evaluateRateLimitResult,
  validateGpsFreshness,
} from "../_shared/securityGuards.ts";
import { authenticateRequestUser, createServiceClient } from "../_shared/supabaseAdmin.ts";

function isValidNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

Deno.serve(async (req: Request) => {
  const corsBlock = enforceCors(req);
  if (corsBlock) return corsBlock;

  if (req.method !== "POST") {
    return jsonResponse(req, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    // 1. Authenticate student exclusively from verified JWT
    const { user, error: authError } = await authenticateRequestUser(req);
    if (authError || !user) {
      return jsonResponse(req, { ok: false, error: "UNAUTHORIZED" }, 401);
    }

    const body = await req.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return jsonResponse(req, { ok: false, error: "INVALID_REQUEST" }, 400);
    }

    const qrToken = typeof body.qr_token === "string" ? body.qr_token.trim() : "";
    const latitude = body.latitude;
    const longitude = body.longitude;
    const accuracy = body.accuracy;
    const idempotencyKey =
      typeof body.idempotency_key === "string" ? body.idempotency_key.slice(0, 128) : null;

    if (qrToken.length < 16 || qrToken.length > 512) {
      return jsonResponse(req, { ok: false, error: "QR_INVALID" }, 400);
    }

    if (
      !isValidNumber(latitude) ||
      !isValidNumber(longitude) ||
      !isValidNumber(accuracy) ||
      latitude < -90 ||
      latitude > 90 ||
      longitude < -180 ||
      longitude > 180 ||
      accuracy <= 0
    ) {
      return jsonResponse(req, { ok: false, error: "LOCATION_INVALID" }, 400);
    }

    // 2. Reject missing or stale GPS samples (>30s old or >10s future clock skew)
    const freshness = validateGpsFreshness(body.client_captured_at);
    if (!freshness.ok) {
      return jsonResponse(req, { ok: false, error: freshness.error }, 400);
    }

    const adminClient = createServiceClient();

    // 3. Require strong IP_HASH_SALT (throws and fails closed if missing)
    let ipHash: string | null = null;
    try {
      ipHash = await extractIpHash(req);
    } catch {
      return jsonResponse(req, { ok: false, error: "SERVER_MISCONFIGURED" }, 500);
    }

    // 4. Fail-closed rate limiting for student account and IP
    const { data: userLimitData, error: userLimitErr } = await adminClient.rpc(
      "check_rate_limit",
      {
        p_key: `student:${user.id}`,
        p_max_attempts: 8,
        p_window_seconds: 60,
        p_block_seconds: 120,
      },
    );

    const userLimitDecision = evaluateRateLimitResult(userLimitData, userLimitErr);
    if (!userLimitDecision.allowed) {
      return jsonResponse(
        req,
        {
          ok: false,
          error: userLimitDecision.error,
          ...(userLimitDecision.retryAfterSeconds !== undefined
            ? { retry_after_seconds: userLimitDecision.retryAfterSeconds }
            : {}),
        },
        userLimitDecision.status,
      );
    }

    if (ipHash) {
      const { data: ipLimitData, error: ipLimitErr } = await adminClient.rpc(
        "check_rate_limit",
        {
          p_key: `ip:${ipHash}`,
          p_max_attempts: 60,
          p_window_seconds: 60,
          p_block_seconds: 60,
        },
      );

      const ipLimitDecision = evaluateRateLimitResult(ipLimitData, ipLimitErr);
      if (!ipLimitDecision.allowed) {
        return jsonResponse(
          req,
          {
            ok: false,
            error: ipLimitDecision.error,
            ...(ipLimitDecision.retryAfterSeconds !== undefined
              ? { retry_after_seconds: ipLimitDecision.retryAfterSeconds }
              : {}),
          },
          ipLimitDecision.status,
        );
      }
    }

    // 5. Hash raw QR token and execute atomic PostgreSQL transaction
    const tokenHash = await sha256Hex(qrToken);

    const { data: rpcResult, error: rpcErr } = await adminClient.rpc(
      "process_attendance_check_in",
      {
        p_student_id: user.id,
        p_token_hash: tokenHash,
        p_latitude: latitude,
        p_longitude: longitude,
        p_accuracy_m: accuracy,
        p_idempotency_key: idempotencyKey,
        p_ip_hash: ipHash,
      },
    );

    if (rpcErr || !rpcResult) {
      return jsonResponse(req, { ok: false, error: "CHECK_IN_FAILED" }, 500);
    }

    if (rpcResult.ok !== true) {
      const code = typeof rpcResult.error_code === "string" ? rpcResult.error_code : "REJECTED";
      const status = code === "ACCOUNT_UNAVAILABLE" ? 403 : 400;
      return jsonResponse(req, { ok: false, error: code }, status);
    }

    return jsonResponse(req, {
      ok: true,
      attendance_date: rpcResult.attendance_date,
      checked_in_at: rpcResult.checked_in_at,
      status: rpcResult.status,
    });
  } catch {
    return jsonResponse(req, { ok: false, error: "INTERNAL_ERROR" }, 500);
  }
});
