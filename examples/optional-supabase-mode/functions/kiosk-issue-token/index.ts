import { enforceCors, jsonResponse } from "../_shared/cors.ts";
import { generateSecureToken, sha256Hex } from "../_shared/crypto.ts";
import {
  decodeVerifiedJwtClaims,
  verifyKioskAuthorization,
} from "../_shared/securityGuards.ts";
import { authenticateRequestUser, createServiceClient } from "../_shared/supabaseAdmin.ts";

Deno.serve(async (req: Request) => {
  const corsBlock = enforceCors(req);
  if (corsBlock) return corsBlock;

  if (req.method !== "POST") {
    return jsonResponse(req, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    const { user, jwt, error: authError } = await authenticateRequestUser(req);
    if (authError || !user || !jwt) {
      return jsonResponse(req, { ok: false, error: "UNAUTHORIZED" }, 401);
    }

    const adminClient = createServiceClient();

    const { data: profile, error: profileErr } = await adminClient
      .from("profiles")
      .select("role, is_active")
      .eq("id", user.id)
      .single();

    if (profileErr || !profile || profile.role !== "kiosk" || profile.is_active !== true) {
      return jsonResponse(req, { ok: false, error: "FORBIDDEN" }, 403);
    }

    const { data: device, error: deviceErr } = await adminClient
      .from("kiosk_devices")
      .select("id, device_name, is_active, secret_hash, revoked_before")
      .eq("auth_user_id", user.id)
      .single();

    if (deviceErr || !device) {
      return jsonResponse(req, { ok: false, error: "KIOSK_NOT_AUTHORIZED" }, 403);
    }

    const claims = decodeVerifiedJwtClaims(jwt);
    const authCheck = await verifyKioskAuthorization({
      device,
      providedSecret: req.headers.get("x-kiosk-secret") ?? "",
      deviceSecretSalt: Deno.env.get("KIOSK_DEVICE_SECRET_SALT"),
      jwtIssuedAtSec: claims?.iat,
    });

    if (!authCheck.ok) {
      return jsonResponse(req, { ok: false, error: authCheck.error }, authCheck.status);
    }

    const rawToken = generateSecureToken(32);
    const tokenHash = await sha256Hex(rawToken);

    const { data: rpcResult, error: rpcErr } = await adminClient.rpc("issue_kiosk_qr_token", {
      p_kiosk_device_id: device.id,
      p_token_hash: tokenHash,
    });

    if (rpcErr || !rpcResult?.ok) {
      return jsonResponse(req, { ok: false, error: rpcResult?.error_code ?? "ISSUE_FAILED" }, 400);
    }

    return jsonResponse(req, {
      ok: true,
      token: rawToken,
      token_id: rpcResult.token_id,
      issued_at: rpcResult.issued_at,
      expires_at: rpcResult.expires_at,
      ttl_seconds: rpcResult.ttl_seconds,
      campus_name: rpcResult.campus_name,
      device_name: device.device_name,
    });
  } catch {
    return jsonResponse(req, { ok: false, error: "INTERNAL_ERROR" }, 500);
  }
});
