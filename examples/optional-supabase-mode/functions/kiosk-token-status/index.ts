import { enforceCors, jsonResponse } from "../_shared/cors.ts";
import {
  decodeVerifiedJwtClaims,
  verifyKioskAuthorization,
} from "../_shared/securityGuards.ts";
import { authenticateRequestUser, createServiceClient } from "../_shared/supabaseAdmin.ts";

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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

    const body = await req.json().catch(() => null);
    const tokenId = typeof body?.token_id === "string" ? body.token_id.trim() : "";
    if (!UUID_REGEX.test(tokenId)) {
      return jsonResponse(req, { ok: false, error: "INVALID_TOKEN_ID" }, 400);
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
      .select("id, is_active, secret_hash, revoked_before")
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

    const { data: rpcResult, error: rpcErr } = await adminClient.rpc("get_kiosk_token_status", {
      p_kiosk_device_id: device.id,
      p_token_id: tokenId,
    });

    if (rpcErr || !rpcResult?.ok) {
      return jsonResponse(req, { ok: false, error: rpcResult?.error_code ?? "STATUS_ERROR" }, 400);
    }

    return jsonResponse(req, {
      ok: true,
      status: rpcResult.status,
      expires_at: rpcResult.expires_at,
      consumed_at: rpcResult.consumed_at,
      server_now: rpcResult.server_now,
    });
  } catch {
    return jsonResponse(req, { ok: false, error: "INTERNAL_ERROR" }, 500);
  }
});
