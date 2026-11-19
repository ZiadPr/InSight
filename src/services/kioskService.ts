import { secureFetchJson } from "../lib/secureTransport";
import type { KioskTokenResponse, KioskTokenStatusResponse } from "../types/attendance";

export async function issueKioskToken(
  deviceSecret?: string,
): Promise<KioskTokenResponse> {
  try {
    const headers: Record<string, string> = {};
    if (deviceSecret && deviceSecret.trim().length > 0) {
      headers["x-kiosk-secret"] = deviceSecret.trim();
    }

    const res = await secureFetchJson<KioskTokenResponse>("/api/kiosk/issue-token", {
      method: "POST",
      headers,
      body: {},
    });

    if (!res.data) {
      return { ok: false, error: "NETWORK_ERROR" };
    }
    return res.data;
  } catch {
    return { ok: false, error: "NETWORK_ERROR" };
  }
}

export async function getKioskTokenStatus(
  tokenId: string,
  deviceSecret?: string,
): Promise<KioskTokenStatusResponse> {
  try {
    const headers: Record<string, string> = {};
    if (deviceSecret && deviceSecret.trim().length > 0) {
      headers["x-kiosk-secret"] = deviceSecret.trim();
    }

    const res = await secureFetchJson<KioskTokenStatusResponse>("/api/kiosk/token-status", {
      method: "POST",
      headers,
      body: { token_id: tokenId },
    });

    if (!res.data) {
      return { ok: false, error: "NETWORK_ERROR" };
    }
    return res.data;
  } catch {
    return { ok: false, error: "NETWORK_ERROR" };
  }
}
