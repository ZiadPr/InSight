import { evaluateCorsOrigin } from "./securityGuards.ts";

export function getCorsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin");
  const decision = evaluateCorsOrigin(origin, Deno.env.get("ALLOWED_ORIGINS"));

  const headers: Record<string, string> = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "authorization, x-client-info, apikey, content-type, x-kiosk-secret",
    "Vary": "Origin",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
  };

  if (decision.allowed && decision.allowOrigin) {
    headers["Access-Control-Allow-Origin"] = decision.allowOrigin;
  }

  return headers;
}

export function enforceCors(req: Request): Response | null {
  const origin = req.headers.get("Origin");
  const decision = evaluateCorsOrigin(origin, Deno.env.get("ALLOWED_ORIGINS"));

  if (!decision.allowed) {
    return new Response(JSON.stringify({ ok: false, error: "ORIGIN_NOT_ALLOWED" }), {
      status: 403,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Vary": "Origin",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
      },
    });
  }

  if (req.method === "OPTIONS") {
    return new Response("ok", {
      status: 200,
      headers: getCorsHeaders(req),
    });
  }

  return null;
}

export function jsonResponse(
  req: Request,
  body: Record<string, unknown>,
  status = 200,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...getCorsHeaders(req),
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}
