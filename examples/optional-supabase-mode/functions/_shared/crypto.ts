import {
  constantTimeEqualStr,
  requireStrongSalt,
  sha256HexWeb,
} from "./securityGuards.ts";

export function generateSecureToken(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export const sha256Hex = sha256HexWeb;
export const constantTimeEqual = constantTimeEqualStr;

export async function extractIpHash(req: Request): Promise<string | null> {
  const salt = requireStrongSalt(Deno.env.get("IP_HASH_SALT"), "IP_HASH_SALT");
  const forwarded =
    req.headers.get("x-forwarded-for") ?? req.headers.get("cf-connecting-ip") ?? "";
  const ip = forwarded.split(",")[0]?.trim();
  if (!ip) return null;
  return await sha256Hex(`${salt}:${ip}`);
}

export function sanitizeExcelCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  const str = String(value);
  if (str.length === 0) return "";
  const firstChar = str[0];
  if (
    firstChar === "=" ||
    firstChar === "+" ||
    firstChar === "-" ||
    firstChar === "@" ||
    firstChar === "\t" ||
    firstChar === "\r"
  ) {
    return `'${str}`;
  }
  return str;
}
