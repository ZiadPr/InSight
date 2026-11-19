export function isValidEmail(email: string): boolean {
  const trimmed = email.trim();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed) && trimmed.length <= 254;
}

export function isValidQrTokenFormat(token: string): boolean {
  const trimmed = token.trim();
  // Base64url random token (>= 20 chars, safe URL-safe characters only)
  return trimmed.length >= 20 && trimmed.length <= 512 && /^[A-Za-z0-9_-]+$/.test(trimmed);
}

export function normalizeManualAttendanceCode(input: string): string {
  return input.replace(/[\s-]+/g, "").toUpperCase();
}

export function isValidManualCodeFormat(code: string): boolean {
  const normalized = normalizeManualAttendanceCode(code.trim());
  return /^[A-Z0-9]{8}$/.test(normalized);
}

export function isValidQrOrManualInput(value: string): boolean {
  const trimmed = value.trim();
  return isValidQrTokenFormat(trimmed) || isValidManualCodeFormat(trimmed);
}

export function isValidGpsCoordinates(
  latitude: number,
  longitude: number,
  accuracy: number,
): boolean {
  return (
    Number.isFinite(latitude) &&
    Number.isFinite(longitude) &&
    Number.isFinite(accuracy) &&
    latitude >= -90 &&
    latitude <= 90 &&
    longitude >= -180 &&
    longitude <= 180 &&
    accuracy > 0
  );
}

/**
 * Neutralizes Excel/CSV formula injection for exported string cells.
 * Any value starting with =, +, -, @, tab, or carriage return is prefixed with an apostrophe.
 */
export function sanitizeSpreadsheetCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  const text = String(value);
  if (text.length === 0) return "";
  const first = text[0];
  if (first === "=" || first === "+" || first === "-" || first === "@" || first === "\t" || first === "\r") {
    return `'${text}`;
  }
  return text;
}

/**
 * Haversine distance in meters (mirror of server PostgreSQL function for testing/reference;
 * NEVER used as an authoritative security decision in the browser).
 */
export function calculateHaversineMeters(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number,
): number {
  const R = 6371000;
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(Math.max(0, 1 - a)));
  return R * c;
}
