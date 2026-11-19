import crypto from "node:crypto";
import { PostgresConnection } from "./postgresConnection.js";

export async function checkPersistentRateLimit(key: string, maximum: number, windowMs: number, blockMs: number, connection = new PostgresConnection(), now = Date.now()): Promise<{ allowed: true } | { allowed: false; retryAfterSeconds: number }> {
  const keyHash = crypto.createHash("sha256").update(key).digest("hex");
  const row = await connection.prepare(`
    INSERT INTO rate_limits (key, attempts, window_start, blocked_until)
    VALUES (@key, 1, @now::bigint, 0)
    ON CONFLICT(key) DO UPDATE SET
      attempts = CASE
        WHEN rate_limits.blocked_until > @now::bigint THEN rate_limits.attempts
        WHEN @now::bigint - rate_limits.window_start >= @window::bigint THEN 1
        ELSE rate_limits.attempts + 1 END,
      window_start = CASE
        WHEN rate_limits.blocked_until <= @now::bigint AND @now::bigint - rate_limits.window_start >= @window::bigint THEN @now::bigint
        ELSE rate_limits.window_start END,
      blocked_until = CASE
        WHEN rate_limits.blocked_until > @now::bigint THEN rate_limits.blocked_until
        WHEN @now::bigint - rate_limits.window_start >= @window::bigint THEN 0
        WHEN rate_limits.attempts + 1 > @maximum::integer THEN @now::bigint + @block::bigint
        ELSE 0 END
    RETURNING blocked_until
  `).get({ key: keyHash, now, window: windowMs, maximum, block: blockMs });
  const blockedUntil = Number(row.blocked_until);
  return blockedUntil > now
    ? { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((blockedUntil-now)/1000)) }
    : { allowed: true };
}

export async function resetPersistentRateLimit(key: string, connection = new PostgresConnection()): Promise<void> {
  const keyHash = crypto.createHash("sha256").update(key).digest("hex");
  await connection.prepare("DELETE FROM rate_limits WHERE key = ?").run(keyHash);
}
