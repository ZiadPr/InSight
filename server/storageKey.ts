import crypto from "node:crypto";

/** Resolve a stable server-only key without relying on an ephemeral local file. */
export function resolveHostedStorageKey(encryptionKey: string | undefined, bootstrapPassword: string | undefined): Buffer {
  const configured = encryptionKey?.trim();
  if (configured) {
    if (!/^[0-9a-fA-F]{64}$/.test(configured)) throw new Error("DATA_ENCRYPTION_KEY must contain 64 hexadecimal characters.");
    return Buffer.from(configured, "hex");
  }
  if (!bootstrapPassword || bootstrapPassword.length < 12 || bootstrapPassword.length > 128 || !/[A-Za-z]/.test(bootstrapPassword) || !/\d/.test(bootstrapPassword)) {
    throw new Error("Configure a strong administrator bootstrap password before starting the server.");
  }
  // The bootstrap environment secret is retained even after account passwords
  // change through the UI. A separate salt keeps this key independent of login hashes.
  return crypto.scryptSync(bootstrapPassword, "insight-storage-key-v1", 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}
