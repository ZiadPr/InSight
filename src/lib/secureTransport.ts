import { authHeaders } from "./authStorage";

interface EncryptedEnvelope {
  encrypted: true;
  alg: "AES-256-GCM";
  iv: string;
  tag: string;
  ciphertext: string;
}

interface ActiveChannel {
  channelId: string;
  aesKey: CryptoKey;
  expiresAtMs: number;
}

export class SecureTransportError extends Error {
  readonly code: string;
  readonly status?: number;

  constructor(code: string, status?: number) {
    super(code);
    this.name = "SecureTransportError";
    this.code = code;
    this.status = status;
  }
}

let activeChannel: ActiveChannel | null = null;
let handshakeInFlight: Promise<ActiveChannel> | null = null;
let adminStepUpToken: string | null = null;
let adminStepUpExpiresAtMs = 0;
let pinnedServerSigningKeyBase64: string | null = null;

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function encodeUtf8(value: string): ArrayBuffer {
  return toArrayBuffer(new TextEncoder().encode(value));
}

function isEncryptedEnvelope(value: unknown): value is EncryptedEnvelope {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    v.encrypted === true &&
    v.alg === "AES-256-GCM" &&
    typeof v.iv === "string" &&
    typeof v.tag === "string" &&
    typeof v.ciphertext === "string"
  );
}

export function setAdminStepUpToken(token: string, expiresAtIso: string): void {
  adminStepUpToken = token;
  const parsed = Date.parse(expiresAtIso);
  adminStepUpExpiresAtMs = Number.isFinite(parsed) ? parsed : Date.now() + 15 * 60_000;
}

export function clearAdminStepUpToken(): void {
  adminStepUpToken = null;
  adminStepUpExpiresAtMs = 0;
}

export function getAdminStepUpRemainingMs(): number {
  if (!adminStepUpToken) return 0;
  return Math.max(0, adminStepUpExpiresAtMs - Date.now());
}

export function hasActiveAdminStepUp(): boolean {
  return Boolean(adminStepUpToken) && Date.now() < adminStepUpExpiresAtMs - 3_000;
}

export function resetSecureTransport(): void {
  activeChannel = null;
  handshakeInFlight = null;
  clearAdminStepUpToken();
}

/**
 * Complements mandatory HTTPS/TLS transport with an authenticated ephemeral
 * ECDH P-256 + ECDSA P-256 signed key exchange and AES-256-GCM payload envelope.
 */
async function performHandshake(): Promise<ActiveChannel> {
  if (typeof globalThis.crypto?.subtle === "undefined") {
    throw new SecureTransportError("WEBCRYPTO_UNAVAILABLE");
  }

  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const spkiBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const clientPublicKey = toBase64Url(new Uint8Array(spkiBuffer));

  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const clientNonce = toBase64Url(nonceBytes);

  let res: Response;
  try {
    res = await fetch("/api/security/handshake", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_public_key: clientPublicKey,
        client_nonce: clientNonce,
      }),
    });
  } catch {
    throw new SecureTransportError("TRANSPORT_NETWORK_ERROR");
  }

  const data = (await res.json().catch(() => null)) as {
    ok?: boolean;
    error?: string;
    channel_id?: string;
    server_public_key?: string;
    expires_at?: string;
    signing_public_key?: string;
    signature?: string;
  } | null;

  if (!res.ok) {
    throw new SecureTransportError(data?.error || `SECURE_HANDSHAKE_HTTP_${res.status}`, res.status);
  }

  if (
    !data ||
    !data.ok ||
    !data.channel_id ||
    !data.server_public_key ||
    !data.expires_at ||
    !data.signing_public_key ||
    !data.signature
  ) {
    throw new SecureTransportError("SECURE_HANDSHAKE_FAILED", res.status);
  }

  // Enforce pinning of the server's ECDSA P-256 identity key within this session
  if (pinnedServerSigningKeyBase64 && pinnedServerSigningKeyBase64 !== data.signing_public_key) {
    throw new Error("SERVER_KEY_MISMATCH");
  }

  const signingPubKey = await crypto.subtle.importKey(
    "spki",
    toArrayBuffer(fromBase64Url(data.signing_public_key)),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );

  const transcript = `${data.channel_id}|${data.server_public_key}|${clientPublicKey}|${clientNonce}|${data.expires_at}`;
  const sigVerified = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    signingPubKey,
    toArrayBuffer(fromBase64Url(data.signature)),
    encodeUtf8(transcript),
  );
  if (!sigVerified) {
    throw new Error("HANDSHAKE_SIGNATURE_INVALID");
  }
  pinnedServerSigningKeyBase64 = data.signing_public_key;

  const serverPubBytes = fromBase64Url(data.server_public_key);
  const serverPublicKey = await crypto.subtle.importKey(
    "spki",
    toArrayBuffer(serverPubBytes),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPublicKey },
    keyPair.privateKey,
    256,
  );

  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encodeUtf8(`${clientNonce}:${data.channel_id}`),
      info: encodeUtf8("insight-e2ee-v1"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  const channel: ActiveChannel = {
    channelId: data.channel_id,
    aesKey,
    expiresAtMs: Date.parse(data.expires_at) || Date.now() + 14 * 60_000,
  };
  activeChannel = channel;
  return channel;
}

async function getOrCreateChannel(forceRefresh = false): Promise<ActiveChannel> {
  if (!forceRefresh && activeChannel && Date.now() < activeChannel.expiresAtMs - 15_000) {
    return activeChannel;
  }
  if (!handshakeInFlight || forceRefresh) {
    handshakeInFlight = performHandshake().finally(() => {
      handshakeInFlight = null;
    });
  }
  return handshakeInFlight;
}

async function encryptBody(
  channel: ActiveChannel,
  method: string,
  pathname: string,
  payload: unknown,
): Promise<EncryptedEnvelope> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const aad = encodeUtf8(`${channel.channelId}:${method.toUpperCase()}:${pathname}`);
  const encoded = encodeUtf8(JSON.stringify(payload));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: aad },
      channel.aesKey,
      encoded,
    ),
  );
  const ciphertext = sealed.slice(0, sealed.length - 16);
  const tag = sealed.slice(sealed.length - 16);
  return {
    encrypted: true,
    alg: "AES-256-GCM",
    iv: toBase64Url(iv),
    tag: toBase64Url(tag),
    ciphertext: toBase64Url(ciphertext),
  };
}

async function decryptEnvelope<T>(
  channel: ActiveChannel,
  method: string,
  pathname: string,
  envelope: EncryptedEnvelope,
): Promise<T> {
  const iv = fromBase64Url(envelope.iv);
  const ct = fromBase64Url(envelope.ciphertext);
  const tag = fromBase64Url(envelope.tag);
  const combined = new Uint8Array(ct.length + tag.length);
  combined.set(ct, 0);
  combined.set(tag, ct.length);

  const aad = encodeUtf8(`${channel.channelId}:${method.toUpperCase()}:${pathname}`);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: aad },
    channel.aesKey,
    toArrayBuffer(combined),
  );
  const text = new TextDecoder().decode(decrypted);
  return JSON.parse(text) as T;
}

export interface SecureFetchOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  includeStepUp?: boolean;
}

export async function secureFetchJson<T>(
  url: string,
  options: SecureFetchOptions = {},
): Promise<{ status: number; ok: boolean; data: T | null }> {
  const method = (options.method ?? "GET").toUpperCase();
  const pathname = new URL(url, window.location.origin).pathname;

  const execute = async (forceNewChannel: boolean): Promise<{ status: number; ok: boolean; data: T | null; retryHandshake: boolean }> => {
    const channel = await getOrCreateChannel(forceNewChannel);
    const headers: Record<string, string> = {
      ...authHeaders(),
      ...(options.headers ?? {}),
      "X-Sec-Channel": channel.channelId,
    };

    if (options.includeStepUp && adminStepUpToken) {
      headers["X-Admin-StepUp"] = adminStepUpToken;
    }

    let requestBody: string | undefined;
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      const envelope = await encryptBody(channel, method, pathname, options.body);
      requestBody = JSON.stringify(envelope);
    }

    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers,
        body: requestBody,
      });
    } catch {
      throw new SecureTransportError("TRANSPORT_NETWORK_ERROR");
    }

    const rawJson = (await res.json().catch(() => null)) as unknown;
    let parsed: T | null = null;
    if (isEncryptedEnvelope(rawJson)) {
      parsed = await decryptEnvelope<T>(channel, method, pathname, rawJson);
    } else {
      parsed = rawJson as T | null;
    }

    const errCode = (parsed as { error?: string } | null)?.error;
    const retryHandshake =
      !forceNewChannel &&
      (res.status === 428 ||
        errCode === "ENCRYPTED_CHANNEL_REQUIRED" ||
        errCode === "ENCRYPTED_CHANNEL_EXPIRED");

    if (errCode === "ADMIN_STEP_UP_REQUIRED") {
      clearAdminStepUpToken();
    }

    return { status: res.status, ok: res.ok, data: parsed, retryHandshake };
  };

  const first = await execute(false);
  if (first.retryHandshake) {
    const second = await execute(true);
    return { status: second.status, ok: second.ok, data: second.data };
  }
  return { status: first.status, ok: first.ok, data: first.data };
}
