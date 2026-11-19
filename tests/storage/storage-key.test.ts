import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { resolveHostedStorageKey } from "../../server/storageKey.ts";

test("Hosted encryption keys remain stable across restarts without local files", () => {
  const bootstrap = crypto.randomBytes(24).toString("base64url") + "A1";
  const first = resolveHostedStorageKey(undefined, bootstrap);
  const second = resolveHostedStorageKey(undefined, bootstrap);
  assert.equal(first.length, 32);
  assert.ok(first.equals(second));
  assert.ok(!first.equals(resolveHostedStorageKey(undefined, bootstrap + "2")));
});

test("A dedicated key takes precedence and invalid key material fails closed", () => {
  const dedicated = crypto.randomBytes(32);
  const resolved = resolveHostedStorageKey(dedicated.toString("hex"), undefined);
  assert.ok(resolved.equals(dedicated));
  assert.throws(() => resolveHostedStorageKey("invalid", undefined), /64 hexadecimal/);
  assert.throws(() => resolveHostedStorageKey(undefined, undefined), /bootstrap password/);
  assert.throws(() => resolveHostedStorageKey(undefined, "weak"), /bootstrap password/);
});
