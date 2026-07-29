// Memoized key material for `crypto.ts` (fix #6): the ES256 sign/verify key
// imports and the HS256 consent secret encoding, each cached by the stable
// (frozen) config / JWK reference so the source is not re-imported per request.
// Split out of `crypto.ts` to keep that file under the 250-line limit (§6).

import { importJWK } from "jose";
import type { JWK } from "jose";
import type { BridgeConfig } from "./config.ts";

// --- fix #6: memoized key imports (WeakMap keyed by the stable private-JWK ref) ---
// jose's importJWK returns CryptoKey | Uint8Array (CryptoKey for our EC keys). We
// infer it via the function's own return type rather than naming CryptoKey
// directly (that global's availability depends on the DOM lib / @types/node).
type ImportedKey = Awaited<ReturnType<typeof importJWK>>;

const signKeyCache = new WeakMap<JWK, Promise<ImportedKey>>();
const verifyKeyCache = new WeakMap<JWK, Promise<ImportedKey>>();

export function signKey(config: BridgeConfig): Promise<ImportedKey> {
  return cached(signKeyCache, config.signingPrivateJwk, () => importJWK(config.signingPrivateJwk, "ES256"));
}

export function verifyKey(config: BridgeConfig): Promise<ImportedKey> {
  return cached(verifyKeyCache, config.signingPrivateJwk, () => importJWK(publicJwk(config), "ES256"));
}

export function signingKeyId(config: BridgeConfig): string | undefined {
  const kid = config.signingPrivateJwk.kid;
  return config.signingKeyId ?? (typeof kid === "string" && kid ? kid : undefined);
}

export function publicJwk(config: BridgeConfig): JWK {
  const jwk = config.signingPrivateJwk;
  return {
    kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y,
    alg: "ES256", use: "sig", kid: signingKeyId(config),
  };
}

function cached(map: WeakMap<JWK, Promise<ImportedKey>>, jwk: JWK, load: () => Promise<ImportedKey>): Promise<ImportedKey> {
  let p = map.get(jwk);
  if (!p) {
    p = load();
    map.set(jwk, p);
  }
  return p;
}

// Same fix-#6 discipline for the HS256 consent key: encode once per (frozen) config.
const consentSecretCache = new WeakMap<BridgeConfig, Uint8Array>();
export function consentSecret(config: BridgeConfig): Uint8Array {
  let secret = consentSecretCache.get(config);
  if (!secret) {
    secret = new TextEncoder().encode(config.consentSigningSecret);
    consentSecretCache.set(config, secret);
  }
  return secret;
}
