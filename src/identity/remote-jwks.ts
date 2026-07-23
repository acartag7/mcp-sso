import { createRemoteJWKSet, customFetch, errors, jwksCache } from "jose";
import { ownDataValue, snapshotOwnDataArray, snapshotOwnDataRecord } from "../own-property.ts";
import { guardedGlobalFetch } from "../outbound-tls.ts";
import { captureHttpResponse } from "./util.ts";

type RemoteJwkSet = ReturnType<typeof createRemoteJWKSet>;
const PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"] as const;
const PUBLIC_JWK_STRING_FIELDS = [
  "kty", "kid", "alg", "use", "crv", "n", "e", "x", "y",
] as const;

/** Remote fetch and parse failures that prevent an identity decision. */
export function isRemoteJwksInfrastructureError(error: unknown): boolean {
  return error instanceof errors.JWKSTimeout
    || error instanceof errors.JWKSInvalid
    || (error instanceof errors.JOSEError && error.code === "ERR_JOSE_GENERIC");
}

/** Require the fetched JWKS cache to be an own-data JSON shape before a
 * selected key is returned to signature verification. */
export function createValidatedRemoteJWKSet(
  url: URL,
  options?: Parameters<typeof createRemoteJWKSet>[1],
): RemoteJwkSet {
  type FetchImplementation = NonNullable<NonNullable<typeof options>[typeof customFetch]>;
  const configuredFetch = ownDataValue(options, customFetch);
  if (configuredFetch !== undefined && typeof configuredFetch !== "function") {
    throw new TypeError("remote JWKS custom fetch must be a function");
  }
  if (ownDataValue(options, jwksCache) !== undefined) {
    throw new TypeError("validated remote JWKS does not accept an external cache");
  }
  const upstream = (configuredFetch as FetchImplementation | undefined)
    ?? guardedGlobalFetch as FetchImplementation;
  const guardedFetch: FetchImplementation = async (...args) => {
    const response = captureHttpResponse(await upstream(...args), "json");
    if (response === null) throw new errors.JWKSInvalid("JWKS response is malformed");
    return {
      status: response.status,
      async json() { return sanitizeJwks(await response.read()); },
    } as Response;
  };
  const remote = createRemoteJWKSet(url, {
    timeoutDuration: ownDataValue(options, "timeoutDuration") as number | undefined,
    cooldownDuration: ownDataValue(options, "cooldownDuration") as number | undefined,
    cacheMaxAge: ownDataValue(options, "cacheMaxAge") as number | undefined,
    headers: ownDataValue(options, "headers") as Record<string, string> | undefined,
    [customFetch]: guardedFetch,
    [jwksCache]: undefined,
  });
  const guarded = async (...args: Parameters<RemoteJwkSet>) => {
    const key = await remote(...args);
    assertOwnJwks(remote.jwks());
    return key;
  };
  Object.defineProperties(guarded, {
    coolingDown: { get: () => remote.coolingDown, enumerable: true },
    fresh: { get: () => remote.fresh, enumerable: true },
    reloading: { get: () => remote.reloading, enumerable: true },
    reload: { value: () => remote.reload(), enumerable: true },
    jwks: { value: () => remote.jwks(), enumerable: true },
  });
  return guarded as RemoteJwkSet;
}

function assertOwnJwks(value: unknown): void {
  const jwks = snapshotOwnDataRecord(value);
  const keys = jwks && snapshotOwnDataArray(jwks.keys);
  if (jwks === null || keys === null || keys.length === 0 || !keys.every(validOwnJwk)) {
    throw new errors.JWKSInvalid("JSON Web Key Set must contain own data properties");
  }
}

function sanitizeJwks(value: unknown): Readonly<Record<string, unknown>> {
  const jwks = snapshotOwnDataRecord(value);
  const keys = jwks && snapshotOwnDataArray(jwks.keys);
  if (jwks === null || keys === null || keys.length === 0) {
    throw new errors.JWKSInvalid("JSON Web Key Set must contain own data properties");
  }
  const safe = Object.create(null) as Record<string, unknown>;
  const safeKeys: Readonly<Record<string, unknown>>[] = [];
  for (let index = 0; index < keys.length; index += 1) {
    const key = sanitizeJwk(keys[index]);
    if (key !== null) safeKeys[safeKeys.length] = key;
  }
  if (safeKeys.length === 0) {
    throw new errors.JWKSInvalid("JSON Web Key Set must contain a supported public key");
  }
  safe.keys = Object.freeze(safeKeys);
  return Object.freeze(safe);
}

const SELECTOR_FIELDS = ["kty", "kid", "alg", "use", "key_ops", "crv"] as const;

/** Copy only public key material and jose's key-selection fields. Unknown JWK
 * extensions are ignored without traversing their values. */
function sanitizeJwk(value: unknown): Readonly<Record<string, unknown>> | null {
  const jwk = snapshotOwnDataRecord(value);
  if (jwk === null) throw new errors.JWKSInvalid("JSON Web Key Set members must be data objects");
  const safe = Object.create(null) as Record<string, unknown>;
  for (const field of PRIVATE_JWK_FIELDS) {
    if (Object.hasOwn(jwk, field)) {
      throw new errors.JWKSInvalid("JSON Web Key Set members must be public keys");
    }
  }
  if (jwk.kty !== "RSA" && jwk.kty !== "EC") return null;
  for (const field of PUBLIC_JWK_STRING_FIELDS) {
    if (Object.hasOwn(jwk, field)) {
      if (typeof jwk[field] !== "string") {
        throw new errors.JWKSInvalid("JWK public members must be strings");
      }
      safe[field] = jwk[field];
    }
  }
  if (Object.hasOwn(jwk, "key_ops")) {
    const operations = snapshotOwnDataArray(jwk.key_ops);
    if (operations === null || !operations.every((item) => typeof item === "string")) {
      throw new errors.JWKSInvalid("JWK key_ops must be an array of strings");
    }
    safe.key_ops = Object.freeze([...operations]);
  }
  assertOwnPublicKeyMaterial(safe);
  for (const field of SELECTOR_FIELDS) {
    if (!Object.hasOwn(safe, field)) safe[field] = undefined;
  }
  return Object.freeze(safe);
}

function assertOwnPublicKeyMaterial(jwk: Readonly<Record<string, unknown>>): void {
  const required = jwk.kty === "RSA"
    ? ["n", "e"] as const
    : jwk.kty === "EC"
      ? ["crv", "x", "y"] as const
      : null;
  if (required === null || !required.every((field) =>
    Object.hasOwn(jwk, field) && typeof jwk[field] === "string" && jwk[field] !== "")) {
    throw new errors.JWKSInvalid("JWK must contain own public key material");
  }
}

function validOwnJwk(value: unknown): boolean {
  const jwk = snapshotOwnDataRecord(value);
  if (jwk === null) return false;
  if (jwk.key_ops !== undefined) {
    const operations = snapshotOwnDataArray(jwk.key_ops);
    if (operations === null || !operations.every((item) => typeof item === "string")) return false;
  }
  return true;
}
