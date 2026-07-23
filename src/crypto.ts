// Crypto & token contracts (§7). Algorithm pinning is non-negotiable: consent
// tokens are HS256, access tokens are ES256 (EC P-256); verifiers pin the alg set.
// Consent and access keys are separate. Fix #6: the imported verification/signing
// key is memoized (the source re-imported per request).

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { SignJWT, importJWK, jwtVerify } from "jose";
import type { JWK, JWTPayload } from "jose";
import type { ClockPort } from "./ports/clock.ts";
import { assertBridgeConfig, type BridgeConfig } from "./config.ts";
import { assertAllowedScopesCeiling, scopeString } from "./scopes.ts";
import { OAuthError } from "./errors.ts";
import { ownBooleanTrue, snapshotOwnDataRecord } from "./own-property.ts";
import {
  accessClaims, audienceMatches, consentClaims, CONSENT_TYP, requiredString, stringClaim,
} from "./crypto-claims.ts";

const CONSENT_AUDIENCE = "mcp-sso/consent";
const CODE_PREFIX = "ac";
const REFRESH_PREFIX = "rt";

export interface ConsentRequestClaims {
  clientId: string;
  redirectUri: string;
  resource: string;
  scopes: string[];
  codeChallenge: string;
  codeChallengeMethod: "S256";
  state?: string;
  /** Verified subject (resolved by the IdentityPort before prepare()). */
  subject: string;
  /** Authorization ceiling (contracts §17.4). Carried in the consent JWT as the
   *  `allowed_scopes` claim so `approve` re-intersects from the VERIFIED token,
   *  not from client-resupplied input. Undefined when the identity port set no
   *  ceiling (old behavior: no narrowing). */
  allowedScopes?: string[];
}

export interface AccessTokenClaims {
  subject: string;
  clientId: string;
  scopes: string[]; machine?: boolean; // client_credentials grant ⇒ mints the gty marker claim (§17.2)
}

export interface VerifiedAccessToken {
  subject: string;
  clientId: string;
  scopes: string[];
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function generateAuthorizationCode(): string {
  return `${CODE_PREFIX}_${base64url(randomBytes(32))}`;
}

export function generateRefreshFamilyId(): string {
  return base64url(randomBytes(18));
}

/** Single-use id minted into each consent token; consumed on approve (§7.1). */
export function generateConsentJti(): string {
  return base64url(randomBytes(18));
}

export function generateRefreshToken(familyId: string = generateRefreshFamilyId()): string {
  return `${REFRESH_PREFIX}.${familyId}.${base64url(randomBytes(32))}`;
}

export function parseRefreshFamilyId(refreshToken: string): string | null {
  const parts = refreshToken.split(".");
  if (parts.length !== 3 || parts[0] !== REFRESH_PREFIX) return null;
  const family = parts[1];
  return family && /^[A-Za-z0-9_-]{16,}$/.test(family) ? family : null;
}

/** RFC 7636 PKCE S256, timing-safe. Malformed inputs are rejected outright — a
 *  1-char verifier can never match a stored challenge. */
export function verifyPkceS256(verifier: string, challenge: string): boolean {
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return false;
  if (!/^[A-Za-z0-9_-]{43}$/.test(challenge)) return false;
  const actual = pkceChallenge(verifier);
  const left = Buffer.from(actual);
  const right = Buffer.from(challenge);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function pkceChallenge(verifier: string): string {
  return base64url(createHash("sha256").update(verifier).digest());
}

export async function signConsentToken(claims: ConsentRequestClaims, config: BridgeConfig, clock: ClockPort): Promise<string> {
  assertBridgeConfig(config);
  const claimSnapshot = snapshotOwnDataRecord(claims);
  if (claimSnapshot === null) throw new Error("consent claims must be a data object");
  const safeClaims = claimSnapshot as unknown as ConsentRequestClaims;
  const allowedScopes = assertAllowedScopesCeiling(safeClaims.allowedScopes);
  const now = nowSeconds(clock);
  return await new SignJWT({
    typ: CONSENT_TYP,
    jti: generateConsentJti(),
    client_id: safeClaims.clientId,
    redirect_uri: safeClaims.redirectUri,
    resource: safeClaims.resource,
    scope: scopeString(safeClaims.scopes),
    code_challenge: safeClaims.codeChallenge,
    code_challenge_method: safeClaims.codeChallengeMethod,
    state: safeClaims.state,
    allowed_scopes: allowedScopes === undefined ? undefined : scopeString(allowedScopes),
  }).setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(config.issuer)
    .setAudience(CONSENT_AUDIENCE)
    .setSubject(safeClaims.subject)
    .setIssuedAt(now)
    .setExpirationTime(now + config.consentTokenTtlSeconds)
    .sign(consentSecret(config));
}

export async function verifyConsentToken(token: string, config: BridgeConfig, clock: ClockPort): Promise<ConsentRequestClaims & { jti: string }> {
  assertBridgeConfig(config);
  try {
    const { payload } = await jwtVerify(token, consentSecret(config), {
      algorithms: ["HS256"],
      issuer: config.issuer,
      audience: CONSENT_AUDIENCE,
      currentDate: new Date(clock.nowMs()),
    });
    const snapshot = snapshotOwnDataRecord(payload);
    if (snapshot === null) throw new Error("invalid consent claims");
    const claims = snapshot as JWTPayload;
    if (claims.iss !== config.issuer || !audienceMatches(claims.aud, CONSENT_AUDIENCE)
      || typeof claims.exp !== "number") throw new Error("invalid consent trust claims");
    return { ...consentClaims(claims), jti: requiredString(claims.jti, "jti") };
  } catch {
    throw new OAuthError("invalid_consent", "Consent token is invalid or expired");
  }
}

export async function signAccessToken(claims: AccessTokenClaims, config: BridgeConfig, clock: ClockPort): Promise<string> {
  assertBridgeConfig(config);
  const claimSnapshot = snapshotOwnDataRecord(claims);
  if (claimSnapshot === null) throw new Error("access-token claims must be a data object");
  const safeClaims = claimSnapshot as unknown as AccessTokenClaims;
  const now = nowSeconds(clock);
  const key = await signKey(config);
  return await new SignJWT({ client_id: safeClaims.clientId, scope: scopeString(safeClaims.scopes),
    ...(ownBooleanTrue(safeClaims, "machine") ? { gty: "client_credentials" } : {}) })
    .setProtectedHeader({ alg: "ES256", kid: keyId(config), typ: "JWT" })
    .setIssuer(config.issuer)
    .setSubject(safeClaims.subject)
    .setAudience(config.resource)
    .setIssuedAt(now)
    .setExpirationTime(now + config.accessTokenTtlSeconds)
    .sign(key);
}

export async function verifyAccessToken(token: string, config: BridgeConfig, clock: ClockPort): Promise<VerifiedAccessToken> {
  assertBridgeConfig(config);
  try {
    const key = await verifyKey(config);
    const { payload } = await jwtVerify(token, key, {
      algorithms: ["ES256"],
      issuer: config.issuer,
      audience: config.resource,
      currentDate: new Date(clock.nowMs()),
    });
    const snapshot = snapshotOwnDataRecord(payload);
    if (snapshot === null) throw new Error("invalid access-token claims");
    const payloadClaims = snapshot as JWTPayload;
    if (payloadClaims.iss !== config.issuer || !audienceMatches(payloadClaims.aud, config.resource)
      || typeof payloadClaims.exp !== "number") throw new Error("invalid access-token trust claims");
    const claims = accessClaims(payloadClaims);
    if (claims.subject.startsWith("mcc_") && !(claims.clientId === claims.subject && payloadClaims.gty === "client_credentials")) throw new Error("reserved-namespace sub without machine binding"); // machine tokens carry sub===client_id AND the gty marker (§17.2); anything else = pre-guard masquerade
    return claims;
  } catch {
    throw new OAuthError("invalid_token", "Bearer token is invalid", 401);
  }
}

export function publicJwk(config: BridgeConfig): JWK {
  assertBridgeConfig(config);
  const jwk = config.signingPrivateJwk;
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, alg: "ES256", use: "sig", kid: keyId(config) };
}

export function expiresAtIso(clock: ClockPort, ttlSeconds: number): string {
  return new Date(clock.nowMs() + ttlSeconds * 1000).toISOString();
}

// --- fix #6: memoized key imports (WeakMap keyed by the stable private-JWK ref) ---
// jose's importJWK returns CryptoKey | Uint8Array (CryptoKey for our EC keys). We
// infer it via the function's own return type rather than naming CryptoKey
// directly (that global's availability depends on the DOM lib / @types/node).
type ImportedKey = Awaited<ReturnType<typeof importJWK>>;

const signKeyCache = new WeakMap<JWK, Promise<ImportedKey>>();
const verifyKeyCache = new WeakMap<JWK, Promise<ImportedKey>>();

function signKey(config: BridgeConfig): Promise<ImportedKey> {
  return cached(signKeyCache, config.signingPrivateJwk, () => importJWK(config.signingPrivateJwk, "ES256"));
}

function verifyKey(config: BridgeConfig): Promise<ImportedKey> {
  return cached(verifyKeyCache, config.signingPrivateJwk, () => importJWK(publicJwk(config), "ES256"));
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
function consentSecret(config: BridgeConfig): Uint8Array {
  let secret = consentSecretCache.get(config);
  if (!secret) {
    secret = new TextEncoder().encode(config.consentSigningSecret);
    consentSecretCache.set(config, secret);
  }
  return secret;
}

function keyId(config: BridgeConfig): string | undefined {
  return config.signingKeyId ?? stringClaim(config.signingPrivateJwk.kid);
}

function nowSeconds(clock: ClockPort): number {
  return Math.floor(clock.nowMs() / 1000);
}

function base64url(bytes: Buffer): string {
  return bytes.toString("base64url");
}
