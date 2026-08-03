// Crypto & token contracts (§7). Algorithm pinning is non-negotiable: consent
// tokens are HS256, access tokens are ES256 (EC P-256); verifiers pin the alg set.
// Consent and access keys are separate. Fix #6: the imported verification/signing
// key is memoized (the source re-imported per request).

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { SignJWT, importJWK, jwtVerify } from "jose";
import type { JWK, JWTPayload } from "jose";
import { finiteClockSnapshot, type ClockPort } from "./ports/clock.ts";
import type { BridgeConfig } from "./config.ts";
import { scopeString, type CredentialKind } from "./scopes.ts";
import { OAuthError } from "./errors.ts";
import { consentSecret, signKey, verifyKey } from "./crypto-keys.ts";

const CONSENT_AUDIENCE = "mcp-sso/consent";
const CONSENT_TYP = "mcp-sso-consent";
export const MAX_CONSENT_TOKEN_BYTES = 192 * 1024;
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
  /** CIMD provenance for the CURRENT flow (§17.1.6 decision 3): minted as
   *  `cimd_verified: true` ONLY when `prepare` established the registration by
   *  genuine validation this flow. OMITTED when absent/false — never
   *  `cimd_verified: false`. It is NEVER a scope-accumulation entitlement. */
  cimdVerified?: true;
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
  credentialKind: CredentialKind;
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
  const now = nowSeconds(clock);
  const token = await new SignJWT({
    typ: CONSENT_TYP,
    jti: generateConsentJti(),
    client_id: claims.clientId,
    redirect_uri: claims.redirectUri,
    resource: claims.resource,
    scope: scopeString(claims.scopes),
    code_challenge: claims.codeChallenge,
    code_challenge_method: claims.codeChallengeMethod,
    state: claims.state,
    allowed_scopes: claims.allowedScopes === undefined ? undefined : scopeString(claims.allowedScopes),
    ...(claims.cimdVerified === true ? { cimd_verified: true } : {}),
  }).setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(config.issuer)
    .setAudience(CONSENT_AUDIENCE)
    .setSubject(claims.subject)
    .setIssuedAt(now)
    .setExpirationTime(now + config.consentTokenTtlSeconds)
    .sign(consentSecret(config));
  if (Buffer.byteLength(token, "utf8") > MAX_CONSENT_TOKEN_BYTES) {
    throw new OAuthError("invalid_request", "Authorization request is too large");
  }
  return token;
}

export async function verifyConsentToken(token: string, config: BridgeConfig, clock: ClockPort): Promise<ConsentRequestClaims & { jti: string }> {
  try {
    const nowMs = finiteClockSnapshot(clock);
    const { payload } = await jwtVerify(token, consentSecret(config), {
      algorithms: ["HS256"],
      issuer: config.issuer,
      audience: CONSENT_AUDIENCE,
      currentDate: new Date(nowMs),
    });
    return { ...consentClaims(payload), jti: requiredString(payload.jti, "jti") };
  } catch {
    throw new OAuthError("invalid_consent", "Consent token is invalid or expired");
  }
}

export async function signAccessToken(claims: AccessTokenClaims, config: BridgeConfig, clock: ClockPort): Promise<string> {
  const now = nowSeconds(clock);
  const key = await signKey(config);
  return await new SignJWT({ client_id: claims.clientId, scope: scopeString(claims.scopes), ...(claims.machine ? { gty: "client_credentials" } : {}) })
    .setProtectedHeader({ alg: "ES256", kid: keyId(config), typ: "JWT" })
    .setIssuer(config.issuer)
    .setSubject(claims.subject)
    .setAudience(config.resource)
    .setIssuedAt(now)
    .setExpirationTime(now + config.accessTokenTtlSeconds)
    .sign(key);
}

export async function verifyAccessToken(token: string, config: BridgeConfig, clock: ClockPort): Promise<VerifiedAccessToken> {
  try {
    const nowMs = finiteClockSnapshot(clock);
    const key = await verifyKey(config);
    const { payload } = await jwtVerify(token, key, {
      algorithms: ["ES256"],
      issuer: config.issuer,
      audience: config.resource,
      currentDate: new Date(nowMs),
    });
    return accessClaims(payload);
  } catch {
    throw new OAuthError("invalid_token", "Bearer token is invalid", 401);
  }
}

export function publicJwk(config: BridgeConfig): JWK {
  const jwk = config.signingPrivateJwk;
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, alg: "ES256", use: "sig", kid: keyId(config) };
}

export function expiresAtIso(clock: ClockPort, ttlSeconds: number): string {
  return new Date(clock.nowMs() + ttlSeconds * 1000).toISOString();
}

function keyId(config: BridgeConfig): string | undefined {
  return config.signingKeyId ?? stringClaim(config.signingPrivateJwk.kid);
}

function consentClaims(payload: JWTPayload): ConsentRequestClaims {
  if (payload.typ !== CONSENT_TYP) throw new Error("wrong token type");
  const scopes = payload.scope === "" ? [] : typeof payload.scope === "string" ? payload.scope.split(/\s+/) : [];
  const allowedScopes = payload.allowed_scopes === "" ? []
    : typeof payload.allowed_scopes === "string" && payload.allowed_scopes.trim() ? payload.allowed_scopes.split(/\s+/)
    : undefined;
  return {
    clientId: requiredString(payload.client_id, "client_id"),
    redirectUri: primitiveString(payload.redirect_uri, "redirect_uri"),
    resource: requiredString(payload.resource, "resource"),
    scopes,
    codeChallenge: requiredString(payload.code_challenge, "code_challenge"),
    codeChallengeMethod: "S256",
    state: stringClaim(payload.state),
    subject: requiredString(payload.sub, "sub"),
    allowedScopes,
    ...cimdVerifiedClaim(payload),
  };
}

/** Strict `=== true` is the SOLE true path (§17.1.6 decision 3). ANY present
 *  non-`true` value (`false`, `"true"`, `1`, `0`, `null`) INVALIDATES the
 *  token — a `!!x`/`== true` read would wrongly accept `1`/`"true"`. */
function cimdVerifiedClaim(payload: JWTPayload): { cimdVerified?: true } {
  if (!Object.hasOwn(payload, "cimd_verified")) return {};
  if (payload.cimd_verified !== true) throw new Error("cimd_verified must be true when present");
  return { cimdVerified: true };
}

function accessClaims(payload: JWTPayload): VerifiedAccessToken {
  const subject = requiredString(payload.sub, "sub");
  const clientId = requiredString(payload.client_id, "client_id");
  return {
    subject,
    clientId,
    scopes: payload.scope === "" ? [] : typeof payload.scope === "string" ? payload.scope.split(/\s+/) : [],
    credentialKind: credentialKindClaim(payload, subject, clientId),
  };
}

function credentialKindClaim(payload: JWTPayload, subject: string, clientId: string): CredentialKind {
  const machineSubject = subject.startsWith("mcc_");
  const hasGrantType = Object.hasOwn(payload, "gty");
  if (!machineSubject && !hasGrantType) return "interactive";
  if (machineSubject && clientId === subject && hasGrantType && payload.gty === "client_credentials") return "machine";
  throw new Error("partial or conflicting machine credential binding");
}

function requiredString(value: unknown, label: string): string {
  if (typeof value === "string" && value) return value;
  throw new Error(`missing ${label}`);
}

function primitiveString(value: unknown, label: string): string {
  if (typeof value === "string") return value;
  throw new Error(`missing ${label}`);
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function nowSeconds(clock: ClockPort): number {
  return Math.floor(clock.nowMs() / 1000);
}

function base64url(bytes: Buffer): string {
  return bytes.toString("base64url");
}
