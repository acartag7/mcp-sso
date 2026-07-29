// ES256 access-token signing and verification (contracts §7.2/§8.1). One
// resolved resource is carried explicitly from issuance through verification;
// multi-value JWT audiences are rejected even when jose finds a matching member.

import { SignJWT, jwtVerify } from "jose";
import type { JWTPayload } from "jose";
import type { BridgeConfig } from "./config.ts";
import { OAuthError } from "./errors.ts";
import { signingKeyId, signKey, verifyKey } from "./crypto-keys.ts";
import { finiteClockSnapshot, type ClockPort } from "./ports/clock.ts";
import { buildResourceCatalog, canonicalResource, resolveResource } from "./resource.ts";
import type { ResourceConfiguration } from "./resource.ts";
import { scopeString, type CredentialKind } from "./scopes.ts";

export interface AccessTokenClaims {
  subject: string;
  clientId: string;
  scopes: string[];
  resource: string;
  /** client_credentials grant ⇒ mints the gty marker claim (§17.2). */
  machine?: boolean;
}

export interface VerifiedAccessToken {
  subject: string;
  clientId: string;
  scopes: string[];
  resource: string;
  credentialKind: CredentialKind;
}

export async function signAccessToken(
  claims: AccessTokenClaims,
  config: BridgeConfig,
  clock: ClockPort,
): Promise<string> {
  if (typeof claims.resource !== "string") {
    throw new OAuthError("invalid_target", "access-token resource is required");
  }
  const resource = configuredResource(config, claims.resource);
  const now = Math.floor(clock.nowMs() / 1000);
  const key = await signKey(config);
  return await new SignJWT({
    client_id: claims.clientId,
    scope: scopeString(claims.scopes),
    ...(claims.machine ? { gty: "client_credentials" } : {}),
  }).setProtectedHeader({ alg: "ES256", kid: signingKeyId(config), typ: "JWT" })
    .setIssuer(config.issuer)
    .setSubject(claims.subject)
    .setAudience(resource)
    .setIssuedAt(now)
    .setExpirationTime(now + config.accessTokenTtlSeconds)
    .sign(key);
}

export async function verifyAccessToken(
  token: string,
  config: BridgeConfig,
  clock: ClockPort,
  expectedResource?: string,
): Promise<VerifiedAccessToken> {
  try {
    const resource = configuredResource(config, expectedResource);
    const nowMs = finiteClockSnapshot(clock);
    const key = await verifyKey(config);
    const { payload } = await jwtVerify(token, key, {
      algorithms: ["ES256"],
      issuer: config.issuer,
      audience: resource,
      currentDate: new Date(nowMs),
    });
    if (typeof payload.aud !== "string" || payload.aud !== resource) {
      throw new Error("access-token aud must be the exact primitive-string resource");
    }
    return accessClaims(payload, resource);
  } catch {
    throw new OAuthError("invalid_token", "Bearer token is invalid", 401);
  }
}

/** Resolve the expected audience for one verification.
 *
 *  A caller that already holds a pinned resource — `RequestAuthorizer` resolves
 *  one at construction — passes it here on every request. Rebuilding the whole
 *  catalog to re-derive a string boot already validated would re-parse the URL
 *  and re-scan every scope catalog on the busiest path in the library, so a
 *  value that is ALREADY canonical is accepted as-is. `canonicalResource` is
 *  idempotent, which is what makes that check exact rather than a shortcut: an
 *  input that is not its own canonical form is not a configured resource, and
 *  falls through to the full catalog resolution (which rejects it). */
function configuredResource(config: BridgeConfig, requested: string | undefined): string {
  const options = { allowInsecureLocalhost: config.dev?.allowInsecureLocalhost === true };
  if (requested !== undefined) {
    let canonical: string;
    try { canonical = canonicalResource(requested, options); } catch { canonical = ""; }
    if (canonical === requested) return canonical;
  }
  const catalog = buildResourceCatalog(config as unknown as ResourceConfiguration, options);
  return resolveResource(catalog, requested).resource;
}

function accessClaims(payload: JWTPayload, resource: string): VerifiedAccessToken {
  const subject = requiredString(payload.sub, "sub");
  const clientId = requiredString(payload.client_id, "client_id");
  return {
    subject,
    clientId,
    scopes: payload.scope === "" ? [] : typeof payload.scope === "string" ? payload.scope.split(/\s+/) : [],
    resource,
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
