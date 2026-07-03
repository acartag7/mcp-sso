// EntraIdentity — the bridge acts as an OIDC client to Microsoft Entra ID v2.0:
// it redirects the user to Entra (auth-code + PKCE), exchanges the code for an
// id_token, validates iss/aud/tid, and maps oid/email → subject. The bridge then
// issues its OWN audience-bound tokens (no Entra token passthrough).
//
// Entra's endpoints are always the well-known https login.microsoftonline.com URLs
// (raw `^https://` asserted, addendum 11). Claim validation is exported and unit-
// testable WITHOUT the JWKS fetch (addendum 12); code exchange takes an injectable
// transport so it is testable without the network. An optional subject/email
// allowlist adds defense-in-depth.
//
// --- Manual checklist: live-tenant verification (cannot be automated without a
// real tenant; run before claiming Entra works end-to-end) ---
//   1. Register ONE app in the Entra tenant (App registrations): redirect URI =
//      the bridge's Entra-callback URL; allow public-client PKCE OR create a
//      client secret; expose openid/profile/email/offline_access.
//   2. Sign a real user in via getAuthorizationUrl → Entra login → callback.
//   3. Confirm exchangeCodeForToken returns an id_token and validateEntraIdToken
//      accepts it (iss/aud/tid match the config; subject is the user's oid).
//   4. Confirm a user from a NON-allowed tid is rejected (entra_bad_tid).
//   5. Confirm the bridge then mints its OWN token (the Entra token is not
//      forwarded to any MCP client).

import { createRemoteJWKSet, errors, importJWK, jwtVerify, type JWTPayload } from "jose";
import type { IdentityClaims, IdentityResult } from "../ports/identity.ts";

export interface EntraConfig {
  tenantId: string;
  clientId: string;
  /** Confidential-client secret. Omit for a public client (PKCE only). */
  clientSecret?: string;
  /** The bridge's Entra-callback URL (may be http://localhost for dev). */
  redirectUri: string;
  /** Allowed `tid` values; defaults to [tenantId]. */
  allowedTenantIds?: string[];
  /** Optional defense-in-depth subject/email allowlist (case-insensitive). */
  subjectAllowlist?: string[];
}

type EntraPayload = JWTPayload & { oid?: string; email?: string; preferred_username?: string; tid?: string };

const ENTRA_BASE = "https://login.microsoftonline.com";

function assertHttpsRaw(value: string, label: string): void {
  if (!value.startsWith("https://")) throw new Error(`${label} must be an https:// URL`);
}
export function entraIssuer(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/v2.0`; }
export function entraAuthorizeEndpoint(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/oauth2/v2.0/authorize`; }
export function entraTokenEndpoint(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/oauth2/v2.0/token`; }
export function entraJwksUrl(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/discovery/v2.0/keys`; }

export interface EntraAuthorizeRequest {
  state: string;
  codeChallenge: string;
  codeChallengeMethod?: "S256";
  scope?: string;
}

/** Build the Entra v2.0 authorization URL (auth-code + PKCE S256). */
export function getAuthorizationUrl(config: EntraConfig, req: EntraAuthorizeRequest): string {
  const params = new URLSearchParams({
    client_id: config.clientId,
    response_type: "code",
    redirect_uri: config.redirectUri,
    response_mode: "query",
    scope: req.scope ?? "openid profile email offline_access",
    state: req.state,
    code_challenge: req.codeChallenge,
    code_challenge_method: req.codeChallengeMethod ?? "S256",
  });
  return `${entraAuthorizeEndpoint(config.tenantId)}?${params.toString()}`;
}

/** Injectable transport for the token endpoint (so tests avoid the network). */
export interface EntraTokenTransport {
  postForm(url: string, body: URLSearchParams): Promise<{ status: number; text(): Promise<string> }>;
}

export async function exchangeCodeForToken(
  config: EntraConfig,
  args: { code: string; codeVerifier: string },
  transport: EntraTokenTransport,
): Promise<string> {
  const body = new URLSearchParams({
    client_id: config.clientId,
    grant_type: "authorization_code",
    code: args.code,
    redirect_uri: config.redirectUri,
    code_verifier: args.codeVerifier,
    ...(config.clientSecret ? { client_secret: config.clientSecret } : { scope: "openid profile email" }),
  });
  const resp = await transport.postForm(entraTokenEndpoint(config.tenantId), body);
  if (resp.status !== 200) throw new Error(`entra token exchange failed: HTTP ${resp.status}`);
  const parsed = JSON.parse(await resp.text()) as { id_token?: string };
  if (!parsed.id_token) throw new Error("entra token exchange returned no id_token");
  return parsed.id_token;
}

/** Validate an Entra id_token's claims (iss/aud/tid/exp) and extract the subject.
 *  Exported so the gate is unit-testable WITHOUT the JWKS fetch. Signature is
 *  checked separately by jwtVerify in the caller. */
export function validateEntraIdToken(payload: EntraPayload, config: EntraConfig): { ok: true; identity: IdentityClaims } | { ok: false; reason: string } {
  if (payload.iss !== entraIssuer(config.tenantId)) return { ok: false, reason: "entra_bad_iss" };
  if (payload.aud !== config.clientId) return { ok: false, reason: "entra_bad_aud" };
  const allowedTids = config.allowedTenantIds ?? [config.tenantId];
  if (!payload.tid || !allowedTids.includes(payload.tid)) return { ok: false, reason: "entra_bad_tid" };
  if (!payload.exp) return { ok: false, reason: "entra_missing_exp" };
  const subject = payload.oid ?? payload.preferred_username ?? payload.email;
  if (!subject) return { ok: false, reason: "entra_no_subject" };
  if (config.subjectAllowlist && config.subjectAllowlist.length > 0 && !subjectAllowed(subject, payload, config.subjectAllowlist)) {
    return { ok: false, reason: "entra_subject_not_allowed" };
  }
  return {
    ok: true,
    identity: { subject, claims: { oid: payload.oid, email: payload.email ?? payload.preferred_username, tid: payload.tid, expiresAt: payload.exp } },
  };
}

/** Case-insensitive allowlist match on oid / preferred_username / email. */
export function subjectAllowed(subject: string, payload: EntraPayload, allowlist: string[]): boolean {
  void subject;
  const candidates = [payload.oid, payload.preferred_username, payload.email].filter((v): v is string => typeof v === "string" && v.length > 0);
  return candidates.some((c) => allowlist.some((entry) => entry.trim().toLowerCase() === c.trim().toLowerCase()));
}

export type EntraVerifyKey = Awaited<ReturnType<typeof importJWK>>;

/** Verify an Entra id_token against an explicit key (CryptoKey/Uint8Array). Exported
 *  so the full path is testable with a known key — no JWKS fetch. */
export async function verifyEntraIdToken(token: string, key: EntraVerifyKey, config: EntraConfig, currentDate?: Date): Promise<IdentityResult> {
  try {
    const { payload } = await jwtVerify<EntraPayload>(token, key, { algorithms: ["RS256"], currentDate });
    return validateEntraIdToken(payload, config);
  } catch (error) {
    return { ok: false, reason: jwtErrorReason(error) };
  }
}

export interface EntraIdentity {
  getAuthorizationUrl(req: EntraAuthorizeRequest): string;
  exchangeCodeForToken(args: { code: string; codeVerifier: string }, transport: EntraTokenTransport): Promise<string>;
  verify(input: unknown): Promise<IdentityResult>;
}

/** Build the Entra identity port. `verify` takes a raw id_token string; the adapter
 *  drives getAuthorizationUrl + exchangeCodeForToken for the redirect dance. */
export function createEntraIdentity(config: EntraConfig): EntraIdentity {
  assertHttpsRaw(ENTRA_BASE, "entra base");
  const jwks = createRemoteJWKSet(new URL(entraJwksUrl(config.tenantId)), { cacheMaxAge: 5 * 60 * 1000 });
  return {
    getAuthorizationUrl: (req) => getAuthorizationUrl(config, req),
    exchangeCodeForToken: (args, transport) => exchangeCodeForToken(config, args, transport),
    async verify(input: unknown): Promise<IdentityResult> {
      if (typeof input !== "string" || !input) return { ok: false, reason: "entra_id_token_missing" };
      try {
        const { payload } = await jwtVerify<EntraPayload>(input, jwks, { algorithms: ["RS256"] });
        return validateEntraIdToken(payload, config);
      } catch (error) {
        return { ok: false, reason: jwtErrorReason(error) };
      }
    },
  };
}

function jwtErrorReason(error: unknown): string {
  if (error instanceof errors.JWTExpired) return "entra_token_expired";
  if (error instanceof errors.JWTClaimValidationFailed) return "entra_bad_claim";
  if (error instanceof errors.JOSEAlgNotAllowed) return "entra_unsupported_alg";
  if (error instanceof errors.JWKSNoMatchingKey) return "entra_unknown_key";
  if (error instanceof errors.JOSEError) return "entra_token_invalid";
  return "entra_verify_failed";
}
