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
//   6. (groupAuthorization) In the app manifest set `groupMembershipClaims` to
//      emit group OBJECT IDs — "ApplicationGroup" (direct membership, solves
//      overage for the mapping use case; requires Entra P1) or "SecurityGroup"
//      (transitive). Mapping keys MUST be the group object IDs (GUIDs), never
//      display names (a documented spoof vector — boot-rejected).
//   7. Confirm a user whose groups map to a subset of scopeCatalog receives
//      exactly the intersected scopes in the bridge token; a user in zero
//      mapped groups (with empty baseScopes) is rejected (entra_no_groups).
//   8. Confirm an overage (>200-group) token fails closed (entra_groups_overage)
//      and that the `_claim_sources` endpoint URL is NEVER fetched. Remedy:
//      switch the manifest to "ApplicationGroup" or reduce group sprawl.
//   9. Guest/B2B users: group-claim behavior is UNVERIFIED in Microsoft's docs —
//      confirm a guest's membership resolves as expected before relying on it.

import { createRemoteJWKSet, errors, importJWK, jwtVerify, type JWTPayload } from "jose";
import type { IdentityClaims, IdentityResult } from "../ports/identity.ts";
import { type GroupAuthorization, assertGroupAuthorizationMapping, resolveGroupCeiling } from "./entra-groups.ts";
import { assertHttpsRaw } from "./util.ts";

export interface EntraConfig {
  tenantId: string;
  clientId: string;
  /** Confidential-client secret. Omit for a public client (PKCE only). */
  clientSecret?: string;
  /** The bridge's Entra-callback URL (may be http://localhost for dev). */
  redirectUri: string;
  /** Allowed `tid` values; defaults to [tenantId]. */
  allowedTenantIds?: string[];
  /** Optional defense-in-depth subject allowlist (case-insensitive). Matches the
   *  immutable `oid` by default; set `allowMutableClaims` to also match the mutable
   *  preferred_username/email (Microsoft warns against those for authorization). */
  subjectAllowlist?: string[];
  /** Opt-in: also match the allowlist against preferred_username/email. Default false. */
  allowMutableClaims?: boolean;
  /** Opt-in group→scope authorization ceiling (contracts §17.4). When set, a
   *  subject's granted scopes are capped by the union of their matched Entra
   *  groups' mapped scopes plus `baseScopes`. Boot-rejects non-GUID keys and
   *  empty scope values; mapped/base scopes must be ⊆ `scopeCatalog` when that
   *  is passed to `createEntraIdentity`. */
  groupAuthorization?: GroupAuthorization;
}

type EntraPayload = JWTPayload & {
  oid?: string; email?: string; preferred_username?: string; tid?: string;
  /** Group object IDs (GUIDs) when configured and ≤200 groups. */
  groups?: unknown;
  /** Access-token overage marker (defensively checked on id_tokens). */
  hasgroups?: unknown;
  /** id_token overage marker: `{ groups: "<sourceName>" }`. */
  _claim_names?: unknown;
  /** Read-nowhere — the `_claim_sources` endpoint URL is NEVER dereferenced. */
  _claim_sources?: unknown;
};

const ENTRA_BASE = "https://login.microsoftonline.com";

export function entraIssuer(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/v2.0`; }
export function entraAuthorizeEndpoint(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/oauth2/v2.0/authorize`; }
export function entraTokenEndpoint(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/oauth2/v2.0/token`; }
export function entraJwksUrl(tenantId: string): string { return `${ENTRA_BASE}/${tenantId}/discovery/v2.0/keys`; }

export interface EntraAuthorizeRequest {
  state: string;
  codeChallenge: string;
  codeChallengeMethod?: "S256";
  scope?: string;
  /** OIDC nonce — bind the returned id_token to this request (recommended). */
  nonce?: string;
}

/** Build the Entra v2.0 authorization URL (auth-code + PKCE S256). */
export function getAuthorizationUrl(config: EntraConfig, req: EntraAuthorizeRequest): string {
  if (req.codeChallengeMethod !== undefined && req.codeChallengeMethod !== "S256") throw new Error("entra_bad_config: codeChallengeMethod must be S256 (PKCE plain/other rejected — sibling of generic-oidc)");
  const params = new URLSearchParams({
    client_id: config.clientId,
    response_type: "code",
    redirect_uri: config.redirectUri,
    response_mode: "query",
    scope: req.scope ?? "openid profile email offline_access",
    state: req.state,
    code_challenge: req.codeChallenge,
    code_challenge_method: req.codeChallengeMethod ?? "S256",
    ...(req.nonce ? { nonce: req.nonce } : {}),
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

/** Validate an Entra id_token's claims and extract the subject. Exported so the gate
 *  is unit-testable WITHOUT the JWKS fetch. Signature is checked separately by
 *  jwtVerify in the caller. Multi-tenant: when `allowedTenantIds` is set, the `tid`
 *  must be allowlisted AND `iss` must equal `entraIssuer(payload.tid)` (the standard
 *  Entra multi-tenant issuer pattern). Single-tenant (unset): `iss` must equal
 *  `entraIssuer(config.tenantId)` exactly. */
export function validateEntraIdToken(payload: EntraPayload, config: EntraConfig, expectedNonce?: string): { ok: true; identity: IdentityClaims } | { ok: false; reason: string } {
  if (config.allowedTenantIds && config.allowedTenantIds.length > 0) {
    if (!payload.tid || !config.allowedTenantIds.includes(payload.tid)) return { ok: false, reason: "entra_bad_tid" };
    if (payload.iss !== entraIssuer(payload.tid)) return { ok: false, reason: "entra_bad_iss" };
  } else {
    if (payload.iss !== entraIssuer(config.tenantId)) return { ok: false, reason: "entra_bad_iss" };
    if (payload.tid && payload.tid !== config.tenantId) return { ok: false, reason: "entra_bad_tid" };
  }
  if (payload.aud !== config.clientId) return { ok: false, reason: "entra_bad_aud" };
  if (expectedNonce !== undefined && payload.nonce !== expectedNonce) return { ok: false, reason: "entra_bad_nonce" };
  if (!payload.exp) return { ok: false, reason: "entra_missing_exp" };
  const subject = payload.oid ?? payload.preferred_username ?? payload.email;
  if (!subject) return { ok: false, reason: "entra_no_subject" };
  if (config.subjectAllowlist && config.subjectAllowlist.length > 0 && !subjectAllowed(payload, config.subjectAllowlist, config.allowMutableClaims)) {
    return { ok: false, reason: "entra_subject_not_allowed" };
  }
  const claims = { oid: payload.oid, email: payload.email ?? payload.preferred_username, tid: payload.tid, expiresAt: payload.exp };
  // §17.4: when group→scope mapping is configured, resolve the ceiling from the
  // VERIFIED payload (signature already checked by the caller). Unconfigured ⇒
  // unchanged v0.1 behavior (no ceiling). Overage/no-groups fail CLOSED here so
  // the bridge's resolveIdentity emits identity.verify with the Entra reason.
  if (config.groupAuthorization) {
    const ceiling = resolveGroupCeiling(payload, config.groupAuthorization);
    if (!ceiling.ok) return ceiling; // entra_groups_overage | entra_no_groups
    return { ok: true, identity: { subject, allowedScopes: ceiling.allowedScopes, claims } };
  }
  return { ok: true, identity: { subject, claims } };
}

/** Case-insensitive allowlist match. Matches the immutable `oid` by default; only
 *  matches the mutable preferred_username/email when `allowMutable` is true
 *  (Microsoft warns against using those claims for authorization). */
export function subjectAllowed(payload: EntraPayload, allowlist: string[], allowMutable = false): boolean {
  const candidates: string[] = [];
  if (payload.oid) candidates.push(payload.oid);
  if (allowMutable) {
    if (payload.preferred_username) candidates.push(payload.preferred_username);
    if (payload.email) candidates.push(payload.email);
  }
  return candidates.some((c) => allowlist.some((entry) => entry.trim().toLowerCase() === c.trim().toLowerCase()));
}

export type EntraVerifyKey = Awaited<ReturnType<typeof importJWK>>;

export interface EntraVerifyOptions {
  currentDate?: Date;
  /** If set, the id_token's `nonce` claim must equal this (OIDC request binding). If UNSET — e.g. header-driven deployments where a fronting proxy delivers the id_token — the token is NOT replay-bound here; the proxy that minted the nonce owns replay protection (threat-model row 12). */
  expectedNonce?: string;
}

/** Verify an Entra id_token against an explicit key (CryptoKey/Uint8Array). Exported
 *  so the full path is testable with a known key — no JWKS fetch. */
export async function verifyEntraIdToken(token: string, key: EntraVerifyKey, config: EntraConfig, options?: EntraVerifyOptions): Promise<IdentityResult> {
  try {
    const { payload } = await jwtVerify<EntraPayload>(token, key, { algorithms: ["RS256"], currentDate: options?.currentDate });
    return validateEntraIdToken(payload, config, options?.expectedNonce);
  } catch (error) {
    return { ok: false, reason: jwtErrorReason(error) };
  }
}

export interface EntraIdentity {
  getAuthorizationUrl(req: EntraAuthorizeRequest): string;
  exchangeCodeForToken(args: { code: string; codeVerifier: string }, transport: EntraTokenTransport): Promise<string>;
  verify(input: unknown, options?: { expectedNonce?: string }): Promise<IdentityResult>;
}

/** Build the Entra identity port. `verify` takes a raw id_token string; the adapter
 *  drives getAuthorizationUrl + exchangeCodeForToken for the redirect dance.
 *  `opts.scopeCatalog` is the wiring-time junction where the Entra group mapping
 *  and the bridge catalog meet: when supplied, the mapped/base scopes are
 *  validated ⊆ scopeCatalog at boot (§17.4). Omit it only if the deployer
 *  validates the subset elsewhere — passing it is recommended. */
export function createEntraIdentity(config: EntraConfig, opts?: { scopeCatalog?: readonly string[] }): EntraIdentity {
  assertHttpsRaw(ENTRA_BASE, "entra base");
  // §17.4 boot validation: GUID-only keys, non-empty scope values (+ subset ⊆
  // catalog when supplied). Fail closed at construction, never a silent default.
  assertGroupAuthorizationMapping(config.groupAuthorization, opts?.scopeCatalog);
  const jwks = createRemoteJWKSet(new URL(entraJwksUrl(config.tenantId)), { cacheMaxAge: 5 * 60 * 1000 });
  return {
    getAuthorizationUrl: (req) => getAuthorizationUrl(config, req),
    exchangeCodeForToken: (args, transport) => exchangeCodeForToken(config, args, transport),
    async verify(input: unknown, options?: { expectedNonce?: string }): Promise<IdentityResult> {
      if (typeof input !== "string" || !input) return { ok: false, reason: "entra_id_token_missing" };
      try {
        const { payload } = await jwtVerify<EntraPayload>(input, jwks, { algorithms: ["RS256"] });
        return validateEntraIdToken(payload, config, options?.expectedNonce);
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
  // JWKS-fetch transport failures (base JOSEError non-200/malformed + JWKSTimeout) ⇒ entra_verify_failed ⇒ exchange_failed (§17.11). Sibling of generic-oidc.ts.
  if (error instanceof errors.JWKSTimeout) return "entra_verify_failed";
  if (error instanceof errors.JOSEError && error.code === "ERR_JOSE_GENERIC") return "entra_verify_failed";
  if (error instanceof errors.JOSEError) return "entra_token_invalid";
  return "entra_verify_failed";
}

// Public group-authorization API (§17.4) re-exported for the ./identity/entra subpath.
export { type GroupAuthorization, assertGroupAuthorizationMapping, resolveGroupCeiling } from "./entra-groups.ts";
// §17.11 redirect-flow identity (createEntraRedirectIdentity) re-exported for the ./identity/entra subpath.
export { createEntraRedirectIdentity, type EntraRedirectOptions } from "./entra-redirect.ts";
