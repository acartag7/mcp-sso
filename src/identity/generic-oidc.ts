// GenericOidcIdentity (contracts §17.6) — the bridge acts as an OIDC client to a
// deployer-configured issuer (auth-code + PKCE S256 + nonce), validates the
// id_token (iss/aud/iat/exp/nonce/at_hash), and takes the subject from `sub`
// (keyed as (issuer, sub)). The bridge then issues its OWN audience-bound tokens
// (no upstream-token passthrough). Endpoints come from OIDC Discovery (fetched
// once at boot; issuer exact-match; https-only; redirects not followed) OR manual
// config (zero fetch). Plain https, NOT the §17.1 SSRF guard — deployer-trusted
// config. Claim validation is exported + unit-testable without the JWKS fetch
// (addendum 12); code exchange takes an injectable transport (no network in tests).
//
// ⚠️ Addendum 12 / row 12: `validateGenericOidcIdToken` is claim-validation ONLY
// (no signature; exp/iat presence only) — route raw id_tokens through
// `verifyGenericOidcIdToken` / `createGenericOidcIdentity().verify`, NEVER the
// pure validator alone. Header mode (raw id_token, no nonce/access_token) skips
// nonce + at_hash (documented residual; the fronting proxy owns replay binding).
//
// --- Manual checklist: live-issuer verification (run before claiming live; the
//   expanded steps are in docs/identity/generic-oidc.md) ---
//   1. Register one client: redirect URI = the bridge callback; PKCE or a secret; openid/profile/email.
//   2. GET /oauth/authorize 302s to the IdP; after login the callback validates (state/nonce/jti),
//      exchanges, verifies (iss/aud/multi-aud/iat+exp/nonce/at_hash); subject = stable sub.
//   3. Approve → the bridge mints its OWN token; IdP tokens discarded (never logged/forwarded).
//   4. Negatives: a multi-aud id_token, a non-allowlisted subject, or a bad iss/nonce/at_hash ⇒ rejected.

import { createRemoteJWKSet, errors, importJWK, jwtVerify, type JWK } from "jose";
import type { IdentityClaims, IdentityResult } from "../ports/identity.ts";
import {
  validateGenericOidcIdToken, resolveAllowedAlgs,
  type GenericOidcIdTokenPayload, type GenericOidcValidateOpts,
} from "./generic-oidc-claims.ts";
import {
  resolveEndpoints, defaultTokenTransport, assertValidHttpsEndpoint, formUrlEncode,
  type GenericOidcEndpoints, type GenericOidcTokenTransport, type DiscoveryTransport, type ResolvedEndpoints, type TokenAuthMethod,
} from "./generic-oidc-discovery.ts";

export type { GenericOidcEndpoints, GenericOidcManualEndpoints } from "./generic-oidc-discovery.ts";

export interface GenericOidcConfig {
  /** https issuer — the exact-match anchor for the id_token `iss` and the
   *  discovery document `issuer` (OIDC Discovery §4.3). */
  issuer: string;
  clientId: string;
  /** Confidential-client secret. Omit for a public client (PKCE only). */
  clientSecret?: string;
  /** Override the token-endpoint auth method for a confidential client. */
  tokenEndpointAuthMethod?: TokenAuthMethod;
  /** The bridge's OIDC callback URL (registered at the IdP). */
  redirectUri: string;
  /** "discover" (fetch OIDC discovery at boot) or manual endpoints (zero fetch). */
  endpoints: GenericOidcEndpoints;
  /** Upstream scopes requested; default "openid profile email". */
  scopes?: string;
  /** Optional defense-in-depth allowlist (matches `sub`; case-insensitive). */
  subjectAllowlist?: string[];
  /** Opt-in: also match a VERIFIED email against `subjectAllowlist`
   *  (`email_verified === true` strict). */
  allowEmailAllowlist?: boolean;
  /** Opt-in: accept a discovery that omits PKCE S256 (loud warning). */
  allowProviderWithoutPkce?: boolean;
}

export interface GenericOidcAuthorizeRequest {
  state: string;
  /** Required — the generic port always sends + verifies the nonce (§17.6). */
  nonce: string;
  codeChallenge: string;
  codeChallengeMethod?: "S256";
}

export interface GenericOidcTokenResponse {
  id_token: string;
  /** REQUIRED in the code flow (§3.1.3.3) — for `at_hash`, then discarded; requiring
   *  it guarantees a present at_hash is validated (no header-mode skip in code flow). */
  access_token: string;
}

/** A concrete key (CryptoKey/Uint8Array/JWK) or the JWKS resolver (derived from
 *  jose's helpers; `typeof key === "function"` picks the getKey overload). */
type VerifyKey = Uint8Array | JWK | Awaited<ReturnType<typeof importJWK>> | ReturnType<typeof createRemoteJWKSet>;
export type GenericOidcVerifyKey = Awaited<ReturnType<typeof importJWK>>;

export interface GenericOidcVerifyOpts extends GenericOidcValidateOpts {
  /** Override the verify clock (test-only; the JWKS path uses wall-clock). */
  currentDate?: Date;
  /** Override the allowed algs (test-only; defaults to the boot-resolved set). */
  allowedAlgs?: string[];
  /** Verify against this key instead of the JWKS (test-only). */
  verifyKey?: VerifyKey;
}

export interface GenericOidcIdentity {
  readonly redirectUri: string;
  getAuthorizationUrl(req: GenericOidcAuthorizeRequest): string;
  exchangeCodeForToken(args: { code: string; codeVerifier: string }, transport?: GenericOidcTokenTransport): Promise<GenericOidcTokenResponse>;
  verify(input: unknown, opts?: GenericOidcVerifyOpts): Promise<IdentityResult>;
}

/** Options for `createGenericOidcIdentity`. */
export interface GenericOidcIdentityOpts {
  /** Injectable discovery transport (tests avoid the network). */
  discoveryFetch?: DiscoveryTransport;
  /** Override the claim validator. Defaults to the generic validator bound to
   *  `config`; the Google preset injects its own to add `hd`/`email_verified`
   *  gating on top of the shared generic checks (no claim-logic duplication). */
  validate?: (payload: GenericOidcIdTokenPayload, opts: GenericOidcValidateOpts) => IdentityResult;
}

export function getAuthorizationUrl(config: GenericOidcConfig, resolved: ResolvedEndpoints, req: GenericOidcAuthorizeRequest): string {
  // PKCE is always S256 (§17.6) — reject any runtime override (e.g. `as any` "plain").
  if (req.codeChallengeMethod !== undefined && req.codeChallengeMethod !== "S256") throw new Error("generic_oidc_bad_config: codeChallengeMethod must be S256 (PKCE plain/other rejected — §17.6)");
  const params = new URLSearchParams({
    client_id: config.clientId,
    response_type: "code",
    redirect_uri: config.redirectUri,
    response_mode: "query",
    scope: config.scopes ?? "openid profile email",
    state: req.state,
    nonce: req.nonce,
    code_challenge: req.codeChallenge,
    code_challenge_method: req.codeChallengeMethod ?? "S256",
  });
  // Build via URL so an endpoint that already carries a query is preserved (no 2nd `?`).
  const url = new URL(resolved.authorizationEndpoint);
  for (const [k, v] of params.entries()) url.searchParams.set(k, v);
  return url.toString();
}

/** Exchange the code at the token endpoint; returns id_token + access_token (at_hash only, then discarded). */
export async function exchangeCodeForToken(
  config: GenericOidcConfig,
  resolved: ResolvedEndpoints,
  args: { code: string; codeVerifier: string },
  transport: GenericOidcTokenTransport,
): Promise<GenericOidcTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: args.code,
    redirect_uri: config.redirectUri,
    code_verifier: args.codeVerifier,
  });
  const headers: Record<string, string> = {};
  if (config.clientSecret && resolved.tokenAuthMethod === "client_secret_basic") {
    // basic ⇒ clientId + secret in the Authorization header ONLY (RFC 6749 §2.3.1) — not duplicated in the body.
    headers.authorization = `Basic ${Buffer.from(`${formUrlEncode(config.clientId)}:${formUrlEncode(config.clientSecret)}`).toString("base64")}`;
  } else {
    body.set("client_id", config.clientId); // public + post: client identification lives in the body
    if (config.clientSecret) body.set("client_secret", config.clientSecret); // post
  }
  const resp = await transport.postForm(resolved.tokenEndpoint, body, headers);
  if (resp.status !== 200) { let detail = ""; try { const e = JSON.parse(await resp.text()) as { error?: unknown; error_description?: unknown }; if (typeof e.error === "string") detail = `: ${e.error}${typeof e.error_description === "string" ? ` — ${String(e.error_description).slice(0, 160).replace(/[\r\n]+/g, " ")}` : ""}`; } catch { /* non-JSON error body — the HTTP status is the detail */ } throw new Error(`generic_oidc_exchange_failed: token endpoint returned HTTP ${resp.status}${detail}`); }
  const parsed = JSON.parse(await resp.text()) as Partial<GenericOidcTokenResponse>;
  if (typeof parsed.id_token !== "string" || !parsed.id_token) throw new Error("generic_oidc_exchange_failed: token response missing id_token");
  // access_token is REQUIRED in the code flow (OIDC §3.1.3.3) — requiring it also
  // guarantees a present at_hash is validated (no header-mode skip in the code flow).
  if (typeof parsed.access_token !== "string" || !parsed.access_token) throw new Error("generic_oidc_exchange_failed: token response missing access_token (required in the OIDC code flow)");
  return { id_token: parsed.id_token, access_token: parsed.access_token };
}

/** Shared jose-verify + pure-validate seam (generic identity, standalone verifier,
 *  Google preset). iss/aud/multi-aud live in `validate` (NOT jose's `audience`,
 *  which accepts multi-aud); jose enforces the alg pin; JWKS-fetch failures ⇒ exchange_failed. */
export interface VerifyIdTokenArgs {
  allowedAlgs: string[];
  validate: (payload: GenericOidcIdTokenPayload, opts: GenericOidcValidateOpts) => IdentityResult;
  expectedNonce?: string;
  accessToken?: string;
  currentDate?: Date;
}
export async function verifyIdTokenWithKey(token: string, key: VerifyKey, args: VerifyIdTokenArgs): Promise<IdentityResult> {
  try {
    // jose's `jwtVerify` is overloaded (concrete key vs getKey resolver). The JWKS
    // resolver is callable; concrete keys are not — narrow by `typeof === "function"`
    // so each branch matches its overload (a union arg would fail resolution).
    const verifyOpts = { algorithms: args.allowedAlgs, currentDate: args.currentDate };
    const { payload, protectedHeader } = typeof key === "function"
      ? await jwtVerify(token, key, verifyOpts)
      : await jwtVerify(token, key, verifyOpts);
    return args.validate(payload as GenericOidcIdTokenPayload, {
      expectedNonce: args.expectedNonce,
      accessToken: args.accessToken,
      alg: typeof protectedHeader?.alg === "string" ? protectedHeader.alg : undefined,
    });
  } catch (error) {
    return { ok: false, reason: jwtErrorReason(error) };
  }
}

export function jwtErrorReason(error: unknown): string {
  if (error instanceof errors.JWTExpired) return "generic_oidc_token_expired";
  if (error instanceof errors.JWTClaimValidationFailed) return "generic_oidc_bad_claim";
  if (error instanceof errors.JOSEAlgNotAllowed) return "generic_oidc_unsupported_alg";
  if (error instanceof errors.JWKSNoMatchingKey) return "generic_oidc_unknown_key";
  // JWKS-fetch transport failures (jose throws the base JOSEError, code
  // ERR_JOSE_GENERIC, ONLY from its JWKS fetch on non-200/malformed; and
  // JWKSTimeout on its 5s timeout) ⇒ `generic_oidc_verify_failed` ⇒ exchange_failed
  // (§17.11; no identity decision). Subclasses have their own codes, so the
  // ERR_JOSE_GENERIC check never misclassifies a signature/claim error.
  if (error instanceof errors.JWKSTimeout) return "generic_oidc_verify_failed";
  if (error instanceof errors.JOSEError && error.code === "ERR_JOSE_GENERIC") return "generic_oidc_verify_failed";
  if (error instanceof errors.JOSEError) return "generic_oidc_token_invalid";
  return "generic_oidc_verify_failed";
}

/** Verify an id_token against an explicit key (testable with a known key, no JWKS). */
export async function verifyGenericOidcIdToken(token: string, key: VerifyKey, config: GenericOidcConfig, opts?: GenericOidcVerifyOpts): Promise<IdentityResult> {
  return verifyIdTokenWithKey(token, key, {
    allowedAlgs: opts?.allowedAlgs ?? resolveAllowedAlgs(undefined),
    validate: (p, o) => validateGenericOidcIdToken(p, config, o),
    expectedNonce: opts?.expectedNonce,
    accessToken: opts?.accessToken,
    currentDate: opts?.currentDate,
  });
}

/** Build the generic OIDC identity port (async: discovery is a boot fetch). */
export async function createGenericOidcIdentity(config: GenericOidcConfig, opts?: GenericOidcIdentityOpts): Promise<GenericOidcIdentity> {
  assertValidHttpsEndpoint(config.issuer, "issuer");
  if (typeof config.clientId !== "string" || !config.clientId.trim()) throw new Error("generic_oidc_bad_config: clientId is required (an empty clientId makes the aud check vacuous)");
  if (typeof config.redirectUri !== "string" || !config.redirectUri.trim()) throw new Error("generic_oidc_bad_config: redirectUri is required");
  if (config.clientSecret !== undefined && !config.clientSecret.trim()) throw new Error("generic_oidc_bad_config: clientSecret must be a non-empty string if set (an empty value would silently use public-client auth)");
  if (config.scopes !== undefined && (!config.scopes.trim() || !config.scopes.split(/\s+/).includes("openid"))) throw new Error("generic_oidc_bad_config: scopes must be a non-empty, space-separated list including 'openid' (omit for the default 'openid profile email')");
  if (config.subjectAllowlist !== undefined && (!Array.isArray(config.subjectAllowlist) || !config.subjectAllowlist.every((e) => typeof e === "string"))) throw new Error("generic_oidc_bad_config: subjectAllowlist must be an array of strings");
  const resolved = await resolveEndpoints(config, opts?.discoveryFetch);
  const jwks = createRemoteJWKSet(new URL(resolved.jwksUri), { cacheMaxAge: 5 * 60 * 1000 });
  const validate = opts?.validate ?? ((p, o) => validateGenericOidcIdToken(p, config, o));
  return {
    redirectUri: config.redirectUri,
    getAuthorizationUrl: (req) => getAuthorizationUrl(config, resolved, req),
    exchangeCodeForToken: (args, transport) => exchangeCodeForToken(config, resolved, args, transport ?? defaultTokenTransport),
    async verify(input, vopts) {
      if (typeof input !== "string" || !input) return { ok: false, reason: "generic_oidc_id_token_missing" };
      return verifyIdTokenWithKey(input, vopts?.verifyKey ?? jwks, {
        allowedAlgs: vopts?.allowedAlgs ?? resolved.allowedAlgs,
        validate,
        expectedNonce: vopts?.expectedNonce,
        accessToken: vopts?.accessToken,
        currentDate: vopts?.currentDate,
      });
    },
  };
}

// Re-exports for the ./identity/generic-oidc subpath.
export { validateGenericOidcIdToken, computeAtHash, subjectAllowedGeneric, resolveAllowedAlgs, type GenericOidcIdTokenPayload, type GenericOidcValidateOpts, type GenericOidcClaimConfig } from "./generic-oidc-claims.ts";
export { resolveEndpoints, defaultTokenTransport, defaultDiscoveryTransport, type ResolvedEndpoints, type DiscoveryTransport, type GenericOidcTokenTransport } from "./generic-oidc-discovery.ts";
export { createGenericOidcRedirectIdentity, type GenericOidcRedirectOpts } from "./generic-oidc-redirect.ts";
