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

import { errors, jwtVerify } from "jose";
import type { IdentityClaims, IdentityResult } from "../ports/identity.ts";
import {
  validateGenericOidcIdToken, resolveAllowedAlgs,
  type GenericOidcIdTokenPayload, type GenericOidcValidateOpts,
} from "./generic-oidc-claims.ts";
import {
  resolveEndpoints, defaultTokenTransport, assertValidHttpsEndpoint, formUrlEncode,
  type GenericOidcEndpoints, type GenericOidcTokenTransport, type DiscoveryTransport, type ResolvedEndpoints, type TokenAuthMethod,
} from "./generic-oidc-discovery.ts";
import { snapshotOwnDataArray, snapshotOwnDataRecord } from "../own-property.ts";
import { createValidatedRemoteJWKSet } from "./remote-jwks.ts";
import { captureHttpResponse } from "./util.ts";
import { snapshotGenericOidcConfig } from "./generic-oidc-config.ts";
import type {
  GenericOidcAuthorizeRequest, GenericOidcConfig, GenericOidcIdentity,
  GenericOidcIdentityOpts, GenericOidcTokenResponse, GenericOidcVerifyKey,
  GenericOidcVerifyOpts, VerifyKey,
} from "./generic-oidc-types.ts";

export type {
  GenericOidcAuthorizeRequest, GenericOidcConfig, GenericOidcIdentity,
  GenericOidcIdentityOpts, GenericOidcTokenResponse, GenericOidcVerifyKey,
  GenericOidcVerifyOpts,
} from "./generic-oidc-types.ts";

export type { GenericOidcEndpoints, GenericOidcManualEndpoints } from "./generic-oidc-discovery.ts";

export function getAuthorizationUrl(config: GenericOidcConfig, resolved: ResolvedEndpoints, req: GenericOidcAuthorizeRequest): string {
  const safeConfig = snapshotGenericOidcConfig(config);
  const endpointFields = snapshotOwnDataRecord(resolved);
  const request = snapshotOwnDataRecord(req);
  if (endpointFields === null || typeof endpointFields.authorizationEndpoint !== "string"
    || request === null || typeof request.state !== "string" || !request.state
    || typeof request.nonce !== "string" || !request.nonce
    || typeof request.codeChallenge !== "string" || !request.codeChallenge) {
    throw new Error("generic_oidc_bad_config: authorization input is malformed");
  }
  assertValidHttpsEndpoint(endpointFields.authorizationEndpoint, "authorizationEndpoint");
  // PKCE is always S256 (§17.6) — reject any runtime override (e.g. `as any` "plain").
  if (request.codeChallengeMethod !== undefined && request.codeChallengeMethod !== "S256") throw new Error("generic_oidc_bad_config: codeChallengeMethod must be S256 (PKCE plain/other rejected — §17.6)");
  const params = new URLSearchParams({
    client_id: safeConfig.clientId,
    response_type: "code",
    redirect_uri: safeConfig.redirectUri,
    response_mode: "query",
    scope: safeConfig.scopes ?? "openid profile email",
    state: request.state,
    nonce: request.nonce,
    code_challenge: request.codeChallenge,
    code_challenge_method: request.codeChallengeMethod as "S256" | undefined ?? "S256",
  });
  // Build via URL so an endpoint that already carries a query is preserved (no 2nd `?`).
  const url = new URL(endpointFields.authorizationEndpoint);
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
  const safeConfig = snapshotGenericOidcConfig(config);
  const endpointFields = snapshotOwnDataRecord(resolved);
  const fields = snapshotOwnDataRecord(args);
  if (endpointFields === null || typeof endpointFields.tokenEndpoint !== "string"
    || (endpointFields.tokenAuthMethod !== "client_secret_post" && endpointFields.tokenAuthMethod !== "client_secret_basic")
    || fields === null || typeof fields.code !== "string" || !fields.code
    || typeof fields.codeVerifier !== "string" || !fields.codeVerifier) {
    throw new Error("generic_oidc_exchange_failed: exchange input is malformed");
  }
  assertValidHttpsEndpoint(endpointFields.tokenEndpoint, "tokenEndpoint");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: fields.code,
    redirect_uri: safeConfig.redirectUri,
    code_verifier: fields.codeVerifier,
  });
  const headers: Record<string, string> = {};
  if (safeConfig.clientSecret && endpointFields.tokenAuthMethod === "client_secret_basic") {
    // basic ⇒ clientId + secret in the Authorization header ONLY (RFC 6749 §2.3.1) — not duplicated in the body.
    headers.authorization = `Basic ${Buffer.from(`${formUrlEncode(safeConfig.clientId)}:${formUrlEncode(safeConfig.clientSecret)}`).toString("base64")}`;
  } else {
    body.set("client_id", safeConfig.clientId); // public + post: client identification lives in the body
    if (safeConfig.clientSecret) body.set("client_secret", safeConfig.clientSecret); // post
  }
  const response = captureHttpResponse(
    await transport.postForm(endpointFields.tokenEndpoint, body, headers), "text",
  );
  if (response === null) throw new Error("generic_oidc_exchange_failed: malformed transport response");
  if (response.status !== 200) { let detail = ""; try { const text = await response.read(); if (typeof text !== "string") throw new Error("malformed response body"); const e = snapshotOwnDataRecord(JSON.parse(text)); if (e && typeof e.error === "string") detail = `: ${e.error}${typeof e.error_description === "string" ? ` — ${e.error_description.replace(/[\r\n]+/g, " ")}` : ""}`; } catch { /* non-JSON error body — the HTTP status is the detail */ } throw new Error(`generic_oidc_exchange_failed: token endpoint returned HTTP ${response.status}${detail}`); }
  const text = await response.read();
  const parsed = typeof text === "string" ? snapshotOwnDataRecord(JSON.parse(text)) : null;
  if (parsed === null) throw new Error("generic_oidc_exchange_failed: token response must be a JSON data object");
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
    const argsSnapshot = snapshotOwnDataRecord(args);
    const allowedAlgs = argsSnapshot && snapshotOwnDataArray(argsSnapshot.allowedAlgs);
    if (argsSnapshot === null || allowedAlgs === null
      || !allowedAlgs.every((alg) => typeof alg === "string")
      || typeof argsSnapshot.validate !== "function") throw new Error("invalid verify options");
    // jose's `jwtVerify` is overloaded (concrete key vs getKey resolver). The JWKS
    // resolver is callable; concrete keys are not — narrow by `typeof === "function"`
    // so each branch matches its overload (a union arg would fail resolution).
    const verifyOpts = { algorithms: allowedAlgs as string[], currentDate: argsSnapshot.currentDate as Date | undefined };
    const { payload, protectedHeader } = typeof key === "function"
      ? await jwtVerify(token, key, verifyOpts)
      : await jwtVerify(token, key, verifyOpts);
    const headerSnapshot = snapshotOwnDataRecord(protectedHeader);
    if (headerSnapshot === null) throw new Error("invalid protected header");
    return (argsSnapshot.validate as VerifyIdTokenArgs["validate"])(payload as GenericOidcIdTokenPayload, {
      expectedNonce: argsSnapshot.expectedNonce as string | undefined,
      accessToken: argsSnapshot.accessToken as string | undefined,
      alg: typeof headerSnapshot.alg === "string" ? headerSnapshot.alg : undefined,
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
  const optionSnapshot = opts === undefined ? undefined : snapshotOwnDataRecord(opts);
  if (optionSnapshot === null) return { ok: false, reason: "generic_oidc_bad_claim" };
  return verifyIdTokenWithKey(token, key, {
    allowedAlgs: optionSnapshot?.allowedAlgs as string[] | undefined ?? resolveAllowedAlgs(undefined),
    validate: (p, o) => validateGenericOidcIdToken(p, config, o),
    expectedNonce: optionSnapshot?.expectedNonce as string | undefined,
    accessToken: optionSnapshot?.accessToken as string | undefined,
    currentDate: optionSnapshot?.currentDate as Date | undefined,
  });
}

/** Build the generic OIDC identity port (async: discovery is a boot fetch). */
export async function createGenericOidcIdentity(config: GenericOidcConfig, opts?: GenericOidcIdentityOpts): Promise<GenericOidcIdentity> {
  const optionSnapshot = opts === undefined ? undefined : snapshotOwnDataRecord(opts);
  if (optionSnapshot === null) throw new Error("generic_oidc_bad_config: options must be data objects");
  const safeConfig = snapshotGenericOidcConfig(config);
  assertValidHttpsEndpoint(safeConfig.issuer, "issuer");
  const resolved = await resolveEndpoints(safeConfig, optionSnapshot?.discoveryFetch as DiscoveryTransport | undefined);
  const jwks = createValidatedRemoteJWKSet(new URL(resolved.jwksUri), { cacheMaxAge: 5 * 60 * 1000 });
  const validate = optionSnapshot?.validate as GenericOidcIdentityOpts["validate"]
    ?? ((p, o) => validateGenericOidcIdToken(p, safeConfig, o));
  return {
    redirectUri: safeConfig.redirectUri,
    getAuthorizationUrl: (req) => getAuthorizationUrl(safeConfig, resolved, req),
    exchangeCodeForToken: (args, transport) => exchangeCodeForToken(safeConfig, resolved, args, transport ?? defaultTokenTransport),
    async verify(input, vopts) {
      if (typeof input !== "string" || !input) return { ok: false, reason: "generic_oidc_id_token_missing" };
      const verifySnapshot = vopts === undefined ? undefined : snapshotOwnDataRecord(vopts);
      if (verifySnapshot === null) return { ok: false, reason: "generic_oidc_bad_claim" };
      return verifyIdTokenWithKey(input, verifySnapshot?.verifyKey as VerifyKey | undefined ?? jwks, {
        allowedAlgs: verifySnapshot?.allowedAlgs as string[] | undefined ?? resolved.allowedAlgs,
        validate,
        expectedNonce: verifySnapshot?.expectedNonce as string | undefined,
        accessToken: verifySnapshot?.accessToken as string | undefined,
        currentDate: verifySnapshot?.currentDate as Date | undefined,
      });
    },
  };
}

// Re-exports for the ./identity/generic-oidc subpath.
export { validateGenericOidcIdToken, computeAtHash, subjectAllowedGeneric, resolveAllowedAlgs, type GenericOidcIdTokenPayload, type GenericOidcValidateOpts, type GenericOidcClaimConfig } from "./generic-oidc-claims.ts";
export { resolveEndpoints, defaultTokenTransport, defaultDiscoveryTransport, type ResolvedEndpoints, type DiscoveryTransport, type GenericOidcTokenTransport } from "./generic-oidc-discovery.ts";
export { createGenericOidcRedirectIdentity, type GenericOidcRedirectOpts } from "./generic-oidc-redirect.ts";
