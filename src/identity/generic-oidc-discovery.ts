// Boot-time endpoint resolution for the §17.6 generic OIDC port: OIDC Discovery
// (§17.6 "discover" mode) or deployer-supplied manual endpoints. Factored out of
// generic-oidc.ts to keep both files under the 250-line limit. Plain https
// throughout — NOT the §17.1 SSRF guard — because the issuer is deployer-trusted
// config and enterprise IdPs legitimately live on private networks (§17.6).
//
// Fail-closed boot rules: discovery-document `issuer` MUST exactly equal the
// configured issuer (OIDC Discovery §4.3 / RFC 8414 §3.3); every endpoint +
// `jwks_uri` MUST pass the raw `^https://` check (addendum 11); discovery
// redirects are NOT followed (a 3xx ⇒ boot failure); PKCE `S256` MUST be
// advertised unless `allowProviderWithoutPkce` is set (loud).

import { assertHttpsRaw } from "./util.ts";
import { resolveAllowedAlgs } from "./generic-oidc-claims.ts";
import {
  bindClassDataMethod, ownBooleanTrue, snapshotOwnDataRecord, snapshotOwnStringArray,
} from "../own-property.ts";
import { guardedGlobalFetch } from "../outbound-tls.ts";
import { captureHttpResponse } from "./util.ts";

/** Manual endpoint mode — zero boot-time fetching. */
export interface GenericOidcManualEndpoints {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
}
export type GenericOidcEndpoints = "discover" | GenericOidcManualEndpoints;

/** How a confidential client presents its secret at the token endpoint. */
export type TokenAuthMethod = "client_secret_post" | "client_secret_basic";

/** The config subset `resolveEndpoints` consumes. */
export interface GenericOidcDiscoveryConfig {
  issuer: string;
  endpoints: GenericOidcEndpoints;
  /** Confidential-client secret. Omit for a public client (PKCE only). */
  clientSecret?: string;
  /** Override the token-endpoint auth method for a confidential client (otherwise
   *  resolved from discovery `token_endpoint_auth_methods_supported`). */
  tokenEndpointAuthMethod?: TokenAuthMethod;
  /** Opt-in: accept a provider whose discovery omits PKCE support (loud). */
  allowProviderWithoutPkce?: boolean;
}

/** Injectable GET transport for the discovery document (tests avoid the network). */
export interface DiscoveryTransport {
  get(url: string): Promise<{ status: number; json(): Promise<unknown> }>;
}

/** Injectable POST transport for the token endpoint. `headers` carries the
 *  Authorization header when `client_secret_basic` is used. */
export interface GenericOidcTokenTransport {
  postForm(url: string, body: URLSearchParams, headers?: Record<string, string>): Promise<{ status: number; text(): Promise<string> }>;
}

/** Default discovery fetch: global fetch, redirects NOT followed (manual ⇒ a 3xx
 *  surfaces as status !== 200 ⇒ fail closed), 10 s hard deadline. */
export const defaultDiscoveryTransport: DiscoveryTransport = {
  async get(url) {
    const resp = await guardedGlobalFetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
      headers: { accept: "application/json" },
    });
    return { status: resp.status, json: () => resp.json() };
  },
};

/** Default token-endpoint transport: global fetch, 10 s hard deadline, redirects
 *  REFUSED. The POST body carries the code, PKCE verifier, and (for a confidential
 *  client) the client_secret — a redirected token endpoint would leak those to the
 *  redirect target, so `redirect: "error"` fails hard on any 3xx (the token URL is
 *  https-validated + deployer-trusted, so a redirect is never legitimate). */
export const defaultTokenTransport: GenericOidcTokenTransport = {
  async postForm(url, body, headers) {
    const resp = await guardedGlobalFetch(url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", ...(headers ?? {}) },
      body: body.toString(),
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
    return { status: resp.status, text: () => resp.text() };
  },
};

/** The endpoints + resolved alg set + token-auth method an identity holds after boot. */
export interface ResolvedEndpoints {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  allowedAlgs: string[];
  /** How a confidential client sends its secret (moot for a public client). */
  tokenAuthMethod: TokenAuthMethod;
}

function stringField(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) throw new Error(`generic_oidc_discovery_failed: discovery document missing ${label}`);
  return value;
}
/** Parse an OPTIONAL discovery string-array. Truly absent (undefined/null) ⇒
 *  undefined (callers default). Present-but-malformed (not an array, or an array
 *  with non-string entries) ⇒ throw — fetched metadata is untrusted, and a
 *  malformed security field (e.g. `id_token_signing_alg_values_supported: ["HS256", 7]`)
 *  must fail closed at boot, not silently collapse to the default. */
function asStringArray(value: unknown, label: string): string[] | undefined {
  if (value === undefined) return undefined; // truly absent (key not in the doc) ⇒ callers default
  // null (explicit) or non-array or array-with-non-strings ⇒ malformed ⇒ fail closed
  const values = snapshotOwnStringArray(value);
  if (values === null) throw new Error(`generic_oidc_discovery_failed: discovery '${label}' must contain a dense array of strings`);
  return [...values];
}

/** Raw `^https://` check (addendum 11 — BEFORE `new URL()`, which normalizes
 *  `https:/host`) AND a structural parse: a value like `https://` (no host) must
 *  fail at boot, not surface at the first authorize/exchange. Applies to the issuer
 *  (the exact-match OIDC trust root) + every endpoint, in discovery AND manual mode. */
export function assertValidHttpsEndpoint(value: string, label: string): void {
  assertHttpsRaw(value, label);
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`generic_oidc_bad_config: ${label} must be a valid https URL`); }
  if (url.protocol !== "https:" || !url.hostname) throw new Error(`generic_oidc_bad_config: ${label} must be a valid https URL with a hostname`);
}

/** application/x-www-form-urlencoded for a single value (RFC 6749 §2.3.1
 *  client_secret_basic): like encodeURIComponent except space ⇒ '+' (not %20). */
export function formUrlEncode(s: string): string {
  return encodeURIComponent(s).replace(/%20/g, "+");
}

/** Resolve the token-endpoint auth method for a confidential client. Honors the
 *  provider's advertised `token_endpoint_auth_methods_supported` so a basic-only
 *  issuer is not sent a `client_secret_post` body it would reject. When no method
 *  is advertised (discovery omitted OR manual mode) the OIDC default
 *  `client_secret_basic` (RFC 6749 §2.3.1) is used — consistent across both modes.
 *  A public client sends no secret, so the method is moot. A deployer override is trusted. */
export function resolveTokenAuthMethod(
  clientSecret: string | undefined,
  override: TokenAuthMethod | undefined,
  advertised: string[] | undefined,
): TokenAuthMethod {
  if (!clientSecret) return "client_secret_post";
  // A misspelled override (e.g. "basic", "client-secret-basic") must fail at boot, not silently
  // fall through to client_secret_post (exchangeCodeForToken only special-cases client_secret_basic).
  if (override !== undefined && override !== "client_secret_post" && override !== "client_secret_basic") {
    throw new Error("generic_oidc_bad_config: tokenEndpointAuthMethod must be 'client_secret_post' or 'client_secret_basic'");
  }
  if (override) return override;
  if (advertised === undefined) return "client_secret_basic"; // OIDC default (discovery omitted + manual)
  const methods = snapshotOwnStringArray(advertised);
  if (methods === null) throw new Error("generic_oidc_no_supported_auth_method: malformed advertised method list");
  if (methods.includes("client_secret_post")) return "client_secret_post";
  if (methods.includes("client_secret_basic")) return "client_secret_basic";
  throw new Error("generic_oidc_no_supported_auth_method: the token endpoint advertises neither client_secret_post nor client_secret_basic (required for a confidential client)");
}

/** Resolve endpoints + the allowed-alg set. Discover mode fetches once at boot
 *  and enforces every §17.6 boot rule; manual mode https-checks each endpoint
 *  and skips discovery/PKCE (the deployer knows their provider). */
export async function resolveEndpoints(
  config: GenericOidcDiscoveryConfig,
  transport?: DiscoveryTransport,
): Promise<ResolvedEndpoints> {
  const configSnapshot = snapshotOwnDataRecord(config);
  if (configSnapshot === null) throw new Error("generic_oidc_config_invalid: config must be a data object");
  const safeConfig = configSnapshot as unknown as GenericOidcDiscoveryConfig;
  if (safeConfig.endpoints === "discover") {
    assertValidHttpsEndpoint(safeConfig.issuer, "issuer");
    // Trim trailing slashes without a regex: `/\/+$/` over env-sourced config trips
    // CodeQL js/polynomial-redos; a bounded slice loop is unambiguously linear.
    let issuer = safeConfig.issuer;
    while (issuer.endsWith("/")) issuer = issuer.slice(0, -1);
    const discoveryUrl = issuer + "/.well-known/openid-configuration";
    const fetcher = transport ?? defaultDiscoveryTransport;
    const get = bindClassDataMethod<DiscoveryTransport["get"]>(fetcher, "get");
    if (get === undefined) {
      throw new Error("generic_oidc_discovery_failed: discovery transport is malformed");
    }
    const resp = captureHttpResponse(await get(discoveryUrl), "json");
    if (resp === null) throw new Error("generic_oidc_discovery_failed: malformed transport response");
    if (resp.status !== 200) throw new Error(`generic_oidc_discovery_failed: discovery fetch returned HTTP ${resp.status} (redirects are not followed)`);
    const docRaw = await resp.read();
    // Fetched metadata is untrusted: a non-object doc (JSON null/array/primitive) must fail closed,
    // not crash on `doc.issuer` or best-effort parse (fail-closed on untrusted input).
    const doc = snapshotOwnDataRecord(docRaw);
    if (doc === null) throw new Error("generic_oidc_discovery_failed: discovery document must be a JSON data object");
    const docIssuer = doc.issuer;
    if (typeof docIssuer !== "string" || docIssuer !== safeConfig.issuer) {
      throw new Error("generic_oidc_discovery_issuer_mismatch: the document's `issuer` must exactly equal the configured issuer (OIDC Discovery §4.3)");
    }
    const authorizationEndpoint = stringField(doc.authorization_endpoint, "authorization_endpoint");
    const tokenEndpoint = stringField(doc.token_endpoint, "token_endpoint");
    const jwksUri = stringField(doc.jwks_uri, "jwks_uri");
    assertValidHttpsEndpoint(authorizationEndpoint, "authorization_endpoint");
    assertValidHttpsEndpoint(tokenEndpoint, "token_endpoint");
    assertValidHttpsEndpoint(jwksUri, "jwks_uri");
    const allowedAlgs = resolveAllowedAlgs(asStringArray(doc.id_token_signing_alg_values_supported, "id_token_signing_alg_values_supported"));
    const methods = asStringArray(doc.code_challenge_methods_supported, "code_challenge_methods_supported") ?? [];
    if (!methods.includes("S256")) {
      if (!ownBooleanTrue(safeConfig, "allowProviderWithoutPkce")) {
        throw new Error("generic_oidc_no_pkce: discovery does not advertise PKCE S256 (code_challenge_methods_supported omits S256 — RFC 8414 ⇒ no PKCE); set allowProviderWithoutPkce to proceed (state + nonce + client secret still bind the flow)");
      }
      console.warn("[mcp-sso] generic OIDC provider does not advertise PKCE S256; proceeding with allowProviderWithoutPkce=true. PKCE is a recommended code-injection defense — prefer a provider that supports it.");
    }
    const tokenAuthMethod = resolveTokenAuthMethod(safeConfig.clientSecret, safeConfig.tokenEndpointAuthMethod, asStringArray(doc.token_endpoint_auth_methods_supported, "token_endpoint_auth_methods_supported"));
    return { authorizationEndpoint, tokenEndpoint, jwksUri, allowedAlgs, tokenAuthMethod };
  }
  // Manual mode: no fetch; validate each endpoint URL; default alg pin; no PKCE check.
  const endpoints = snapshotOwnDataRecord(safeConfig.endpoints);
  if (endpoints === null) throw new Error("generic_oidc_config_invalid: endpoints must be a data object");
  const authorizationEndpoint = endpoints.authorizationEndpoint;
  const tokenEndpoint = endpoints.tokenEndpoint;
  const jwksUri = endpoints.jwksUri;
  assertValidHttpsEndpoint(authorizationEndpoint as string, "authorizationEndpoint");
  assertValidHttpsEndpoint(tokenEndpoint as string, "tokenEndpoint");
  assertValidHttpsEndpoint(jwksUri as string, "jwksUri");
  return {
    authorizationEndpoint: authorizationEndpoint as string,
    tokenEndpoint: tokenEndpoint as string,
    jwksUri: jwksUri as string,
    allowedAlgs: resolveAllowedAlgs(undefined),
    tokenAuthMethod: resolveTokenAuthMethod(safeConfig.clientSecret, safeConfig.tokenEndpointAuthMethod, undefined),
  };
}
