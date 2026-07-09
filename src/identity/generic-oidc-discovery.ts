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
    const resp = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(10_000), headers: { accept: "application/json" } });
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
    const resp = await fetch(url, {
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
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value)) throw new Error(`generic_oidc_discovery_failed: discovery '${label}' must be an array when present`);
  if (!value.every((v) => typeof v === "string")) throw new Error(`generic_oidc_discovery_failed: discovery '${label}' must contain only strings`);
  return value;
}

/** Resolve the token-endpoint auth method for a confidential client. Honors the
 *  provider's advertised `token_endpoint_auth_methods_supported` so a basic-only
 *  issuer is not sent a `client_secret_post` body it would reject (the OIDC
 *  default when the field is omitted is `client_secret_basic`). A public client
 *  sends no secret, so the method is moot. A deployer override is trusted.
 *  Manual mode passes no advertised set ⇒ defaults to post (overridable). */
export function resolveTokenAuthMethod(
  clientSecret: string | undefined,
  override: TokenAuthMethod | undefined,
  advertised: string[] | undefined,
): TokenAuthMethod {
  if (!clientSecret) return "client_secret_post";
  if (override) return override;
  if (advertised === undefined) return "client_secret_post";
  if (advertised.includes("client_secret_post")) return "client_secret_post";
  if (advertised.includes("client_secret_basic")) return "client_secret_basic";
  throw new Error("generic_oidc_no_supported_auth_method: the token endpoint advertises neither client_secret_post nor client_secret_basic (required for a confidential client)");
}

/** Resolve endpoints + the allowed-alg set. Discover mode fetches once at boot
 *  and enforces every §17.6 boot rule; manual mode https-checks each endpoint
 *  and skips discovery/PKCE (the deployer knows their provider). */
export async function resolveEndpoints(
  config: GenericOidcDiscoveryConfig,
  transport?: DiscoveryTransport,
): Promise<ResolvedEndpoints> {
  if (config.endpoints === "discover") {
    assertHttpsRaw(config.issuer, "issuer");
    const discoveryUrl = config.issuer.replace(/\/+$/, "") + "/.well-known/openid-configuration";
    const fetcher = transport ?? defaultDiscoveryTransport;
    const resp = await fetcher.get(discoveryUrl);
    if (resp.status !== 200) throw new Error(`generic_oidc_discovery_failed: discovery fetch returned HTTP ${resp.status} (redirects are not followed)`);
    const doc = await resp.json() as Record<string, unknown>;
    const docIssuer = doc.issuer;
    if (typeof docIssuer !== "string" || docIssuer !== config.issuer) {
      throw new Error("generic_oidc_discovery_issuer_mismatch: the document's `issuer` must exactly equal the configured issuer (OIDC Discovery §4.3)");
    }
    const authorizationEndpoint = stringField(doc.authorization_endpoint, "authorization_endpoint");
    const tokenEndpoint = stringField(doc.token_endpoint, "token_endpoint");
    const jwksUri = stringField(doc.jwks_uri, "jwks_uri");
    assertHttpsRaw(authorizationEndpoint, "authorization_endpoint");
    assertHttpsRaw(tokenEndpoint, "token_endpoint");
    assertHttpsRaw(jwksUri, "jwks_uri");
    const allowedAlgs = resolveAllowedAlgs(asStringArray(doc.id_token_signing_alg_values_supported, "id_token_signing_alg_values_supported"));
    const methods = asStringArray(doc.code_challenge_methods_supported, "code_challenge_methods_supported") ?? [];
    if (!methods.includes("S256")) {
      if (!config.allowProviderWithoutPkce) {
        throw new Error("generic_oidc_no_pkce: discovery does not advertise PKCE S256 (code_challenge_methods_supported omits S256 — RFC 8414 ⇒ no PKCE); set allowProviderWithoutPkce to proceed (state + nonce + client secret still bind the flow)");
      }
      console.warn("[mcp-sso] generic OIDC provider does not advertise PKCE S256; proceeding with allowProviderWithoutPkce=true. PKCE is a recommended code-injection defense — prefer a provider that supports it.");
    }
    // token_endpoint_auth_methods_supported omitted ⇒ OIDC default client_secret_basic.
    const tokenAuthMethod = resolveTokenAuthMethod(config.clientSecret, config.tokenEndpointAuthMethod, asStringArray(doc.token_endpoint_auth_methods_supported, "token_endpoint_auth_methods_supported") ?? ["client_secret_basic"]);
    return { authorizationEndpoint, tokenEndpoint, jwksUri, allowedAlgs, tokenAuthMethod };
  }
  // Manual mode: no fetch; https-check each endpoint; default alg pin; no PKCE check.
  assertHttpsRaw(config.endpoints.authorizationEndpoint, "authorizationEndpoint");
  assertHttpsRaw(config.endpoints.tokenEndpoint, "tokenEndpoint");
  assertHttpsRaw(config.endpoints.jwksUri, "jwksUri");
  return {
    authorizationEndpoint: config.endpoints.authorizationEndpoint,
    tokenEndpoint: config.endpoints.tokenEndpoint,
    jwksUri: config.endpoints.jwksUri,
    allowedAlgs: resolveAllowedAlgs(undefined),
    tokenAuthMethod: resolveTokenAuthMethod(config.clientSecret, config.tokenEndpointAuthMethod, undefined),
  };
}
