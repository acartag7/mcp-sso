// The §17.6 default HTTP transports with stream-counted body caps, plus the
// token-endpoint exchange that consumes the token transport (moved here from
// generic-oidc.ts to keep both files under the 250-line limit). The caps are
// hard limits on untrusted input: a hostile or broken IdP cannot force the
// bridge to buffer an arbitrary discovery document or token response before
// any validation runs. Both caps follow the CIMD `maxDocumentBytes` shape —
// a closed integer domain, boot-validated (fail closed on misconfig, never a
// silent default). Cap rejections are fetch/protocol failures in the existing
// taxonomy (`generic_oidc_discovery_failed` / `generic_oidc_exchange_failed`)
// — the §17.11 throw rule maps them to `exchange_failed`, never
// `identity_rejected`. A deployer-supplied custom transport owns its own body
// discipline; these caps govern the transports the core builds from config.

import { readCappedText } from "./util.ts";
import { formUrlEncode, type DiscoveryTransport, type GenericOidcTokenTransport, type ResolvedEndpoints } from "./generic-oidc-discovery.ts";
import type { GenericOidcConfig, GenericOidcTokenResponse } from "./generic-oidc.ts";

/** Default discovery-document cap: 64 KiB (§17.6 owner decision D5). Real
 *  discovery documents are a few KB; 64 KiB fits every known provider with an
 *  order of magnitude of slack. */
export const DEFAULT_MAX_DISCOVERY_DOCUMENT_BYTES = 65536;
/** Default token-response cap: 16 KiB (§17.6 owner decision D5). A token
 *  response is two JWTs plus OAuth fields — a few KB at most. */
export const DEFAULT_MAX_TOKEN_RESPONSE_BYTES = 16384;
/** Closed integer domain for BOTH caps (the CIMD §17.1.5 rule-21 shape):
 *  non-integer, `NaN`, `Infinity`, or out-of-domain values are boot failures. */
const CAP_MIN = 1024;
const CAP_MAX = 1048576;

/** Resolve `maxDiscoveryDocumentBytes` (default 65536), throwing
 *  `generic_oidc_bad_config` on an out-of-domain value. Called at boot so a
 *  misconfigured cap fails before any fetch, in discovery AND manual mode. */
export function discoveryDocumentCap(value: number | undefined): number {
  if (value === undefined) return DEFAULT_MAX_DISCOVERY_DOCUMENT_BYTES;
  if (typeof value !== "number" || !Number.isInteger(value) || value < CAP_MIN || value > CAP_MAX) {
    throw new Error(`generic_oidc_bad_config: maxDiscoveryDocumentBytes must be an integer in [${CAP_MIN}, ${CAP_MAX}]`);
  }
  return value;
}

/** Resolve `maxTokenResponseBytes` (default 16384) — same domain, same rules. */
export function tokenResponseCap(value: number | undefined): number {
  if (value === undefined) return DEFAULT_MAX_TOKEN_RESPONSE_BYTES;
  if (typeof value !== "number" || !Number.isInteger(value) || value < CAP_MIN || value > CAP_MAX) {
    throw new Error(`generic_oidc_bad_config: maxTokenResponseBytes must be an integer in [${CAP_MIN}, ${CAP_MAX}]`);
  }
  return value;
}

/** Build the discovery GET transport with its byte cap. Global fetch, redirects
 *  NOT followed (manual ⇒ a 3xx surfaces as status !== 200 ⇒ fail closed),
 *  10 s hard deadline; `json()` stream-counts the body and rejects past the
 *  cap without materializing the remainder. */
export function createDiscoveryTransport(maxDocumentBytes: number): DiscoveryTransport {
  return {
    async get(url) {
      const resp = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(10_000), headers: { accept: "application/json" } });
      return {
        status: resp.status,
        json: () => readCappedText(resp.body, maxDocumentBytes, `generic_oidc_discovery_failed: discovery document exceeded the ${maxDocumentBytes}-byte cap`)
          .then((text) => JSON.parse(text)),
      };
    },
  };
}

/** Build the token-endpoint POST transport with its byte cap. Global fetch, 10 s
 *  hard deadline, redirects REFUSED. The POST body carries the code, PKCE
 *  verifier, and (for a confidential client) the client_secret — a redirected
 *  token endpoint would leak those to the redirect target, so `redirect:
 *  "error"` fails hard on any 3xx (the token URL is https-validated +
 *  deployer-trusted, so a redirect is never legitimate). `text()` stream-counts
 *  the response and rejects past the cap. */
export function createTokenTransport(maxResponseBytes: number): GenericOidcTokenTransport {
  return {
    async postForm(url, body, headers) {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", ...(headers ?? {}) },
        body: body.toString(),
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      return { status: resp.status, text: () => readCappedText(resp.body, maxResponseBytes, `generic_oidc_exchange_failed: token response exceeded the ${maxResponseBytes}-byte cap`) };
    },
  };
}

/** Default transports at the default caps (back-compat import surface). */
export const defaultDiscoveryTransport: DiscoveryTransport = createDiscoveryTransport(DEFAULT_MAX_DISCOVERY_DOCUMENT_BYTES);
export const defaultTokenTransport: GenericOidcTokenTransport = createTokenTransport(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);

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
  // Read the body ONCE (the default transport caps + aborts past maxTokenResponseBytes
  // here — an oversized body throws instead of being materialized), then use it for
  // both the non-200 detail and the success parse.
  const text = await resp.text();
  if (resp.status !== 200) { let detail = ""; try { const e = JSON.parse(text) as { error?: unknown; error_description?: unknown }; if (typeof e.error === "string") detail = `: ${e.error}${typeof e.error_description === "string" ? ` — ${String(e.error_description).replace(/[\r\n]+/g, " ")}` : ""}`; } catch { /* non-JSON error body — the HTTP status is the detail */ } throw new Error(`generic_oidc_exchange_failed: token endpoint returned HTTP ${resp.status}${detail}`); }
  const parsed = JSON.parse(text) as Partial<GenericOidcTokenResponse>;
  if (typeof parsed.id_token !== "string" || !parsed.id_token) throw new Error("generic_oidc_exchange_failed: token response missing id_token");
  // access_token is REQUIRED in the code flow (OIDC §3.1.3.3) — requiring it also
  // guarantees a present at_hash is validated (no header-mode skip in the code flow).
  if (typeof parsed.access_token !== "string" || !parsed.access_token) throw new Error("generic_oidc_exchange_failed: token response missing access_token (required in the OIDC code flow)");
  return { id_token: parsed.id_token, access_token: parsed.access_token };
}
