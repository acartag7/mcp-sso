// Hono transport adapter (contracts §9.6). OAuth domain decisions stay in the
// framework-free core; this layer applies body/framing limits and normalizes
// request data. Returns a Hono instance. NormResponse maps to c.redirect (302) or
// c.json/c.body otherwise.

import { Hono } from "hono";
import type { Context } from "hono";
import type { MiddlewareHandler } from "hono";
import { bodyLimit } from "hono/body-limit";
import type { IdentityPort } from "../ports/identity.ts";
import { pathAfterOrigin } from "../config.ts";
import { asDirectOAuth, Bridge } from "./bridge.ts";
import type { UpstreamRedirectFlow } from "./upstream-flow.ts";
import {
  formBodySnapshot, headerString, oauthErrorResponse, OAUTH_POST_BODY_MAX_BYTES,
  type NormRequest, type NormResponse,
} from "./http.ts";
import { formOccurrencesFromUrlEncoded, hasDuplicatedAuthorizeParams, queryOccurrencesFromUrl } from "./authorize-params.ts";
import { OAuthError } from "../errors.ts";

export interface HonoAdapterOptions {
  bridge: Bridge;
  /** IdentityPort for the default header-based authorize. Required unless
   *  `skipAuthorize` is set (console pairing owns the authorize route). */
  identity?: IdentityPort;
  identityHeader?: string;
  /** When true, GET /oauth/authorize is NOT registered — the caller mounts its
   *  own. Default false. */
  skipAuthorize?: boolean;
  /** §17.11 upstream redirect-flow orchestrator. When set, GET /oauth/authorize
   *  → upstream.handleAuthorize and GET upstream.callbackPath → upstream.handleCallback.
   *  Mutually exclusive with `identity`/`identityHeader` and `skipAuthorize`. */
  upstream?: UpstreamRedirectFlow;
  /** Client-IP extractor for the rate-limit key (§6.7) and the audit `ip` field.
   *  Hono has no framework-validated `req.ip` (fastify/express key on theirs,
   *  gated by trustProxy config), so the deployer supplies one wired to their
   *  actual topology — e.g. the rightmost trusted X-Forwarded-For hop, or the
   *  runtime's connection info. Default: no IP — every request uses the one
   *  "unknown" rate-limit key and audit events omit `ip`. With a real limiter,
   *  client-controlled headers therefore cannot spread traffic across buckets;
   *  the no-op limiter default still permits every request. The adapter NEVER
   *  reads X-Forwarded-For on its own: an attacker-chosen header must not select
   *  the rate-limit bucket.
   *  Request own-property extensions survive POST body guarding. Extractors
   *  needing prototype-only/private runtime state must use stable `Context`
   *  environment data instead of relying on raw Request identity. */
  clientIp?: (c: Context) => string | undefined;
}

const CONTENT_LENGTH = /^(?:0|[1-9][0-9]*)$/;

function payloadTooLarge(): Response {
  return new Response("Payload Too Large", { status: 413 });
}

function invalidRequest(): Response {
  return new Response('{"error":"invalid_request","error_description":"Invalid request"}', {
    status: 400,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function restoreRequestExtensions(original: Request, replacement: Request): void {
  for (const key of Reflect.ownKeys(original)) {
    if (Object.hasOwn(replacement, key)) continue;
    const descriptor = Object.getOwnPropertyDescriptor(original, key);
    if (descriptor) Object.defineProperty(replacement, key, descriptor);
  }
}

// Hono 4.12.34's bodyLimit uses parseInt(Content-Length) and trusts a declared
// length that is within the cap. Validate the framing, reject CL+TE ambiguity,
// then hide a valid declaration from bodyLimit so it counts the actual stream.
const validateBodyFraming: MiddlewareHandler = async (c, next) => {
  const raw = c.req.raw;
  const contentLength = raw.headers.get("content-length");
  const transferEncoding = raw.headers.get("transfer-encoding");
  if (contentLength !== null) {
    if (!CONTENT_LENGTH.test(contentLength) || transferEncoding !== null) return payloadTooLarge();
    const declared = Number(contentLength);
    if (!Number.isSafeInteger(declared) || declared > OAUTH_POST_BODY_MAX_BYTES) return payloadTooLarge();
    if (raw.body !== null) {
      const headers = new Headers(raw.headers);
      headers.delete("content-length");
      const init: RequestInit & { duplex: "half" } = { headers, body: raw.body, duplex: "half" };
      c.req.raw = new Request(raw, init);
    }
  }
  await next();
};

const limitOAuthBody = bodyLimit({
  maxSize: OAUTH_POST_BODY_MAX_BYTES,
  onError: payloadTooLarge,
});

/** Apply before body parsing on caller-owned Hono OAuth POST routes. */
export const honoOAuthBodyLimit: MiddlewareHandler = async (c, next) => {
  const original = c.req.raw;
  const restore = (): void => {
    if (c.req.raw !== original) restoreRequestExtensions(original, c.req.raw);
  };
  let downstream: Response | void = undefined;
  let downstreamStarted = false;
  try {
    const framing = await validateBodyFraming(c, async () => {
      restore();
      downstream = await limitOAuthBody(c, async () => {
        restore();
        downstreamStarted = true;
        await next();
      });
    });
    restore();
    return framing ?? downstream;
  } catch (error) {
    restore();
    if (downstreamStarted) throw error;
    return invalidRequest();
  }
};

export function createOAuthApp(opts: HonoAdapterOptions): Hono {
  const app = new Hono();
  const { bridge, identity, identityHeader = "cf-access-jwt-assertion", skipAuthorize = false, upstream, clientIp } = opts;

  const toNorm = async (c: Context): Promise<NormRequest> => {
    const ct = (c.req.header("content-type")?.split(";", 1)[0] ?? "").trim().toLowerCase();
    let body: unknown;
    try {
      if (ct === "application/json") body = await c.req.json();
      else if (ct === "application/x-www-form-urlencoded") body = formOccurrencesFromUrlEncoded(await c.req.text());
    } catch { body = undefined; }
    const headers: NormRequest["headers"] = {};
    c.req.raw.headers.forEach((value, key) => { headers[key] = value; });
    // Parse the raw query so repeated keys survive as arrays — Hono's c.req.query()
    // collapses duplicates to the first value, which would defeat the RFC 6749 §3.1
    // duplicate-param checks (contracts §17.11 authorize step 2 / callback row 1).
    // Single-valued params stay strings (unchanged behavior for every other route).
    const query = queryOccurrencesFromUrl(c.req.raw.url);
    return { query, body, formBody: formBodySnapshot(body, headers), headers, ip: clientIp?.(c) };
  };
  // Build a standard Response directly: hono route handlers accept a Response,
  // and this sidesteps hono's strict RedirectStatusCode/ContentfulStatusCode unions
  // (our NormResponse.status is a plain number set by the Bridge).
  const send = (_c: Context, r: NormResponse): Response => {
    const headers = new Headers();
    for (const [key, value] of Object.entries(r.headers)) headers.set(key, value);
    if (r.redirect) {
      headers.set("location", r.redirect);
      return new Response(null, { status: r.status, headers });
    }
    if (typeof r.body === "string") return new Response(r.body, { status: r.status, headers });
    if (!headers.has("content-type")) headers.set("content-type", "application/json; charset=utf-8");
    return new Response(r.body === undefined || r.body === null ? null : JSON.stringify(r.body), { status: r.status, headers });
  };

  const resourcePath = pathAfterOrigin(bridge.config.resource);
  app.get("/.well-known/oauth-authorization-server", async (c) => send(c, await bridge.handleAuthorizationServerMetadata()));
  app.get("/.well-known/oauth-protected-resource", async (c) => send(c, await bridge.handleProtectedResourceMetadata()));
  app.get(`/.well-known/oauth-protected-resource${resourcePath}`, async (c) => send(c, await bridge.handleProtectedResourceMetadata()));
  app.get("/oauth/jwks", async (c) => send(c, await bridge.handleJwks()));
  app.post("/oauth/register", honoOAuthBodyLimit, async (c) => send(c, await bridge.handleRegister(await toNorm(c))));
  if (upstream && (identity || skipAuthorize)) {
    throw new Error("createOAuthApp: 'upstream' is mutually exclusive with 'identity'/'identityHeader' and 'skipAuthorize' (exactly one authorize mode — §17.11)");
  }
  if (upstream) {
    const up = upstream;
    app.get("/oauth/authorize", async (c) => send(c, await up.handleAuthorize(await toNorm(c))));
    app.get(up.callbackPath, async (c) => send(c, await up.handleCallback(await toNorm(c))));
  } else if (!skipAuthorize) {
    if (!identity) throw new Error("createOAuthApp: identity is required unless skipAuthorize or upstream is set");
    const id = identity;
    app.get("/oauth/authorize", async (c) => {
      // Identity resolution is pre-validation. Route throws through the direct
      // §9.5 path, stripping any redirect target a user-supplied IdentityPort put
      // on an OAuthError and hiding non-OAuth details (verification.md HF.3).
      // bridge.resolveIdentity also emits the identity.verify audit event.
      let identityResolved: { subject: string; allowedScopes?: string[] };
      const req = await toNorm(c);
      if (hasDuplicatedAuthorizeParams(req.query)) {
        return send(c, oauthErrorResponse(bridge.config, new OAuthError("invalid_request", "duplicate request parameters")));
      }
      try {
        identityResolved = await bridge.resolveIdentity(id, headerString(req.headers, identityHeader), req.ip);
      } catch (error) {
        return send(c, oauthErrorResponse(bridge.config, asDirectOAuth(error)));
      }
      return send(c, await bridge.handleAuthorize(req, identityResolved));
    });
  }
  app.post("/oauth/authorize/approve", honoOAuthBodyLimit, async (c) => send(c, await bridge.handleApprove(await toNorm(c))));
  app.post("/oauth/token", honoOAuthBodyLimit, async (c) => send(c, await bridge.handleToken(await toNorm(c))));
  app.post("/oauth/revoke", honoOAuthBodyLimit, async (c) => send(c, await bridge.handleRevoke(await toNorm(c))));
  return app;
}
