// Hono adapter (contracts §9.6). Thin wiring over the framework-free Bridge; all
// OAuth logic stays in the core. Returns a Hono instance. Form bodies are parsed
// via parseBody; NormResponse maps to c.redirect (302) or c.json/c.body otherwise.

import { Hono } from "hono";
import type { Context } from "hono";
import type { IdentityPort } from "../ports/identity.ts";
import { pathAfterOrigin } from "../config.ts";
import { asDirectOAuth, Bridge } from "./bridge.ts";
import { oauthErrorResponse, type NormRequest, type NormResponse } from "./http.ts";

export interface HonoAdapterOptions {
  bridge: Bridge;
  /** IdentityPort for the default header-based authorize. Required unless
   *  `skipAuthorize` is set (console pairing owns the authorize route). */
  identity?: IdentityPort;
  identityHeader?: string;
  /** When true, GET /oauth/authorize is NOT registered — the caller mounts its
   *  own. Default false. */
  skipAuthorize?: boolean;
}

export function createOAuthApp(opts: HonoAdapterOptions): Hono {
  const app = new Hono();
  const { bridge, identity, identityHeader = "cf-access-jwt-assertion", skipAuthorize = false } = opts;

  const toNorm = async (c: Context): Promise<NormRequest> => {
    const ct = c.req.header("content-type") ?? "";
    let body: unknown;
    try {
      if (ct.includes("application/json")) body = await c.req.json();
      else if (ct.includes("application/x-www-form-urlencoded") || ct.includes("multipart/form-data")) body = await c.req.parseBody();
    } catch { body = undefined; }
    const headers: NormRequest["headers"] = {};
    c.req.raw.headers.forEach((value, key) => { headers[key] = value; });
    return { query: c.req.query() as NormRequest["query"], body, headers, ip: c.req.header("x-forwarded-for") ?? "unknown" };
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
  app.post("/oauth/register", async (c) => send(c, await bridge.handleRegister(await toNorm(c))));
  if (!skipAuthorize) {
    if (!identity) throw new Error("createOAuthApp: identity is required unless skipAuthorize is set");
    const id = identity;
    app.get("/oauth/authorize", async (c) => {
      // Identity resolution is pre-validation. Route throws through the direct
      // §9.5 path, stripping any redirect target a user-supplied IdentityPort put
      // on an OAuthError and hiding non-OAuth details (verification.md HF.3).
      // bridge.resolveIdentity also emits the identity.verify audit event.
      let identityResolved: { subject: string; allowedScopes?: string[] };
      try {
        identityResolved = await bridge.resolveIdentity(id, c.req.header(identityHeader), c.req.header("x-forwarded-for") ?? "unknown");
      } catch (error) {
        return send(c, oauthErrorResponse(asDirectOAuth(error)));
      }
      return send(c, await bridge.handleAuthorize(await toNorm(c), identityResolved));
    });
  }
  app.post("/oauth/authorize/approve", async (c) => send(c, await bridge.handleApprove(await toNorm(c))));
  app.post("/oauth/token", async (c) => send(c, await bridge.handleToken(await toNorm(c))));
  app.post("/oauth/revoke", async (c) => send(c, await bridge.handleRevoke(await toNorm(c))));
  return app;
}
