// Express adapter (contracts §9.6). Thin wiring over the framework-free Bridge.
// The returned Router owns bounded OAuth JSON/form parsing. Maps NormResponse → Express.

import { json, Router, urlencoded } from "express";
import type { NextFunction, Request, Response } from "express";
import type { IdentityPort } from "../ports/identity.ts";
import { pathAfterOrigin } from "../config.ts";
import { asDirectOAuth, Bridge } from "./bridge.ts";
import type { UpstreamRedirectFlow } from "./upstream-flow.ts";
import { headerString, headersFromDistinct, oauthErrorResponse, type NormRequest, type NormResponse } from "./http.ts";
import { hasDuplicatedAuthorizeParams, queryOccurrencesFromUrl } from "./authorize-params.ts";
import { OAuthError } from "../errors.ts";

/** Raw JSON and form budget for the built-in OAuth POST routes (§9.6). */
export const EXPRESS_OAUTH_BODY_MAX_BYTES = 256 * 1024;

function parserErrorStatus(error: unknown): 400 | 413 | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const status = (error as { status?: unknown }).status;
  return status === 400 || status === 413 ? status : undefined;
}

export interface ExpressAdapterOptions {
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
}

export function createOAuthRouter(opts: ExpressAdapterOptions): Router {
  const router = Router();
  // Keep the framework parser boundary aligned with the core-supported OAuth
  // request domain. This lives inside the returned router, so unrelated app
  // routes do not inherit the OAuth limit.
  router.use(json({ limit: EXPRESS_OAUTH_BODY_MAX_BYTES }));
  router.use(urlencoded({ extended: false, limit: EXPRESS_OAUTH_BODY_MAX_BYTES }));
  const { bridge, identity, identityHeader = "cf-access-jwt-assertion", skipAuthorize = false, upstream } = opts;

  const toNorm = (req: Request): NormRequest => ({
    query: queryOccurrencesFromUrl(req.originalUrl),
    body: req.body,
    headers: headersFromDistinct(req.headersDistinct, req.headers as NormRequest["headers"]),
    ip: req.ip,
  });
  const send = (res: Response, r: NormResponse): void => {
    for (const [key, value] of Object.entries(r.headers)) res.set(key, value);
    if (r.redirect) { res.redirect(r.status, r.redirect); return; }
    res.status(r.status).send(r.body);
  };
  // Last-resort handler: route escaped throws through the direct §9.5 path. The
  // Bridge is the only layer that may emit redirect-tagged errors after request
  // validation; adapter-level catches strip redirect targets and hide non-OAuth
  // details (verification.md HF.3).
  const wrap = (fn: (req: Request, res: Response) => Promise<void>): (req: Request, res: Response) => Promise<void> =>
    (req, res) => fn(req, res).catch((error) => { send(res, oauthErrorResponse(bridge.config, asDirectOAuth(error))); });

  const resourcePath = pathAfterOrigin(bridge.config.resource);
  router.get("/.well-known/oauth-authorization-server", wrap(async (_req, res) => send(res, await bridge.handleAuthorizationServerMetadata())));
  router.get("/.well-known/oauth-protected-resource", wrap(async (_req, res) => send(res, await bridge.handleProtectedResourceMetadata())));
  router.get(`/.well-known/oauth-protected-resource${resourcePath}`, wrap(async (_req, res) => send(res, await bridge.handleProtectedResourceMetadata())));
  router.get("/oauth/jwks", wrap(async (_req, res) => send(res, await bridge.handleJwks())));
  router.post("/oauth/register", wrap(async (req, res) => send(res, await bridge.handleRegister(toNorm(req)))));
  if (upstream && (identity || skipAuthorize)) {
    throw new Error("createOAuthRouter: 'upstream' is mutually exclusive with 'identity'/'identityHeader' and 'skipAuthorize' (exactly one authorize mode — §17.11)");
  }
  if (upstream) {
    const up = upstream;
    router.get("/oauth/authorize", wrap(async (req, res) => send(res, await up.handleAuthorize(toNorm(req)))));
    router.get(up.callbackPath, wrap(async (req, res) => send(res, await up.handleCallback(toNorm(req)))));
  } else if (!skipAuthorize) {
    if (!identity) throw new Error("createOAuthRouter: identity is required unless skipAuthorize or upstream is set");
    const id = identity;
    // Bridge.resolveIdentity applies the custom RateLimitPort before IdentityPort;
    // CodeQL models only named Express limiter packages, not this library port.
    // codeql[js/missing-rate-limiting]
    router.get("/oauth/authorize", wrap(async (req, res) => {
      const request = toNorm(req);
      if (hasDuplicatedAuthorizeParams(request.query)) {
        send(res, oauthErrorResponse(bridge.config, new OAuthError("invalid_request", "duplicate request parameters")));
        return;
      }
      const identityResolved = await bridge.resolveIdentity(id, headerString(request.headers, identityHeader), request.ip);
      send(res, await bridge.handleAuthorize(request, identityResolved));
    }));
  }
  router.post("/oauth/authorize/approve", wrap(async (req, res) => send(res, await bridge.handleApprove(toNorm(req)))));
  router.post("/oauth/token", wrap(async (req, res) => send(res, await bridge.handleToken(toNorm(req)))));
  router.post("/oauth/revoke", wrap(async (req, res) => send(res, await bridge.handleRevoke(toNorm(req)))));
  // Body-parser errors bypass route wrappers. Keep malformed and over-cap OAuth
  // requests on the adapter's direct error channel instead of Express's default
  // development stack response/logging path.
  router.use((error: unknown, _req: Request, res: Response, next: NextFunction) => {
    const status = parserErrorStatus(error);
    if (status === undefined) { next(error); return; }
    send(res, {
      status,
      headers: {},
      body: { error: "invalid_request", error_description: status === 413 ? "Request body is too large" : "Invalid request" },
    });
  });
  return router;
}
