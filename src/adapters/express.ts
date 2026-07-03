// Express adapter (contracts §9.6). Thin wiring over the framework-free Bridge.
// Returns an Express Router the consumer mounts with `app.use(express.urlencoded(...))`
// already enabled (form parsing). Maps NormResponse → Express.

import { Router } from "express";
import type { Request, Response } from "express";
import type { IdentityPort } from "../ports/identity.ts";
import { pathAfterOrigin } from "../config.ts";
import { Bridge } from "./bridge.ts";
import { headerString, resolveSubject, type NormRequest, type NormResponse } from "./http.ts";

export interface ExpressAdapterOptions {
  bridge: Bridge;
  identity: IdentityPort;
  identityHeader?: string;
}

export function createOAuthRouter(opts: ExpressAdapterOptions): Router {
  const router = Router();
  const { bridge, identity, identityHeader = "cf-access-jwt-assertion" } = opts;

  const toNorm = (req: Request): NormRequest => ({
    query: req.query as NormRequest["query"],
    body: req.body,
    headers: req.headers as NormRequest["headers"],
    ip: req.ip,
  });
  const send = (res: Response, r: NormResponse): void => {
    for (const [key, value] of Object.entries(r.headers)) res.set(key, value);
    if (r.redirect) { res.redirect(r.status, r.redirect); return; }
    res.status(r.status).send(r.body);
  };
  const wrap = (fn: (req: Request, res: Response) => Promise<void>): (req: Request, res: Response) => Promise<void> =>
    (req, res) => fn(req, res).catch((error) => { res.status(500).send({ error: { code: "internal_error", message: String(error) } }); });

  const resourcePath = pathAfterOrigin(bridge.config.resource);
  router.get("/.well-known/oauth-authorization-server", wrap(async (_req, res) => send(res, await bridge.handleAuthorizationServerMetadata())));
  router.get("/.well-known/oauth-protected-resource", wrap(async (_req, res) => send(res, await bridge.handleProtectedResourceMetadata())));
  router.get(`/.well-known/oauth-protected-resource${resourcePath}`, wrap(async (_req, res) => send(res, await bridge.handleProtectedResourceMetadata())));
  router.get("/oauth/jwks", wrap(async (_req, res) => send(res, await bridge.handleJwks())));
  router.post("/oauth/register", wrap(async (req, res) => send(res, await bridge.handleRegister(toNorm(req)))));
  router.get("/oauth/authorize", wrap(async (req, res) => {
    const subject = await resolveSubject(identity, headerString(req.headers, identityHeader));
    send(res, await bridge.handleAuthorize(toNorm(req), subject));
  }));
  router.post("/oauth/authorize/approve", wrap(async (req, res) => send(res, await bridge.handleApprove(toNorm(req)))));
  router.post("/oauth/token", wrap(async (req, res) => send(res, await bridge.handleToken(toNorm(req)))));
  router.post("/oauth/revoke", wrap(async (req, res) => send(res, await bridge.handleRevoke(toNorm(req)))));
  return router;
}
