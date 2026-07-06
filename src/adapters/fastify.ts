// Fastify adapter (contracts §9.6). Thin wiring over the framework-free Bridge; all
// OAuth logic stays in the core. Maps NormResponse to Fastify (302 for redirects,
// status+body otherwise). The consumer supplies a Bridge + an IdentityPort; the
// adapter resolves the subject from `identityHeader` (default Cf-Access-Jwt-Assertion).

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { IdentityPort } from "../ports/identity.ts";
import { pathAfterOrigin } from "../config.ts";
import { asDirectOAuth, Bridge } from "./bridge.ts";
import { headerString, oauthErrorResponse, type NormRequest, type NormResponse } from "./http.ts";

export interface FastifyAdapterOptions {
  bridge: Bridge;
  /** IdentityPort for the default header-based authorize. Required unless
   *  `skipAuthorize` is set (console pairing owns the authorize route). */
  identity?: IdentityPort;
  /** Header carrying the upstream identity credential. Default: cf-access-jwt-assertion. */
  identityHeader?: string;
  /** When true, GET /oauth/authorize is NOT registered — the caller mounts its
   *  own (e.g. a console-pairing surface via handlePairingAuthorize). All other
   *  routes are unaffected. Default false (header-based authorize). */
  skipAuthorize?: boolean;
}

export async function registerOAuthRoutes(app: FastifyInstance, opts: FastifyAdapterOptions): Promise<void> {
  const { bridge, identity, identityHeader = "cf-access-jwt-assertion", skipAuthorize = false } = opts;

  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_req, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(String(body))));
  });

  const toNorm = (req: FastifyRequest): NormRequest => ({
    query: req.query as NormRequest["query"],
    body: req.body,
    headers: req.headers as NormRequest["headers"],
    ip: req.ip,
  });
  const send = async (reply: FastifyReply, res: NormResponse): Promise<void> => {
    for (const [key, value] of Object.entries(res.headers)) reply.header(key, value);
    if (res.redirect) { await reply.redirect(res.redirect, res.status); return; }
    reply.code(res.status).send(res.body);
  };

  const resourcePath = pathAfterOrigin(bridge.config.resource); // e.g. "/mcp"
  app.get("/.well-known/oauth-authorization-server", async (_req, reply) => send(reply, await bridge.handleAuthorizationServerMetadata()));
  app.get("/.well-known/oauth-protected-resource", async (_req, reply) => send(reply, await bridge.handleProtectedResourceMetadata()));
  app.get(`/.well-known/oauth-protected-resource${resourcePath}`, async (_req, reply) => send(reply, await bridge.handleProtectedResourceMetadata()));
  app.get("/oauth/jwks", async (_req, reply) => send(reply, await bridge.handleJwks()));
  app.post("/oauth/register", async (req, reply) => send(reply, await bridge.handleRegister(toNorm(req))));
  if (!skipAuthorize) {
    if (!identity) throw new Error("registerOAuthRoutes: identity is required unless skipAuthorize is set");
    const id = identity;
    app.get("/oauth/authorize", async (req, reply) => {
      // Identity resolution is pre-validation. Route throws through the direct
      // §9.5 path, stripping any redirect target a user-supplied IdentityPort put
      // on an OAuthError and hiding non-OAuth details (verification.md HF.3).
      // bridge.resolveIdentity also emits the identity.verify audit event.
      let identityResolved: { subject: string; allowedScopes?: string[] };
      try {
        identityResolved = await bridge.resolveIdentity(id, headerString(req.headers, identityHeader), req.ip);
      } catch (error) {
        await send(reply, oauthErrorResponse(asDirectOAuth(error)));
        return;
      }
      await send(reply, await bridge.handleAuthorize(toNorm(req), identityResolved));
    });
  }
  app.post("/oauth/authorize/approve", async (req, reply) => send(reply, await bridge.handleApprove(toNorm(req))));
  app.post("/oauth/token", async (req, reply) => send(reply, await bridge.handleToken(toNorm(req))));
  app.post("/oauth/revoke", async (req, reply) => send(reply, await bridge.handleRevoke(toNorm(req))));
}
