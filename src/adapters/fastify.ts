// Fastify adapter (contracts §9.6). Thin wiring over the framework-free Bridge; all
// OAuth logic stays in the core. Maps NormResponse to Fastify (302 for redirects,
// status+body otherwise). The consumer supplies a Bridge + an IdentityPort; the
// adapter resolves the subject from `identityHeader` (default Cf-Access-Jwt-Assertion).

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { IdentityPort } from "../ports/identity.ts";
import { pathAfterOrigin } from "../config.ts";
import { OAuthError } from "../errors.ts";
import { Bridge } from "./bridge.ts";
import { headerString, oauthErrorResponse, resolveSubject, type NormRequest, type NormResponse } from "./http.ts";

export interface FastifyAdapterOptions {
  bridge: Bridge;
  identity: IdentityPort;
  /** Header carrying the upstream identity credential. Default: cf-access-jwt-assertion. */
  identityHeader?: string;
}

export async function registerOAuthRoutes(app: FastifyInstance, opts: FastifyAdapterOptions): Promise<void> {
  const { bridge, identity, identityHeader = "cf-access-jwt-assertion" } = opts;

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
  app.get("/oauth/authorize", async (req, reply) => {
    // Identity resolution happens before the Bridge's own try/catch (which
    // maps OAuthError → NormResponse), so a rejected identity would otherwise
    // surface as a 401 with Fastify's framework body, not §9.5. Route it
    // through the same path (§9.3).
    let subject: string;
    try {
      subject = await resolveSubject(identity, headerString(req.headers, identityHeader));
    } catch (error) {
      if (!(error instanceof OAuthError)) throw error; // real 500
      await send(reply, oauthErrorResponse(error));
      return;
    }
    await send(reply, await bridge.handleAuthorize(toNorm(req), subject));
  });
  app.post("/oauth/authorize/approve", async (req, reply) => send(reply, await bridge.handleApprove(toNorm(req))));
  app.post("/oauth/token", async (req, reply) => send(reply, await bridge.handleToken(toNorm(req))));
  app.post("/oauth/revoke", async (req, reply) => send(reply, await bridge.handleRevoke(toNorm(req))));
}
