// Fastify adapter (contracts §9.6). Thin wiring over the framework-free Bridge; all
// OAuth logic stays in the core. Maps NormResponse to Fastify (302 for redirects,
// status+body otherwise). The consumer supplies a Bridge + an IdentityPort; the
// adapter resolves the subject from `identityHeader` (default Cf-Access-Jwt-Assertion).

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { IdentityPort } from "../ports/identity.ts";
import { pathAfterOrigin } from "../config.ts";
import { OAuthError } from "../errors.ts";
import { asDirectOAuth, Bridge } from "./bridge.ts";
import type { UpstreamRedirectFlow } from "./upstream-flow.ts";
import {
  formBodySnapshot, headerString, headersFromDistinct, oauthErrorResponse, OAUTH_POST_BODY_MAX_BYTES,
  type NormRequest, type NormResponse,
} from "./http.ts";
import { formOccurrencesFromUrlEncoded, hasDuplicatedAuthorizeParams, queryOccurrencesFromUrl } from "./authorize-params.ts";
import {
  PAIRING_AUTHORIZE_MAX_REQUESTS, PAIRING_AUTHORIZE_WINDOW_MS,
} from "./pairing-flow.ts";

export { OAUTH_POST_BODY_MAX_BYTES };

/** Route metadata matching handlePairingAuthorize's mandatory hard gate. */
export const FASTIFY_PAIRING_AUTHORIZE_RATE_LIMIT = Object.freeze({
  max: PAIRING_AUTHORIZE_MAX_REQUESTS,
  timeWindow: PAIRING_AUTHORIZE_WINDOW_MS,
});

const OAUTH_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";

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
  /** §17.11 upstream redirect-flow orchestrator. When set, GET /oauth/authorize
   *  → upstream.handleAuthorize and GET upstream.callbackPath → upstream.handleCallback.
   *  Mutually exclusive with `identity`/`identityHeader` and `skipAuthorize`. */
  upstream?: UpstreamRedirectFlow;
}

export function addOAuthFormContentTypeParser(app: FastifyInstance): void {
  // Only an exact form parser is guarded: hasContentTypeParser("*") is dead on
  // every Fastify 5.x (wildcards are stored under a key the lookup never
  // produces), so a caller-owned wildcard is deliberately NOT detected — the
  // exact parser is installed and, by exact-match precedence, takes urlencoded
  // bodies in this scope away from that wildcard. Never add a wildcard check
  // back: if it ever worked, the parser would be skipped and the OAuth routes
  // would fall to the child-scope Buffer catch-all, 400ing every form client.
  if (app.hasContentTypeParser(OAUTH_FORM_CONTENT_TYPE)) return;
  app.addContentTypeParser(OAUTH_FORM_CONTENT_TYPE, { parseAs: "string" }, (_req, body, done) => {
    done(null, formOccurrencesFromUrlEncoded(String(body)));
  });
}

export async function registerOAuthRoutes(app: FastifyInstance, opts: FastifyAdapterOptions): Promise<void> {
  if (opts.skipAuthorize && !opts.upstream) {
    // Pre-A1 compatibility: caller-owned pairing routes registered after this
    // function inherit automatic form parsing. Keep only the catch-all parser in
    // the child scope so unrelated unknown media retain caller semantics.
    addOAuthFormContentTypeParser(app);
    app.addHook("onRoute", (routeOptions) => {
      const methods = Array.isArray(routeOptions.method) ? routeOptions.method : [routeOptions.method];
      if (routeOptions.url !== "/oauth/authorize"
        || !methods.some((method) => method.toUpperCase() === "POST")) return;
      routeOptions.bodyLimit = Math.min(
        routeOptions.bodyLimit ?? OAUTH_POST_BODY_MAX_BYTES,
        OAUTH_POST_BODY_MAX_BYTES,
      );
    });
  }
  await app.register(async (scope) => registerScopedOAuthRoutes(scope, opts));
}

async function registerScopedOAuthRoutes(app: FastifyInstance, opts: FastifyAdapterOptions): Promise<void> {
  const { bridge, identity, identityHeader = "cf-access-jwt-assertion", skipAuthorize = false, upstream } = opts;

  // This encapsulated scope owns duplicate-preserving semantics for the four
  // built-in POST routes. Removing an inherited exact parser here does not
  // change the parent's unrelated routes (§9.6).
  if (app.hasContentTypeParser(OAUTH_FORM_CONTENT_TYPE)) {
    app.removeContentTypeParser(OAUTH_FORM_CONTENT_TYPE);
  }
  addOAuthFormContentTypeParser(app);
  app.addContentTypeParser("*", { parseAs: "buffer" }, (_req, body, done) => {
    done(null, body);
  });

  const toNorm = (req: FastifyRequest): NormRequest => {
    const headers = headersFromDistinct(req.raw.headersDistinct, req.headers as NormRequest["headers"]);
    const body = req.body;
    return {
      query: queryOccurrencesFromUrl(req.raw.url ?? ""), body,
      formBody: formBodySnapshot(body, headers), headers, ip: req.ip,
    };
  };
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
  app.post("/oauth/register", { bodyLimit: OAUTH_POST_BODY_MAX_BYTES }, async (req, reply) => send(reply, await bridge.handleRegister(toNorm(req))));
  if (upstream && (identity || skipAuthorize)) {
    throw new Error("registerOAuthRoutes: 'upstream' is mutually exclusive with 'identity'/'identityHeader' and 'skipAuthorize' (exactly one authorize mode — §17.11)");
  }
  if (upstream) {
    const up = upstream;
    app.get("/oauth/authorize", async (req, reply) => send(reply, await up.handleAuthorize(toNorm(req))));
    app.get(up.callbackPath, async (req, reply) => send(reply, await up.handleCallback(toNorm(req))));
  } else if (!skipAuthorize) {
    if (!identity) throw new Error("registerOAuthRoutes: identity is required unless skipAuthorize or upstream is set");
    const id = identity;
    app.get("/oauth/authorize", async (req, reply) => {
      // Identity resolution is pre-validation. Route throws through the direct
      // §9.5 path, stripping any redirect target a user-supplied IdentityPort put
      // on an OAuthError and hiding non-OAuth details (verification.md HF.3).
      // bridge.resolveIdentity also emits the identity.verify audit event.
      let identityResolved: { subject: string; allowedScopes?: string[] };
      const request = toNorm(req);
      if (hasDuplicatedAuthorizeParams(request.query)) {
        await send(reply, oauthErrorResponse(bridge.config, new OAuthError("invalid_request", "duplicate request parameters")));
        return;
      }
      try {
        identityResolved = await bridge.resolveIdentity(id, headerString(request.headers, identityHeader), request.ip);
      } catch (error) {
        await send(reply, oauthErrorResponse(bridge.config, asDirectOAuth(error)));
        return;
      }
      await send(reply, await bridge.handleAuthorize(request, identityResolved));
    });
  }
  app.post("/oauth/authorize/approve", { bodyLimit: OAUTH_POST_BODY_MAX_BYTES }, async (req, reply) => send(reply, await bridge.handleApprove(toNorm(req))));
  app.post("/oauth/token", { bodyLimit: OAUTH_POST_BODY_MAX_BYTES }, async (req, reply) => send(reply, await bridge.handleToken(toNorm(req))));
  app.post("/oauth/revoke", { bodyLimit: OAUTH_POST_BODY_MAX_BYTES }, async (req, reply) => send(reply, await bridge.handleRevoke(toNorm(req))));
}
