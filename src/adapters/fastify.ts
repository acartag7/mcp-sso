// Fastify adapter (contracts §9.6). Thin wiring over the framework-free Bridge; all
// OAuth logic stays in the core. Maps NormResponse to Fastify (302 for redirects,
// status+body otherwise). The consumer supplies a Bridge + an IdentityPort; the
// adapter resolves the subject from `identityHeader` (default Cf-Access-Jwt-Assertion).

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { captureIdentityPort, type IdentityPort } from "../ports/identity.ts";
import { pathAfterOrigin } from "../config.ts";
import { classDataValue, ownBooleanTrue, ownDataValue } from "../own-property.ts";
import { asDirectOAuth, Bridge } from "./bridge.ts";
import {
  captureUpstreamRedirectFlow, type UpstreamRedirectFlow,
} from "./upstream-flow.ts";
import {
  headerString, oauthErrorResponse, parseUrlEncodedForm,
  type NormRequest, type NormResponse,
} from "./http.ts";

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

export async function registerOAuthRoutes(app: FastifyInstance, opts: FastifyAdapterOptions): Promise<void> {
  const bridge = ownDataValue(opts, "bridge") as Bridge;
  const identityInput = ownDataValue(opts, "identity");
  const identity = identityInput === undefined ? undefined : captureIdentityPort(identityInput);
  if (identityInput !== undefined && identity === null) {
    throw new TypeError("registerOAuthRoutes: identity is invalid");
  }
  const identityHeaderOption = ownDataValue(opts, "identityHeader");
  if (identityHeaderOption !== undefined
    && (typeof identityHeaderOption !== "string" || !identityHeaderOption)) {
    throw new TypeError("registerOAuthRoutes: identityHeader must be a non-empty string");
  }
  const identityHeader = identityHeaderOption as string | undefined ?? "cf-access-jwt-assertion";
  const upstreamInput = ownDataValue(opts, "upstream");
  const upstream = upstreamInput === undefined
    ? undefined : captureUpstreamRedirectFlow(upstreamInput);
  if (upstreamInput !== undefined && upstream === null) {
    throw new TypeError("registerOAuthRoutes: upstream is invalid");
  }
  const skipAuthorize = ownBooleanTrue(opts, "skipAuthorize");

  if (upstream && (identity || identityHeaderOption !== undefined || skipAuthorize)) {
    throw new Error("registerOAuthRoutes: 'upstream' is mutually exclusive with 'identity'/'identityHeader' and 'skipAuthorize' (exactly one authorize mode — §17.11)");
  }
  if (!upstream && !skipAuthorize && !identity) {
    throw new Error("registerOAuthRoutes: identity is required unless skipAuthorize or upstream is set");
  }
  const resource = classDataValue(classDataValue(bridge, "config"), "resource");
  if (typeof resource !== "string") throw new TypeError("registerOAuthRoutes: bridge is invalid");
  let resourcePath: string;
  try { resourcePath = pathAfterOrigin(resource); }
  catch { throw new TypeError("registerOAuthRoutes: bridge is invalid"); }

  const parseForm = (_req: FastifyRequest, body: string, done: (error: Error | null, value?: unknown) => void): void => {
    done(null, parseUrlEncodedForm(String(body)));
  };
  // skipAuthorize delegates /oauth/authorize to a caller-owned route (the
  // console-pairing composition). Preserve the adapter's historical parent
  // parser for that route when the application has not supplied one itself.
  if (skipAuthorize && app.hasContentTypeParser("application/x-www-form-urlencoded")) {
    throw new Error(
      "registerOAuthRoutes: skipAuthorize requires the built-in duplicate-preserving form parser",
    );
  }
  if (skipAuthorize) {
    app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, parseForm);
  }

  // Keep the OAuth parser inside an encapsulated plugin. If the parent already
  // installed @fastify/formbody/custom parsing, replace it only in this child
  // scope so repeated OAuth fields remain visible without mutating other routes.
  await app.register(async (routes) => {
    if (routes.hasContentTypeParser("application/x-www-form-urlencoded")) {
      routes.removeContentTypeParser("application/x-www-form-urlencoded");
    }
    routes.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, parseForm);

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

    routes.get("/.well-known/oauth-authorization-server", async (_req, reply) => send(reply, await bridge.handleAuthorizationServerMetadata()));
    routes.get("/.well-known/oauth-protected-resource", async (_req, reply) => send(reply, await bridge.handleProtectedResourceMetadata()));
    routes.get(`/.well-known/oauth-protected-resource${resourcePath}`, async (_req, reply) => send(reply, await bridge.handleProtectedResourceMetadata()));
    routes.get("/oauth/jwks", async (_req, reply) => send(reply, await bridge.handleJwks()));
    routes.post("/oauth/register", async (req, reply) => send(reply, await bridge.handleRegister(toNorm(req))));
    if (upstream) {
      const up = upstream;
      routes.get("/oauth/authorize", async (req, reply) => send(reply, await up.handleAuthorize(toNorm(req))));
      routes.get(up.callbackPath, async (req, reply) => send(reply, await up.handleCallback(toNorm(req))));
    } else if (!skipAuthorize) {
      const id = identity!;
      routes.get("/oauth/authorize", async (req, reply) => {
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
    routes.post("/oauth/authorize/approve", async (req, reply) => send(reply, await bridge.handleApprove(toNorm(req))));
    routes.post("/oauth/token", async (req, reply) => send(reply, await bridge.handleToken(toNorm(req))));
    routes.post("/oauth/revoke", async (req, reply) => send(reply, await bridge.handleRevoke(toNorm(req))));
  });
}
