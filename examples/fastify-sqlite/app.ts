// Runnable example: Fastify + sqlite. The standalone entry (index.ts) wires the
// zero-setup path — quickstart secrets (§17.8) + console pairing (§17.5) + a JSONL
// audit sink — so the server boots with NO signing/consent env config and an
// operator pastes a one-time code from the console. buildApp() also still supports
// a header-based IdentityPort (used by the e2e test). The verify gate
// (test/e2e-mcp-sdk.test.ts + test/e2e-pairing.test.ts) imports buildApp().

import Fastify, { type FastifyReply } from "fastify";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Bridge } from "../../src/adapters/bridge.ts";
import { createBridgeConfig, type BridgeConfig } from "../../src/config.ts";
import { OAuthError, oauthErrorBody } from "../../src/errors.ts";
import { buildUnauthorizedChallenge } from "../../src/challenge.ts";
import { RequestAuthorizer } from "../../src/verifier.ts";
import { SystemClock } from "../../src/ports/clock.ts";
import { noopAudit, type AuditPort } from "../../src/ports/audit.ts";
import { openSqliteStore } from "../../src/store/sqlite.ts";
import type { IdentityPort } from "../../src/ports/identity.ts";
import type { ConsolePairingIdentity } from "../../src/identity/console-pairing.ts";
import { handlePairingAuthorize } from "../../src/adapters/pairing-flow.ts";
import type { NormRequest, NormResponse } from "../../src/adapters/http.ts";
import { registerOAuthRoutes } from "../../src/adapters/fastify.ts";

export interface ExampleOptions {
  config: BridgeConfig;
  /** Header-based IdentityPort for the default authorize path (e2e-test mode). */
  identity?: IdentityPort;
  /** Console-pairing identity — when set, buildApp mounts the pairing authorize
   *  surface instead of the header-based one. */
  pairing?: ConsolePairingIdentity;
  sqliteFile?: string; // defaults to :memory:
  identityHeader?: string;
  /** Audit sink for the Bridge + RequestAuthorizer + pairing. Default noopAudit. */
  audit?: AuditPort;
}

/** Build the example Fastify app: OAuth routes + a protected /mcp (MCP server). */
export async function buildApp(opts: ExampleOptions) {
  const app = Fastify();
  const clock = new SystemClock();
  const store = openSqliteStore(opts.sqliteFile ?? ":memory:");
  const audit: AuditPort = opts.audit ?? noopAudit;
  const bridge = new Bridge({ config: opts.config, store, clock, audit });
  const authorizer = new RequestAuthorizer({ config: opts.config, clock, audit });

  const toNorm = (req: { query: unknown; body: unknown; headers: unknown; ip?: string }): NormRequest => ({
    query: req.query as NormRequest["query"],
    body: req.body,
    headers: req.headers as NormRequest["headers"],
    ip: req.ip,
  });
  const sendNorm = async (reply: FastifyReply, res: NormResponse): Promise<void> => {
    for (const [key, value] of Object.entries(res.headers)) reply.header(key, value);
    if (res.redirect) { await reply.redirect(res.redirect, res.status); return; }
    reply.code(res.status).send(res.body);
  };

  if (opts.pairing) {
    // Zero-setup mode: registerOAuthRoutes skips /oauth/authorize; we mount a
    // GET (render pairing page) + POST (verify code → consent page) via the
    // framework-free handlePairingAuthorize orchestrator.
    registerOAuthRoutes(app, { bridge, skipAuthorize: true });
    const pairing = opts.pairing;
    app.get("/oauth/authorize", async (req, reply) => {
      await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "GET", toNorm(req as never)));
    });
    app.post("/oauth/authorize", async (req, reply) => {
      await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "POST", toNorm(req as never)));
    });
  } else {
    registerOAuthRoutes(app, { bridge, identity: opts.identity, identityHeader: opts.identityHeader });
  }

  // Protected /mcp: verify the bridge-issued access token, then delegate to an MCP server.
  app.post("/mcp", async (request, reply) => {
    let auth;
    try {
      auth = await authorizer.authorize({ authorization: request.headers.authorization });
    } catch (error) {
      const oe = error instanceof OAuthError ? error : new OAuthError("invalid_token", "Bearer token is invalid", 401);
      reply.header("www-authenticate", buildUnauthorizedChallenge(opts.config, { scope: opts.config.scopeCatalog, error: oe.code, errorDescription: oe.message }));
      reply.code(oe.status).send({ jsonrpc: "2.0", error: { code: -32001, message: `${oe.code}: ${oe.message}` }, id: null });
      return;
    }
    void oauthErrorBody;
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    const mcp = new McpServer({ name: "mcp-sso-example", version: "0.0.1" });
    mcp.tool("ping", "echo the authenticated subject", async () => ({
      content: [{ type: "text" as const, text: `pong: ${auth.subject}` }],
    }));
    await mcp.connect(transport);
    reply.hijack();
    try {
      await transport.handleRequest(request.raw, reply.raw, request.body);
    } finally {
      await mcp.close();
    }
  });

  return { app, store, bridge, close: async () => { await store.close(); } };
}

/** Read config from env (the production path; standalone index.ts uses quickstart
 *  secrets instead). Kept for deployers who mount signing material via env. */
export function configFromEnv(): BridgeConfig {
  const required = ["OAUTH_ISSUER", "OAUTH_RESOURCE", "OAUTH_CONSENT_SIGNING_SECRET", "OAUTH_SIGNING_PRIVATE_JWK"];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length) throw new Error(`Missing env: ${missing.join(", ")}`);
  return createBridgeConfig({
    issuer: process.env.OAUTH_ISSUER!,
    resource: process.env.OAUTH_RESOURCE!,
    consentSigningSecret: process.env.OAUTH_CONSENT_SIGNING_SECRET!,
    signingPrivateJwk: JSON.parse(process.env.OAUTH_SIGNING_PRIVATE_JWK!) as never,
    signingKeyId: process.env.OAUTH_SIGNING_KEY_ID || undefined,
    redirectAllowlist: (process.env.OAUTH_REDIRECT_ALLOWLIST ?? "").split(",").map((s) => s.trim()).filter(Boolean),
    scopeCatalog: (process.env.OAUTH_SCOPE_CATALOG ?? "mcp:read,mcp:write").split(",").map((s) => s.trim()).filter(Boolean),
    defaultScopes: (process.env.OAUTH_DEFAULT_SCOPES ?? "mcp:read").split(",").map((s) => s.trim()).filter(Boolean),
    allowedOrigins: (process.env.OAUTH_ALLOWED_ORIGINS ?? process.env.OAUTH_ISSUER!).split(",").map((s) => s.trim()).filter(Boolean),
    dcr: { mode: "stateless" },
    dev: process.env.OAUTH_ALLOW_INSECURE_LOCALHOST === "true" ? { allowInsecureLocalhost: true } : undefined,
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}
