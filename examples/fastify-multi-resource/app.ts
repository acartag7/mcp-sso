// Two MCP resources behind ONE mcp-sso issuer.
//
// The deployment shape 0.4.0 exists for: a single issuer, signing key, client
// registry and consent screen protecting several independently addressable MCP
// resources. A client connects only to the endpoint whose tools it needs, and a
// token minted for /grafana/mcp is worthless at /memory/mcp.
//
// CONSUMER IMPORT MAP — this example imports mcp-sso's source directly
// (`../../src/...`) because it lives in-repo and tests the unbuilt source. A
// package consumer imports the SAME symbols from the published entry points:
//
//   root `mcp-sso`               Bridge, RequestAuthorizer, createBridgeConfig,
//                                buildUnauthorizedChallenge, OAuthError, SystemClock
//   `mcp-sso/fastify`            registerOAuthRoutes
//   `mcp-sso/store/sqlite`       SqliteStore
//   `mcp-sso/identity/cloudflare-access`  createCloudflareAccessIdentity
//
// Run it: see README.md in this directory.

import Fastify, { type FastifyInstance } from "fastify";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { Bridge } from "../../src/adapters/bridge.ts";
import { RequestAuthorizer } from "../../src/verifier.ts";
import { createBridgeConfig, type MultiResourceBridgeConfig } from "../../src/config.ts";
import { buildUnauthorizedChallenge } from "../../src/challenge.ts";
import { OAuthError } from "../../src/errors.ts";
import { SystemClock } from "../../src/ports/clock.ts";
import { registerOAuthRoutes } from "../../src/adapters/fastify.ts";
import { openSqliteStore } from "../../src/store/sqlite.ts";
import { createCloudflareAccessIdentity } from "../../src/identity/cloudflare-access.ts";
import type { IdentityPort } from "../../src/ports/identity.ts";
import { noopAudit, type AuditPort } from "../../src/ports/audit.ts";

/** The two resources this deployment serves. Both deliberately publish a shared
 *  `mcp:read` scope: isolation comes from the audience binding, never from scope
 *  names happening to differ. Each also has a scope the other does not offer. */
export const RESOURCE_PATHS = ["/grafana/mcp", "/memory/mcp"] as const;

const SCOPES: Record<string, { catalog: string[]; byDefault: string[] }> = {
  "/grafana/mcp": { catalog: ["mcp:read", "grafana:admin"], byDefault: ["mcp:read"] },
  "/memory/mcp": { catalog: ["mcp:read", "memory:curate"], byDefault: ["mcp:read"] },
};

/** Fail closed on config: an absent or blank env var is missing config, never a
 *  default. `??` would accept "" — that is the exact pattern that silently
 *  disables a gate, so every read goes through here. */
function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key];
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${key} is required (set it to a non-empty value)`);
  }
  return value;
}

export function buildConfig(env: NodeJS.ProcessEnv): MultiResourceBridgeConfig {
  const issuer = required(env, "OAUTH_ISSUER");
  const origin = new URL(issuer).origin;

  return createBridgeConfig({
    issuer,
    consentSigningSecret: required(env, "OAUTH_CONSENT_SIGNING_SECRET"),
    signingPrivateJwk: JSON.parse(required(env, "OAUTH_SIGNING_PRIVATE_JWK")),
    signingKeyId: required(env, "OAUTH_SIGNING_KEY_ID"),
    redirectAllowlist: required(env, "OAUTH_REDIRECT_ALLOWLIST").split(",").map((s) => s.trim()),
    allowedOrigins: [origin],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
    // The whole feature in one field: N resources, one issuer.
    resources: RESOURCE_PATHS.map((path) => ({
      resource: `${origin}${path}`,
      scopeCatalog: SCOPES[path]!.catalog,
      defaultScopes: SCOPES[path]!.byDefault,
    })),
  });
}

/** Mount one bridge (shared OAuth surface) and one protected endpoint per
 *  resource, each behind its OWN resource-pinned RequestAuthorizer. The pin is
 *  what makes A's token fail at B: the authorizer for /memory/mcp will only
 *  accept a token whose `aud` is exactly the /memory/mcp resource URL. */
export async function buildApp(opts: {
  config: MultiResourceBridgeConfig;
  identity: IdentityPort;
  sqliteFile?: string;
  audit?: AuditPort;
}): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  const clock = new SystemClock();
  const audit = opts.audit ?? noopAudit;
  const store = openSqliteStore(opts.sqliteFile ?? ":memory:");
  const bridge = new Bridge({ config: opts.config, store, clock, audit });

  // Registers /oauth/* plus a per-resource PRM document at
  // /.well-known/oauth-protected-resource<path> for each configured resource.
  await registerOAuthRoutes(app, { bridge, identity: opts.identity });

  const origin = new URL(opts.config.issuer).origin;

  // Origin gate — MCP Streamable HTTP DNS-rebinding protection. Scoped to the
  // resource paths and placed in an onRequest hook so it runs BEFORE body
  // parsing and for EVERY method, not just the POST handler below.
  //
  // NOTE: the single-resource examples use `isMcpPath`, which hard-codes the
  // pathname "/mcp" (src/adapters/http.ts:130) and therefore does NOT match
  // "/grafana/mcp". A multi-resource deployment must gate on its own configured
  // paths — reusing isMcpPath here would silently disable this protection.
  const resourcePaths = new Set<string>(RESOURCE_PATHS);
  app.addHook("onRequest", async (request, reply) => {
    let pathname: string;
    try {
      pathname = new URL(request.url, "http://localhost").pathname;
    } catch {
      return; // Not a resource path we gate; the route layer handles it.
    }
    if (!resourcePaths.has(pathname)) return; // OAuth routes manage their own Origin.
    const header = request.headers.origin;
    // An ambiguous (repeated) Origin is rejected rather than best-effort parsed.
    if (Array.isArray(header)) {
      reply.code(403).send({ jsonrpc: "2.0", error: { code: -32001, message: "Origin not allowed" }, id: null });
      return;
    }
    // An ABSENT Origin proceeds — MCP clients are not browsers. A PRESENT one
    // must be allowlisted.
    if (typeof header === "string" && !opts.config.allowedOrigins.includes(header) && header !== origin) {
      reply.code(403).send({ jsonrpc: "2.0", error: { code: -32001, message: "Origin not allowed" }, id: null });
      return;
    }
  });

  for (const path of RESOURCE_PATHS) {
    const resource = `${origin}${path}`;
    const authorizer = new RequestAuthorizer({ config: opts.config, clock, audit, resource });

    app.post(path, async (request, reply) => {
      let auth;
      try {
        auth = await authorizer.authorize({ authorization: request.headers.authorization });
      } catch (error) {
        const oe = error instanceof OAuthError
          ? error
          : new OAuthError("invalid_token", "Bearer token is invalid", 401);
        // The challenge names THIS endpoint's resource, so a client that
        // arrived with the wrong audience is told where to get the right one.
        reply.header("www-authenticate", buildUnauthorizedChallenge(opts.config, { resource, error: oe.code }));
        reply.code(oe.status).send({ jsonrpc: "2.0", error: { code: -32001, message: oe.code }, id: null });
        return;
      }

      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      const mcp = new McpServer({ name: `mcp-sso${path}`, version: "0.4.0" });
      mcp.tool("whoami", "echo the caller and the resource this endpoint serves", async () => ({
        content: [{ type: "text" as const, text: `${auth.subject} @ ${auth.resource}` }],
      }));
      await mcp.connect(transport);
      reply.hijack();
      try {
        await transport.handleRequest(request.raw, reply.raw, request.body);
      } finally {
        await mcp.close();
      }
    });
  }

  return app;
}

/** Cloudflare Access as the identity source for the browser authorize leg.
 *  Scope the Access application to /oauth/authorize* ONLY — see README. */
export function buildIdentity(env: NodeJS.ProcessEnv): IdentityPort {
  return createCloudflareAccessIdentity({
    audience: required(env, "CF_ACCESS_AUDIENCE"),
    certsUrl: required(env, "CF_ACCESS_CERTS_URL"),
    issuer: required(env, "CF_ACCESS_ISSUER"),
    emailAllowlist: required(env, "CF_ACCESS_EMAIL_ALLOWLIST").split(",").map((s) => s.trim()),
  });
}
