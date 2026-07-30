#!/usr/bin/env node
// Two-resource live deployment using CONSOLE PAIRING as the identity leg
// (contracts §17.5) — no IdP account setup, so the gate can prove the part that
// actually needs a real client: whether it follows path-inserted PRM URLs, and
// whether resource A's token is refused at resource B.
//
//   OAUTH_ISSUER=https://<host> node scripts/live-multi-resource-pairing.mjs
//
// A one-time pairing code is printed to stderr; paste it at the authorize step.
// Reading this process's stderr IS the trust boundary (§17.5) — the deployment
// is single-operator by construction.

import Fastify from "fastify";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { generateKeyPairSync, randomBytes } from "node:crypto";

import { Bridge } from "../src/adapters/bridge.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { createBridgeConfig } from "../src/config.ts";
import { buildUnauthorizedChallenge } from "../src/challenge.ts";
import { OAuthError } from "../src/errors.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { openSqliteStore } from "../src/store/sqlite.ts";
import { createConsolePairingIdentity } from "../src/identity/console-pairing.ts";
import { handlePairingAuthorize } from "../src/adapters/pairing-flow.ts";
import { createCloudflareAccessIdentity } from "../src/identity/cloudflare-access.ts";

// Local normalizers — the framework-free pairing orchestrator speaks NormRequest
// / NormResponse; these mirror the shipped scaffold template (src/bin/templates.ts).
const toNorm = (req) => ({ query: req.query, body: req.body, headers: req.headers, ip: req.ip });
const sendNorm = async (reply, res) => {
  for (const [key, value] of Object.entries(res.headers)) reply.header(key, value);
  if (res.redirect) { await reply.redirect(res.redirect, res.status); return; }
  reply.code(res.status).send(res.body);
};

const issuer = process.env.OAUTH_ISSUER;
if (!issuer) {
  console.error("OAUTH_ISSUER is required, e.g. https://mcp-sso.example.com");
  process.exit(2);
}
const origin = new URL(issuer).origin;
const PATHS = (process.env.GATE_PATHS ?? "/grafana/mcp,/memory/mcp").split(",");
const ALL_SCOPES = {
  "/grafana/mcp": { catalog: ["mcp:read", "grafana:admin"], byDefault: ["mcp:read"] },
  "/memory/mcp": { catalog: ["mcp:read", "memory:curate"], byDefault: ["mcp:read"] },
  "/mcp": { catalog: ["mcp:read", "grafana:admin"], byDefault: ["mcp:read"] },
};
const SCOPES = Object.fromEntries(PATHS.map((p) => [p, ALL_SCOPES[p]]));

// A fresh key per run by default; OAUTH_SIGNING_PRIVATE_JWK pins one so the
// verification harness can mint a token against the same material.
let jwk;
if (process.env.OAUTH_SIGNING_PRIVATE_JWK) {
  jwk = JSON.parse(process.env.OAUTH_SIGNING_PRIVATE_JWK);
} else {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  jwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "live" };
}

const config = createBridgeConfig({
  issuer: origin,
  consentSigningSecret: randomBytes(32).toString("hex"),
  signingPrivateJwk: jwk,
  signingKeyId: "live",
  // Claude Code registers its loopback callback via DCR; the hosted clients need listing.
  redirectAllowlist: [
    "https://claude.ai/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
  ],
  allowedOrigins: [origin],
  dcr: { mode: "stateless" },
  // CIMD is opt-in (cimd?.enabled === true). GATE_CIMD=1 turns it on so the
  // client-metadata-document registration path is exercised live.
  ...(process.env.GATE_CIMD ? { cimd: { enabled: true } } : {}),
  accessTokenTtlSeconds: 600,
  refreshTokenTtlSeconds: 2_592_000,
  consentTokenTtlSeconds: 300,
  authorizationCodeTtlSeconds: 300,
  resources: PATHS.map((p) => ({
    resource: `${origin}${p}`,
    scopeCatalog: SCOPES[p].catalog,
    defaultScopes: SCOPES[p].byDefault,
  })),
});

const app = Fastify({ logger: false });
// Log every inbound request so a live client's exact probe sequence is visible.
app.addHook("onRequest", async (req) => {
  console.error(`[req] ${req.method} ${req.url} ua=${(req.headers["user-agent"] ?? "-").slice(0, 40)}`);
});
const clock = new SystemClock();
const store = openSqliteStore(process.env.SQLITE_FILE ?? ":memory:");
const bridge = new Bridge({ config, store, clock, audit: noopAudit });

// Identity leg: Cloudflare Access when configured (the proxy already gates
// /oauth/authorize*), otherwise console pairing.
if (process.env.CF_ACCESS_AUDIENCE) {
  const identity = createCloudflareAccessIdentity({
    audience: process.env.CF_ACCESS_AUDIENCE,
    issuer: process.env.CF_ACCESS_ISSUER,
    certsUrl: `${process.env.CF_ACCESS_ISSUER}/cdn-cgi/access/certs`,
  });
  await registerOAuthRoutes(app, { bridge, identity });
  console.error("[live gate] identity: Cloudflare Access");
} else {
  await registerOAuthRoutes(app, { bridge, skipAuthorize: true });
  const pairing = createConsolePairingIdentity({ subject: "live-gate-operator" });
  app.get("/oauth/authorize", async (req, reply) => {
    await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "GET", toNorm(req)));
  });
  app.post("/oauth/authorize", async (req, reply) => {
    await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "POST", toNorm(req)));
  });
  console.error("[live gate] identity: console pairing");
}

// GATE_NO_DCR=1: force clients onto the CIMD path by making DCR unavailable —
// 410 on /oauth/register and registration_endpoint stripped from AS metadata.
// The library always mounts both; this is a harness-level suppression to prove
// what a CIMD-only deployment would look like.
if (process.env.GATE_NO_DCR) {
  app.addHook("onRequest", async (req, reply) => {
    if (new URL(req.url, "http://x").pathname === "/oauth/register") {
      reply.code(410).send({ error: "invalid_request", error_description: "DCR disabled; use a client_id metadata document" });
    }
  });
  app.addHook("onSend", async (req, reply, payload) => {
    if (new URL(req.url, "http://x").pathname !== "/.well-known/oauth-authorization-server") return payload;
    try {
      const doc = JSON.parse(payload);
      delete doc.registration_endpoint;
      return JSON.stringify(doc);
    } catch { return payload; }
  });
}

// Origin gate keyed on the CONFIGURED resource paths — isMcpPath matches only
// the literal "/mcp" and would never fire here.
const resourcePaths = new Set(PATHS);
app.addHook("onRequest", async (request, reply) => {
  let pathname;
  try { pathname = new URL(request.url, "http://localhost").pathname; } catch { return; }
  if (!resourcePaths.has(pathname)) return;
  const header = request.headers.origin;
  if (Array.isArray(header)
    || (typeof header === "string" && !config.allowedOrigins.includes(header) && header !== origin)) {
    reply.code(403).send({ jsonrpc: "2.0", error: { code: -32001, message: "Origin not allowed" }, id: null });
  }
});

for (const path of PATHS) {
  const resource = `${origin}${path}`;
  const authorizer = new RequestAuthorizer({ config, clock, audit: noopAudit, resource });
  app.post(path, async (request, reply) => {
    let auth;
    try {
      auth = await authorizer.authorize({ authorization: request.headers.authorization });
    } catch (error) {
      const oe = error instanceof OAuthError ? error : new OAuthError("invalid_token", "Bearer token is invalid", 401);
      reply.header("www-authenticate", buildUnauthorizedChallenge(config, { resource, error: oe.code }));
      reply.code(oe.status).send({ jsonrpc: "2.0", error: { code: -32001, message: oe.code }, id: null });
      return;
    }
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    const mcp = new McpServer({ name: `mcp-sso${path}`, version: "0.4.0" });
    mcp.tool("whoami", "echo the caller and the resource this endpoint serves", async () => ({
      content: [{ type: "text", text: `${auth.subject} @ ${auth.resource}` }],
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

const port = Number(process.env.PORT ?? 8787);
await app.listen({ port, host: "127.0.0.1" });
console.error(`\n[live gate] two resources on ${origin}`);
for (const p of PATHS) console.error(`[live gate]   ${origin}${p}`);
console.error(`[live gate] listening on 127.0.0.1:${port}\n`);
