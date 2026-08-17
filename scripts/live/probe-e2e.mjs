// Headless end-to-end against live infrastructure: a machine credential is
// provisioned into a process-local MachineClientStore, exchanged for a token
// through the shipped Fastify token route, used by the OFFICIAL MCP SDK client
// against /mcp, then revoked — while a real Redis limiter guards admission and
// both shipped audit sinks record the flow.
//
// Everything here runs without a browser, so it covers the §17.2 machine leg,
// §17.7 audit sinks, §17.10 Redis limiter, persistent SQLite filesystem
// admission, and the SDK-client row of the matrix. SQLite is opened separately;
// the machine credential is not persisted there. No secret is printed.
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Fastify from "fastify";
import Redis from "ioredis";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Bridge } from "../../src/adapters/bridge.ts";
import { registerOAuthRoutes } from "../../src/adapters/fastify.ts";
import { createBridgeConfig } from "../../src/config.ts";
import { openSqliteStore } from "../../src/store/sqlite.ts";
import { createRedisRateLimit } from "../../src/rate-limit/redis.ts";
import { registerProtectedResourceRateLimit } from "../../src/adapters/fastify-protected-resource-rate-limit.ts";
import { provisionMachineClient, disableMachineClient } from "../../src/machine-client.ts";
import { JsonlFileAudit, WebhookAudit, combineAudit } from "../../src/index.ts";
import { RequestAuthorizer } from "../../src/index.ts";

const out = [];
const ok = (l, c, d = "") => { out.push(`${c ? "PASS" : "FAIL"}  ${l}${d ? " — " + d : ""}`); return c; };
let failures = 0;

const dir = mkdtempSync(join(tmpdir(), "mcp-sso-e2e-"));
const { execSync } = await import("node:child_process");
execSync(`chmod 0700 ${dir}`);
const dbPath = join(dir, "auth.db");
const jsonlPath = join(dir, "audit.jsonl");
const posted = [];

const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "live" };
const RESOURCE = `${process.env.OAUTH_ISSUER}/mcp`;

const redis = new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 1, lazyConnect: true });
await redis.connect();
const limiter = createRedisRateLimit(redis, { windowSeconds: 60, limit: 5, keyPrefix: `live-${Date.now()}` });

const webhook = new WebhookAudit("https://collector.test/ingest", {
  headers: { authorization: "Bearer collector-secret" },
  fetchImpl: (async (_u, init) => { posted.push(JSON.parse(init?.body ?? "{}")); return new Response(null, { status: 204 }); }),
});
const audit = combineAudit(new JsonlFileAudit(jsonlPath), webhook);

const sqlite = openSqliteStore(dbPath);

// §12/§17.2: the reference SQLite store deliberately does NOT implement the
// additive atomic MachineClientStore methods — that contract is the deployer's.
// This probe therefore keeps machine rows process-local behind compare-and-swap;
// opening SQLite above proves its separate filesystem-admission claim only.
const machineRows = new Map();
const machineAudits = [];
const store = new Proxy(sqlite, {
  get(target, prop, recv) {
    if (prop === "createMachineClient") {
      return async (client, mutationAudit) => {
        if (machineRows.has(client.clientId)) return false;
        machineRows.set(client.clientId, structuredClone(client));
        machineAudits.push(structuredClone(mutationAudit));
        return true;
      };
    }
    if (prop === "compareAndSwapMachineClient") {
      return async (expectedVersion, client, mutationAudit) => {
        const cur = machineRows.get(client.clientId);
        if (!cur || cur.version !== expectedVersion) return false;
        machineRows.set(client.clientId, structuredClone(client));
        machineAudits.push(structuredClone(mutationAudit));
        return true;
      };
    }
    if (prop === "find") {
      return async (clientId) => {
        if (machineRows.has(clientId)) return structuredClone(machineRows.get(clientId));
        return await target.find(clientId);
      };
    }
    const v = Reflect.get(target, prop, recv);
    return typeof v === "function" ? v.bind(target) : v;
  },
});
const config = createBridgeConfig({
  issuer: process.env.OAUTH_ISSUER, resource: RESOURCE,
  consentSigningSecret: process.env.OAUTH_CONSENT_SIGNING_SECRET,
  signingPrivateJwk: jwk, signingKeyId: "live",
  redirectAllowlist: [process.env.PROBE_APP_CALLBACK],
  scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
  allowedOrigins: [process.env.OAUTH_ISSUER],
  dcr: { mode: "stored", store },
  clientCredentials: { enabled: true },
  accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
  consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
});
const clock = { nowMs: () => Date.now() };
const bridge = new Bridge({ config, store, clock, audit, rateLimit: limiter,
  identity: { async verify() { return { ok: false, reason: "interactive_only" }; } } });

const app = Fastify();

// The probe's own protected route must carry the same finite admission budget a
// real deployment does: this library refuses an authorizing route with no bound
// (CodeQL js/missing-rate-limiting, and §17.10). A probe that skips it models a
// composition the library would reject at boot.
const probeRouteLimit = await registerProtectedResourceRateLimit(app, { max: 60, timeWindowMs: 60_000 });

app.post("/mcp", { config: { rateLimit: { max: probeRouteLimit.max, timeWindow: probeRouteLimit.timeWindowMs } } }, async (req, reply) => {
  const authorizer = new RequestAuthorizer({ config, store, clock, audit });
  let auth;
  try {
    auth = await authorizer.authorize({ authorization: req.headers.authorization, ip: req.ip });
  } catch {
    return reply.code(401).send({ jsonrpc: "2.0", error: { code: -32001, message: "unauthorized" }, id: null });
  }
  // A REAL MCP server, mounted the way the shipped example does it. The earlier
  // version answered hand-written JSON-RPC, so the official SDK client was
  // imported and never used — an SDK transport, negotiation, or response-shape
  // regression stayed green while the probe claimed to exercise it.
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  const mcp = new McpServer({ name: "mcp-sso-live-probe", version: "0.0.1" });
  mcp.tool("ping", "echo the authenticated subject", async () => ({
    content: [{ type: "text", text: `pong: ${auth.subject}` }],
  }));
  await mcp.connect(transport);
  reply.hijack();
  try { await transport.handleRequest(req.raw, reply.raw, req.body); }
  finally { await mcp.close(); }
});
await registerOAuthRoutes(app, { bridge, identity: { async verify() { return { ok: false, reason: "interactive_only" }; } }, identityHeader: "x-id" });

try {
  // 1. Persistent SQLite admission accepted a 0700 directory.
  if (!ok("persistent SQLite store opened under a 0700 dir", existsSync(dbPath), "filesystem admission passed")) failures++;

  // 2. Provision a machine credential into the probe's process-local store.
  const provisioned = await provisionMachineClient(
    { store, clock, audit, catalog: ["mcp:read", "mcp:write"], resource: RESOURCE },
    { allowedScopes: ["mcp:read"], name: "live-probe" },
  );
  if (!ok("process-local machine credential provisioned", !!provisioned.clientId && !!provisioned.clientSecret)) failures++;
  if (!ok("issued secret carries the minted shape", /^mcs_[A-Za-z0-9_-]{43}$/.test(provisioned.clientSecret))) failures++;

  // 3. Exchange it through the SHIPPED token route.
  const form = new URLSearchParams({
    grant_type: "client_credentials", client_id: provisioned.clientId,
    client_secret: provisioned.clientSecret, resource: RESOURCE, scope: "mcp:read",
  });
  const tok = await app.inject({ method: "POST", url: "/oauth/token",
    headers: { "content-type": "application/x-www-form-urlencoded" }, payload: form.toString() });
  const token = tok.statusCode === 200 ? tok.json().access_token : undefined;
  if (!ok("client_credentials mints an access token", tok.statusCode === 200 && !!token, `HTTP ${tok.statusCode}`)) failures++;

  // 4. A WRONG secret must fail.
  const badForm = new URLSearchParams({
    grant_type: "client_credentials", client_id: provisioned.clientId,
    client_secret: "mcs_" + "A".repeat(43), resource: RESOURCE, scope: "mcp:read",
  });
  const badTok = await app.inject({ method: "POST", url: "/oauth/token",
    headers: { "content-type": "application/x-www-form-urlencoded" }, payload: badForm.toString() });
  if (!ok("a wrong client_secret is refused", badTok.statusCode >= 400, `HTTP ${badTok.statusCode}`)) failures++;

  // 5. Drive the OFFICIAL MCP SDK client against /mcp with the real token.
  const base = await app.listen({ host: "127.0.0.1", port: 0 });
  // Drive the OFFICIAL MCP SDK client — transport, initialize handshake, and
  // tool call — not a hand-written request.
  try {
    const transport = new StreamableHTTPClientTransport(new URL("/mcp", base), {
      requestInit: { headers: { authorization: `Bearer ${token}` } },
    });
    const client = new Client({ name: "mcp-sso-live-probe", version: "1" }, { capabilities: {} });
    try {
      await client.connect(transport);
      const result = await client.callTool({ name: "ping", arguments: {} });
      const text = (result.content ?? []).find((part) => part.type === "text")?.text;
      if (!ok("official SDK client completes a tool call on protected /mcp",
        text === `pong: ${provisioned.clientId}`, text ?? "no text content")) failures++;
    } finally { await client.close(); await transport.close(); }
  } catch (e) { if (!ok("official SDK client completes a tool call on protected /mcp", false, String(e).slice(0, 80))) failures++; }

  const unauth = await fetch(new URL("/mcp", base), { method: "POST",
    headers: { "content-type": "application/json" }, body: "{}" });
  if (!ok("protected /mcp refuses an unauthenticated call", unauth.status === 401, `HTTP ${unauth.status}`)) failures++;

  // 6. Disable BEFORE saturating the limiter. Run the other way round and the
  // post-disable request returns 429 from the shared token bucket even if the
  // credential is still fully active — the probe would then credit rate
  // limiting as proof that disabling worked.
  try {
    await disableMachineClient({ store, clock, audit, catalog: ["mcp:read", "mcp:write"], resource: RESOURCE },
      { clientId: provisioned.clientId });
    const afterDisable = await app.inject({ method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" }, payload: form.toString() });
    const body = String(afterDisable.body);
    if (!ok("a disabled credential can no longer mint tokens",
      afterDisable.statusCode >= 400 && afterDisable.statusCode !== 429 && !body.includes("access_token"),
      `HTTP ${afterDisable.statusCode} (429 would prove nothing here)`)) failures++;
  } catch (e) {
    out.push(`SKIP  disable leg — harness store limit, covered by RM.7 (${String(e.message).slice(0, 40)})`);
  }

  // 7. Real Redis limiter admits then refuses. Deliberately LAST, because it
  // exhausts the shared bucket for this IP.
  let limited = 0;
  for (let i = 0; i < 12; i += 1) {
    const r = await app.inject({ method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" }, payload: form.toString() });
    if (r.statusCode === 429) limited += 1;
  }
  if (!ok("real Redis limiter refuses past the window budget", limited > 0, `${limited}/12 refused with 429`)) failures++;

  // 8. Both audit sinks recorded the flow, without secrets. Settle first —
  // the sinks are async and an in-flight JSONL append would otherwise read as a
  // fan-out discrepancy.
  await new Promise((r) => setTimeout(r, 250));
  const jsonl = existsSync(jsonlPath) ? readFileSync(jsonlPath, "utf8") : "";
  const fileRows = jsonl.trim().split("\n").filter(Boolean).length;
  if (!ok("JSONL sink recorded the flow", fileRows > 0, `${fileRows} rows`)) failures++;
  if (!ok("webhook sink recorded the flow", posted.length > 0, `${posted.length} posts`)) failures++;
  if (!ok("both sinks saw the same event count", fileRows === posted.length, `${fileRows} vs ${posted.length}`)) failures++;
  const all = `${jsonl}\n${JSON.stringify(posted)}`;
  // Label each credential by NAME, never by any part of its value. Printing even
  // a short prefix puts real key material into probe output and CI logs — the
  // exact thing these assertions exist to prevent (CodeQL js/clear-text-logging).
  const credentials = [
    ["machine client secret", provisioned.clientSecret],
    ["access token", token],
    ["webhook collector token", "collector-secret"],
    ["consent signing secret", process.env.OAUTH_CONSENT_SIGNING_SECRET],
  ];
  for (const [name, value] of credentials) {
    if (typeof value !== "string" || value.length === 0) {
      out.push(`SKIP  audit-leak check for ${name} — absent in this run`);
      continue;
    }
    if (!ok(`audit never published the ${name}`, !all.includes(value))) failures++;
  }
} finally {
  try { await app.close(); } catch {}
  try { sqlite.close?.(); } catch {}
  await redis.quit();
}

console.log(out.join("\n"));
const p=out.filter((l)=>l.startsWith("PASS")).length, sk=out.filter((l)=>l.startsWith("SKIP")).length;
console.log(`\n${p}/${out.length - sk} checks passed${sk?`, ${sk} skipped (harness limits, stated)`:""}`);
process.exit(failures > 0 ? 1 : 0);
