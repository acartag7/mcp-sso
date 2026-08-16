// File templates for `mcp-sso init` (contracts §15 "Init CLI"). Dep-free (node builtins); ships in dist/bin.
import { generatedReadme } from "./template-readme.ts";
/** Fastify, its limiter, and the MCP SDK use the exact tested devDependency pins.
 *  Keep these ledger-recorded constants in sync when the repo pins move. */
const FASTIFY_VERSION = "5.8.5"; const FASTIFY_RATE_LIMIT_VERSION = "11.2.0";
const MCP_SDK_VERSION = "1.29.0";

export interface TemplateVars {
  /** The mcp-sso version the init binary is running as (read from its own package.json). */
  mcpSsoVersion: string;
  /** The generated project's name (the target directory's basename). */
  name: string;
}

export interface TemplateFile {
  path: string;
  content: string;
}
/** The generated server — the zero-setup console-pairing composition root, built from
 *  package exports (root + the ./fastify, ./store/sqlite, ./identity/console-pairing
 *  subpaths). Mirrors examples/fastify-sqlite's buildApp + index.ts, minus the env-
 *  driven IdP branches (a documented graduation, not a scaffolded default). */
const SERVER_TS = `// mcp-sso server — zero-setup console pairing (the fastest start: no IdP, no keys).
// Run it, paste the one-time code printed to the console, then point an MCP client at
// the resource URL. For a real identity provider (Cloudflare Access / Entra / Google /
// generic OIDC), graduate to the env-driven composition root in:
//   https://github.com/acartag7/mcp-sso/tree/main/examples/fastify-sqlite
// and docs/gateway-deployment.md + docs/live-verification.md.
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  Bridge, RequestAuthorizer, createBridgeConfig, originOf, isMcpPath, validateAllowedOrigins,
  loadOrCreateQuickstartSecrets, handlePairingAuthorize,
  SystemClock, JsonlFileAudit, buildUnauthorizedChallenge, OAuthError,
  type ClientRegistration, type ClientStore,
} from "mcp-sso";
import { addOAuthFormContentTypeParser, FASTIFY_PAIRING_AUTHORIZE_RATE_LIMIT, OAUTH_POST_BODY_MAX_BYTES, registerOAuthRoutes, semanticOAuthBody } from "mcp-sso/fastify";
import { registerProtectedResourceRateLimit } from "mcp-sso/fastify/protected-resource-rate-limit";
import { openSqliteStore } from "mcp-sso/store/sqlite";
import { createConsolePairingIdentity } from "mcp-sso/identity/console-pairing";
// The normalized request/response shapes the framework-free surface speaks. Inlined
// here so this starter compiles standalone; they are also exported from "mcp-sso"
// (NormRequest / NormResponse) — swap to those imports if you prefer.
type NormRequest = { query: Record<string, string | string[] | undefined>; body: unknown; headers: Record<string, string | string[] | undefined>; ip?: string };
type NormResponse = { status: number; headers: Record<string, string>; body?: unknown; redirect?: string };

// Treat a blank (whitespace-only) env value as MISSING — fail-closed on untrusted input
// (the house rule): e.g. HOST="" must NOT reach Node as "bind all interfaces" (0.0.0.0),
// which would expose the one-time pairing code to the network. Same for PORT (Number("")
// is 0 → an ephemeral, undiscoverable port).
const env = (key: string, def: string): string => {
  const v = process.env[key];
  return v && v.trim() ? v : def;
};
const PORT = Number(env("PORT", "3000"));
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error(\`mcp-sso: PORT must be an integer in 1–65535 (got '\${env("PORT", "3000")}')\`);
}
const HOST = env("HOST", "127.0.0.1"); // loopback default — the pairing code is the identity gate
const DIR = env("MCP_SSO_DIR", "./.mcp-sso");
// The advertised default uses the selected loopback bind, including IPv6 brackets, so
// discovery never points at a different address family from the listening socket.
const DEFAULT_LOOPBACK_HOST = HOST === "::1" ? "[::1]" : HOST;
let ISSUER = env("OAUTH_ISSUER", \`http://\${DEFAULT_LOOPBACK_HOST}:\${PORT}\`);
while (ISSUER.endsWith("/")) ISSUER = ISSUER.slice(0, -1); // trim a trailing / so the derived resource is /mcp, not //mcp
const RESOURCE = env("OAUTH_RESOURCE", \`\${ISSUER}/mcp\`);
const list = (v: string | undefined, def: string): string[] => (v ?? def).split(",").map((s) => s.trim()).filter(Boolean);
const originList = (v: string | undefined, def: string): string[] => v === "" ? [] : (v ?? def).split(",");
const redirectAllowlistModeFromEnv = (
  raw: string | undefined, redirectAllowlist: readonly string[],
): "extend" | "replace" | undefined => {
  if (raw === undefined) return undefined;
  if (raw !== "extend" && raw !== "replace") {
    throw new Error('redirectAllowlistMode must be "extend" or "replace"');
  }
  if (raw === "replace" && redirectAllowlist.length === 0) {
    throw new Error('redirectAllowlistMode "replace" requires at least one redirectAllowlist entry');
  }
  return raw;
};
// Strip control chars before logging an env-derived value (no log-line injection on the operator's console; a char class is linear → no ReDoS).
const oneLine = (s: unknown): string => String(s).replace(/[\\x00-\\x1f\\x7f]/g, "");
// allowInsecureLocalhost lets an http:// loopback issuer boot for local dev (the
// bridge mints real tokens; never set this for a non-loopback / production issuer).
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]); const isLoopback = (url: string): boolean => { try { const u = new URL(url); return (u.protocol === "http:" || u.protocol === "https:") && LOOPBACK.has(u.hostname); } catch { return false; } };
const isHttpLoopback = (url: string): boolean => { try { const u = new URL(url); return u.protocol === "http:" && LOOPBACK.has(u.hostname); } catch { return false; } };

async function main(): Promise<void> {
  // Validate URLs before state creation; errors never echo credential-bearing input.
  const requireUrl = (label: string, v: string): void => {
    let u: URL; try { u = new URL(v); } catch { throw new Error(\`\${label} is not a valid URL\`); }
    if (u.username || u.password) throw new Error(\`\${label} must not contain userinfo (user:password@) — use a plain URL\`);
  };
  requireUrl("OAUTH_ISSUER", ISSUER);
  requireUrl("OAUTH_RESOURCE", RESOURCE);
  if (HOST !== "127.0.0.1" && HOST !== "localhost" && HOST !== "::1") throw new Error("The generated starter is localhost-only: HOST must be a loopback address. Use the production example with a real identity provider and rate limiter for an internet-facing deployment.");
  if (new URL(RESOURCE).pathname !== "/mcp") throw new Error("OAUTH_RESOURCE pathname must be /mcp (the server mounts /mcp); set OAUTH_RESOURCE to <issuer>/mcp or edit server.ts for a custom path."); if (!isLoopback(ISSUER) || !isLoopback(RESOURCE)) throw new Error("The generated starter is localhost-only: OAUTH_ISSUER and OAUTH_RESOURCE must use loopback hosts. Use the production example for an internet-facing deployment.");
  const allowedOrigins = validateAllowedOrigins(originList(process.env.OAUTH_ALLOWED_ORIGINS, new URL(ISSUER).origin));
  const redirectAllowlist = list(process.env.OAUTH_REDIRECT_ALLOWLIST, "http://localhost,http://127.0.0.1");
  const redirectAllowlistMode = redirectAllowlistModeFromEnv(process.env.OAUTH_REDIRECT_ALLOWLIST_MODE, redirectAllowlist);
  const secrets = await loadOrCreateQuickstartSecrets({ dir: DIR });
  let store: ReturnType<typeof openSqliteStore> | undefined;
  const clientStore: ClientStore = {
    async save(client: ClientRegistration): Promise<void> { if (!store) throw new Error("mcp-sso: client store is not ready"); await store.save(client); },
    async find(clientId: string): Promise<ClientRegistration | null> { if (!store) throw new Error("mcp-sso: client store is not ready"); return store.find(clientId); },
  };
  const config = createBridgeConfig({
      issuer: ISSUER, resource: RESOURCE, consentSigningSecret: secrets.consentSigningSecret,
      signingPrivateJwk: secrets.signingPrivateJwk,
      redirectAllowlist,
      redirectAllowlistMode,
      scopeCatalog: list(process.env.OAUTH_SCOPE_CATALOG, "mcp:read,mcp:write"),
      defaultScopes: list(process.env.OAUTH_DEFAULT_SCOPES, "mcp:read"),
      allowedOrigins,
      dev: isHttpLoopback(ISSUER) ? { allowInsecureLocalhost: true } : undefined,
      cimd: { enabled: true },
      dcr: { mode: "stored", store: clientStore },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
      consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
  store = openSqliteStore(\`\${DIR}/auth.db\`);
  const audit = new JsonlFileAudit(\`\${DIR}/audit.jsonl\`);

  const app = Fastify({ trustProxy: false }); const protectedRateLimit = await registerProtectedResourceRateLimit(app);
  const protectedRoute = { config: { rateLimit: { max: protectedRateLimit.max, timeWindow: protectedRateLimit.timeWindowMs, groupId: protectedRateLimit.groupId } } };
  const clock = new SystemClock();
  const bridge = new Bridge({ config, store, clock, audit });
  const authorizer = new RequestAuthorizer({ config, clock, audit });
  const toNorm = (req: FastifyRequest): NormRequest => { const headers = Object.fromEntries(Object.entries(req.raw.headersDistinct ?? {}).flatMap(([k, v]) => !v?.length ? [] : [[k.toLowerCase(), v.length === 1 ? v[0]! : [...v]]]));
    return { query: req.query as NormRequest["query"], body: semanticOAuthBody(req.body, headers), headers, ip: req.ip };
  };
  const sendNorm = async (reply: FastifyReply, res: NormResponse): Promise<void> => {
    for (const [key, value] of Object.entries(res.headers)) reply.header(key, value);
    if (res.redirect) { await reply.redirect(res.redirect, res.status); return; }
    reply.code(res.status).send(res.body);
  };

  // Zero-setup: skip the default authorize; mount the console-pairing surface.
  await registerOAuthRoutes(app, { bridge, skipAuthorize: true });
  const pairing = createConsolePairingIdentity({ audit });
  await app.register(async (pairingApp) => { addOAuthFormContentTypeParser(pairingApp);
    pairingApp.get("/oauth/authorize", { config: { rateLimit: FASTIFY_PAIRING_AUTHORIZE_RATE_LIMIT } }, async (req, reply) => { await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "GET", toNorm(req))); });
    pairingApp.post("/oauth/authorize", { bodyLimit: OAUTH_POST_BODY_MAX_BYTES, config: { rateLimit: FASTIFY_PAIRING_AUTHORIZE_RATE_LIMIT } }, async (req, reply) => { await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "POST", toNorm(req))); });
  });

  // MCP Streamable-HTTP Origin gate (DNS-rebinding MUST): reject a present, non-allowlisted
  // Origin BEFORE body parsing, for every method. isMcpPath parses the pathname (absolute-form-safe).
  app.addHook("onRequest", async (request, reply) => {
    if (!isMcpPath(request.url)) return;
    const occurrences = request.raw.headersDistinct.origin;
    const origin = occurrences?.length === 1 ? occurrences[0] : undefined;
    const ambiguous = occurrences !== undefined && (typeof origin !== "string" || origin.includes(","));
    if (ambiguous || (origin !== undefined && !config.allowedOrigins.includes(origin) && origin !== originOf(config.issuer))) {
      reply.code(403).send({ jsonrpc: "2.0", error: { code: -32001, message: "Origin not allowed" }, id: null });
    }
  });

  // Protected /mcp: verify the bridge-minted access token, then delegate to an MCP server.
  app.post("/mcp", protectedRoute, async (request, reply) => {
    let auth;
    try {
      auth = await authorizer.authorize({ authorization: request.raw.headersDistinct.authorization });
    } catch (error) {
      const oe = error instanceof OAuthError ? error : new OAuthError("invalid_token", "Bearer token is invalid", 401);
      reply.header("www-authenticate", buildUnauthorizedChallenge(config, { scope: config.scopeCatalog, error: oe.code, errorDescription: oe.message }));
      reply.code(oe.status).send({ jsonrpc: "2.0", error: { code: -32001, message: \`\${oe.code}:\${oe.message}\` }, id: null });
      return;
    }
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    const mcp = new McpServer({ name: "mcp-sso", version: "1.0.0" });
    mcp.tool("ping", "echo the authenticated subject", async () => ({ content: [{ type: "text" as const, text: \`pong: \${auth.subject}\` }] }));
    await mcp.connect(transport);
    reply.hijack();
    try { await transport.handleRequest(request.raw, reply.raw, request.body); }
    finally { await mcp.close(); }
  });

  await app.listen({ port: PORT, host: HOST });
  console.error(\`mcp-sso listening on \${oneLine(HOST)}:\${PORT}  (console pairing — paste the one-time code printed above)\`);
  console.error(\`  issuer=\${oneLine(config.issuer)}  resource=\${oneLine(config.resource)}\`);
  console.error(\`  pair with: claude mcp add --transport http my-bridge \${oneLine(RESOURCE)}\`);
}

main().catch((error) => { console.error(oneLine((error as Error)?.message ?? error)); process.exit(1); });
`;

function packageJson(vars: TemplateVars): string {
  // Exact pins only (no ^/~) — supply-chain rule. Node >=24 (native TS, no build step).
  const pkg = {
    name: vars.name,
    version: "0.0.0",
    private: true,
    type: "module",
    scripts: { start: "node server.ts" },
    engines: { node: ">=24" },
    dependencies: {
      "mcp-sso": vars.mcpSsoVersion,
      "@fastify/rate-limit": FASTIFY_RATE_LIMIT_VERSION,
      fastify: FASTIFY_VERSION,
      "@modelcontextprotocol/sdk": MCP_SDK_VERSION,
    },
  };
  return JSON.stringify(pkg, null, 2) + "\n";
}

const GITIGNORE = `node_modules/
.mcp-sso/
`;
// Harden the install: no dependency lifecycle/postinstall scripts run unless the operator
// explicitly vets one (the project's supply-chain posture — install scripts are a primary
// npm supply-chain vector). mcp-sso + fastify + the MCP SDK are pure JS (no scripts), so
// this is the safe default; remove the line only if a dep you've vetted needs a script.
const NPMRC = `ignore-scripts=true
`;
/** Every file \`mcp-sso init\` writes, in write-order. */
export function templateFiles(vars: TemplateVars): TemplateFile[] {
  return [
    { path: "package.json", content: packageJson(vars) },
    { path: "server.ts", content: SERVER_TS },
    { path: ".gitignore", content: GITIGNORE },
    { path: ".npmrc", content: NPMRC },
    { path: "README.md", content: generatedReadme(vars.name) },
  ];
}
