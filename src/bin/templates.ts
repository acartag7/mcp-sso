// File templates for `mcp-sso init` (contracts §15 "Init CLI"). Each generated file
// is a faithful, minimal composition root a stranger can `npm install && npm start`.
// The init binary is dep-free (node builtins only); these strings ship in dist/bin.

/** fastify + the MCP SDK are pinned to the versions mcp-sso is TESTED against (the
 *  repo's devDependencies). The published package cannot read the repo's devDeps at
 *  runtime, so these are fixed here + recorded in docs/dependency-ledger.md; bump them
 *  with the repo's devDeps (exact pins, no ^/~, per the supply-chain rules). */
const FASTIFY_VERSION = "5.8.5";
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
  Bridge, RequestAuthorizer, createBridgeConfig, originOf, isMcpPath,
  loadOrCreateQuickstartSecrets, handlePairingAuthorize,
  SystemClock, JsonlFileAudit, buildUnauthorizedChallenge, OAuthError,
} from "mcp-sso";
import { registerOAuthRoutes } from "mcp-sso/fastify";
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
// 127.0.0.1 (not localhost) matches the HOST bind — no IPv6/IPv4 address-family mismatch.
let ISSUER = env("OAUTH_ISSUER", \`http://127.0.0.1:\${PORT}\`);
while (ISSUER.endsWith("/")) ISSUER = ISSUER.slice(0, -1); // trim a trailing / so the derived resource is /mcp, not //mcp
const RESOURCE = env("OAUTH_RESOURCE", \`\${ISSUER}/mcp\`);
const list = (v: string | undefined, def: string): string[] => (v ?? def).split(",").map((s) => s.trim()).filter(Boolean);
// allowInsecureLocalhost lets an http:// loopback issuer boot for local dev (the
// bridge mints real tokens; never set this for a non-loopback / production issuer).
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);
const isLoopback = (url: string): boolean => { try { return LOOPBACK.has(new URL(url).hostname); } catch { return false; } };

async function main(): Promise<void> {
  // loadOrCreateQuickstartSecrets creates DIR (0o700) + the managed .gitignore +
  // the signing material on first boot (the fs-trust bar + zero-setup keys).
  const secrets = await loadOrCreateQuickstartSecrets({ dir: DIR });
  const audit = new JsonlFileAudit(\`\${DIR}/audit.jsonl\`);
  const config = createBridgeConfig({
    issuer: ISSUER, resource: RESOURCE,
    consentSigningSecret: secrets.consentSigningSecret,
    signingPrivateJwk: secrets.signingPrivateJwk,
    redirectAllowlist: list(process.env.OAUTH_REDIRECT_ALLOWLIST, ""),
    scopeCatalog: list(process.env.OAUTH_SCOPE_CATALOG, "mcp:read,mcp:write"),
    defaultScopes: list(process.env.OAUTH_DEFAULT_SCOPES, "mcp:read"),
    allowedOrigins: list(process.env.OAUTH_ALLOWED_ORIGINS, ISSUER),
    dev: isLoopback(ISSUER) ? { allowInsecureLocalhost: true } : undefined,
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });

  const app = Fastify();
  const clock = new SystemClock();
  const store = openSqliteStore(\`\${DIR}/auth.db\`);
  const bridge = new Bridge({ config, store, clock, audit });
  const authorizer = new RequestAuthorizer({ config, clock, audit });
  const toNorm = (req: FastifyRequest): NormRequest => ({
    query: req.query as NormRequest["query"], body: req.body, headers: req.headers as NormRequest["headers"], ip: req.ip,
  });
  const sendNorm = async (reply: FastifyReply, res: NormResponse): Promise<void> => {
    for (const [key, value] of Object.entries(res.headers)) reply.header(key, value);
    if (res.redirect) { await reply.redirect(res.redirect, res.status); return; }
    reply.code(res.status).send(res.body);
  };

  // Zero-setup: skip the default authorize; mount the console-pairing surface.
  await registerOAuthRoutes(app, { bridge, skipAuthorize: true });
  const pairing = createConsolePairingIdentity({ audit });
  app.get("/oauth/authorize", async (req, reply) => { await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "GET", toNorm(req))); });
  app.post("/oauth/authorize", async (req, reply) => { await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "POST", toNorm(req))); });

  // MCP Streamable-HTTP Origin gate (DNS-rebinding MUST): reject a present, non-allowlisted
  // Origin BEFORE body parsing, for every method. isMcpPath parses the pathname (absolute-form-safe).
  app.addHook("onRequest", async (request, reply) => {
    if (!isMcpPath(request.url)) return;
    const rawOrigin = request.headers.origin;
    const origin = Array.isArray(rawOrigin) ? rawOrigin[0] : rawOrigin;
    if (origin !== undefined && !config.allowedOrigins.includes(origin) && origin !== originOf(config.issuer)) {
      reply.code(403).send({ jsonrpc: "2.0", error: { code: -32001, message: "Origin not allowed" }, id: null });
    }
  });

  // Protected /mcp: verify the bridge-minted access token, then delegate to an MCP server.
  app.post("/mcp", async (request, reply) => {
    let auth;
    try {
      auth = await authorizer.authorize({ authorization: request.headers.authorization });
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

  // Off-loopback warning: the one-time pairing code is the identity gate, so binding
  // it to a non-loopback host exposes the pairing surface to the network (single-
  // operator / private-console use only). Mirrors examples/fastify-sqlite/index.ts.
  if (HOST !== "127.0.0.1" && HOST !== "localhost") {
    console.error(\`[mcp-sso] WARNING: console pairing is bound to \${HOST} (non-loopback). The one-time code is the identity gate — anyone who can reach this port can attempt it. Pairing is for single-operator / private-console use only; use a real identity provider for a network-exposed server.\`);
    // HOST moved off loopback: the issuer MUST be the publicly-reachable URL or discovery
    // advertises 127.0.0.1 (which clients can't reach) + RFC 9728 resource validation fails.
    if (!(process.env.OAUTH_ISSUER && process.env.OAUTH_ISSUER.trim())) {
      console.error(\`[mcp-sso] WARNING: HOST=\${HOST} but OAUTH_ISSUER is unset (defaults to http://127.0.0.1:\${PORT}). Set OAUTH_ISSUER to the URL clients actually reach.\`);
    }
  }
  await app.listen({ port: PORT, host: HOST });
  console.error(\`mcp-sso listening on \${HOST}:\${PORT}  (console pairing — paste the one-time code printed above)\`);
  console.error(\`  issuer=\${config.issuer}  resource=\${config.resource}\`);
  console.error(\`  pair with: claude mcp add --transport http my-bridge \${RESOURCE}\`);
}

main().catch((error) => { console.error(error); process.exit(1); });
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

function readme(vars: TemplateVars): string {
  return `# ${vars.name}

An [mcp-sso](https://github.com/acartag7/mcp-sso) MCP server — OAuth 2.1 for a remote
MCP server, zero-setup (console pairing: no identity provider, no keys to generate).

## Run

\`\`\`bash
npm install

# Terminal 1 — the server (stays foreground):
npm start

# Terminal 2 — once the server is up (it prints a one-time code ONLY when a client connects):
claude mcp add --transport http my-bridge http://127.0.0.1:3000/mcp
# → the server prints the code to Terminal 1; a browser opens — paste the code, approve.
\`\`\`

\`npm install\` creates \`package-lock.json\` — commit it. The top-level pins above are
exact (the versions mcp-sso is tested against); the lockfile fixes the transitive graph.

The server binds loopback (127.0.0.1) by default — the printed pairing code is the
identity gate, so it must not be exposed to the network. Override with HOST/PORT env.

## Production identity provider

Console pairing is for single-operator / private-console use. For a real identity
provider (Cloudflare Access, Microsoft Entra ID, Google, or a generic OIDC issuer),
graduate to the env-driven composition root in
[examples/fastify-sqlite](https://github.com/acartag7/mcp-sso/tree/main/examples/fastify-sqlite)
and follow [docs/gateway-deployment.md](https://github.com/acartag7/mcp-sso/blob/main/docs/gateway-deployment.md)
+ [docs/live-verification.md](https://github.com/acartag7/mcp-sso/blob/main/docs/live-verification.md).
`;
}

/** Every file \`mcp-sso init\` writes, in write-order. */
export function templateFiles(vars: TemplateVars): TemplateFile[] {
  return [
    { path: "package.json", content: packageJson(vars) },
    { path: "server.ts", content: SERVER_TS },
    { path: ".gitignore", content: GITIGNORE },
    { path: ".npmrc", content: NPMRC },
    { path: "README.md", content: readme(vars) },
  ];
}
