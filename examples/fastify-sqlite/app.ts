// Runnable example: Fastify + sqlite. The standalone entry (index.ts) wires the
// zero-setup path — quickstart secrets (§17.8) + console pairing (§17.5) + a JSONL
// audit sink — so the server boots with NO signing/consent env config and an
// operator pastes a one-time code from the console. buildApp() also still supports
// a header-based IdentityPort (used by the e2e test). The verify gate
// (test/e2e-mcp-sdk.test.ts + test/e2e-pairing.test.ts) imports buildApp().

import Fastify, { type FastifyReply } from "fastify";
import { chmod, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Bridge } from "../../src/adapters/bridge.ts";
import { createBridgeConfig, originOf, type BridgeConfig } from "../../src/config.ts";
import { OAuthError, oauthErrorBody } from "../../src/errors.ts";
import { buildUnauthorizedChallenge } from "../../src/challenge.ts";
import { RequestAuthorizer } from "../../src/verifier.ts";
import { SystemClock } from "../../src/ports/clock.ts";
import { noopAudit, type AuditPort } from "../../src/ports/audit.ts";
import { JsonlFileAudit } from "../../src/audit/jsonl-file.ts";
import { openSqliteStore } from "../../src/store/sqlite.ts";
import { loadOrCreateQuickstartSecrets, ensureGitignore, assertRealDir } from "../../src/quickstart.ts";
import { createCloudflareAccessIdentity } from "../../src/identity/cloudflare-access.ts";
import { createEntraRedirectIdentity } from "../../src/identity/entra-redirect.ts";
import { createGoogleRedirectIdentity, type GoogleConfig } from "../../src/identity/google.ts";
import { createGenericOidcRedirectIdentity, type GenericOidcConfig } from "../../src/identity/generic-oidc.ts";
import type { IdentityPort, RedirectIdentityPort } from "../../src/ports/identity.ts";
import { createConsolePairingIdentity, type ConsolePairingOptions } from "../../src/identity/console-pairing.ts";
import { handlePairingAuthorize } from "../../src/adapters/pairing-flow.ts";
import { createUpstreamRedirectFlow } from "../../src/adapters/upstream-flow.ts";
import { isMcpPath, type NormRequest, type NormResponse } from "../../src/adapters/http.ts";
import { registerOAuthRoutes } from "../../src/adapters/fastify.ts";

export interface ExampleOptions {
  config: BridgeConfig;
  /** Header-based IdentityPort for the default authorize path (e2e-test mode). */
  identity?: IdentityPort;
  /** Console-pairing OPTIONS — when set, buildApp constructs the identity itself
   *  (wiring the buildApp `audit` dep into it) and mounts the pairing authorize
   *  surface. Passing options (not a pre-built identity) guarantees pairing audit
   *  events are never dropped relative to the Bridge/RequestAuthorizer audit. */
  pairing?: ConsolePairingOptions;
  /** §17.11 upstream redirect-flow identity + callback config. When set, buildApp
   *  builds `createUpstreamRedirectFlow` with the SAME store/clock/audit the
   *  Bridge uses (the composition root passes the shared instances — §17.11). */
  upstream?: { identity: RedirectIdentityPort; callbackPath?: string; flowTtlSeconds?: number };
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

  if (opts.upstream) {
    // §17.11 upstream redirect-flow mode: the bridge delegates /oauth/authorize +
    // the callback to the orchestrator, built here with the SAME store/clock/audit
    // the Bridge uses (the composition root owns the shared instances).
    const upstream = createUpstreamRedirectFlow({
      bridge, identity: opts.upstream.identity, store, clock, audit,
      callbackPath: opts.upstream.callbackPath, flowTtlSeconds: opts.upstream.flowTtlSeconds,
    });
    await registerOAuthRoutes(app, { bridge, upstream });
  } else if (opts.pairing) {
    // Zero-setup mode: registerOAuthRoutes skips /oauth/authorize; we mount a
    // GET (render pairing page) + POST (verify code → consent page) via the
    // framework-free handlePairingAuthorize orchestrator.
    await registerOAuthRoutes(app, { bridge, skipAuthorize: true });
    const pairing = createConsolePairingIdentity({ ...opts.pairing, audit });
    app.get("/oauth/authorize", async (req, reply) => {
      await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "GET", toNorm(req as never)));
    });
    app.post("/oauth/authorize", async (req, reply) => {
      await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "POST", toNorm(req as never)));
    });
  } else {
    // Awaited so a missing `identity` (now optional for the pairing mode) rejects
    // buildApp fast via registerOAuthRoutes' runtime guard, instead of becoming an
    // unhandled rejection with a partially-registered app.
    await registerOAuthRoutes(app, { bridge, identity: opts.identity, identityHeader: opts.identityHeader });
  }

  // Origin gate — MCP Streamable HTTP transport DNS-rebinding protection (servers
  // MUST validate the `Origin` header on every connection; reject a present,
  // non-allowlisted Origin). Scoped to /mcp and placed in an onRequest hook so it
  // runs BEFORE body parsing and for EVERY method (POST/GET/DELETE) — NOT inside
  // the POST handler, where Fastify's body parser would already have read/rejected
  // the body (a foreign-Origin POST with malformed/oversized JSON would get
  // Fastify's 400/413, not this 403 gate), and where GET/DELETE /mcp would bypass
  // it entirely. Done here, not via the SDK transport's
  // enableDnsRebindingProtection/allowedOrigins: those are off by default +
  // @deprecated, and run INSIDE transport.handleRequest() (after the bearer
  // check), so they can't satisfy "before anything else" (docs/gateway-deployment.md).
  // An ABSENT Origin proceeds (MCP clients are not browsers); a PRESENT Origin must
  // match config.allowedOrigins (defaults to the issuer) or the server's own origin
  // originOf(issuer) — which normalizes a trailing-slash/path issuer (mirrors
  // src/authorize.ts assertOrigin; like it, allowedOrigins entries are matched
  // exactly, not normalized). The OAuth routes have their own origin handling, so
  // this hook is scoped to /mcp only.
  app.addHook("onRequest", async (request, reply) => {
    if (!isMcpPath(request.url)) return; // OAuth routes manage their own Origin; isMcpPath parses the pathname (absolute-form-safe)
    const rawOrigin = request.headers.origin;
    const origin = Array.isArray(rawOrigin) ? rawOrigin[0] : rawOrigin;
    if (origin !== undefined && !opts.config.allowedOrigins.includes(origin) && origin !== originOf(opts.config.issuer)) {
      reply.code(403).send({ jsonrpc: "2.0", error: { code: -32001, message: "Origin not allowed" }, id: null });
      return;
    }
  });

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

/** Default listen host by mode. Console pairing binds LOOPBACK by default (its
 *  trust envelope is "whoever can read the process's stderr IS the operator" —
 *  a non-loopback bind exposes the pairing authorize surface + the printed-code
 *  attempt budget to the network). Cloudflare and every redirect-flow path bind
 *  0.0.0.0 (network deployment — the real IdP is the gate, unlike pairing's
 *  loopback envelope; the callback must be reachable by the IdP). HOST env
 *  overrides either. */
export function defaultListenHost(env: Record<string, string | undefined> = process.env): string {
  return (env.CF_ACCESS_AUDIENCE || env.ENTRA_TENANT_ID || env.GOOGLE_CLIENT_ID || env.OIDC_ISSUER) ? "0.0.0.0" : "127.0.0.1";
}

/** Read config from env (the production path; standalone index.ts uses quickstart
 *  secrets instead). Accepts an env object so the wiring is testable without
 *  mutating the real process.env. */
export function configFromEnv(env: Record<string, string | undefined> = process.env): BridgeConfig {
  const required = ["OAUTH_ISSUER", "OAUTH_RESOURCE", "OAUTH_CONSENT_SIGNING_SECRET", "OAUTH_SIGNING_PRIVATE_JWK"];
  const missing = required.filter((k) => !env[k]);
  if (missing.length) throw new Error(`Missing env: ${missing.join(", ")}`);
  return createBridgeConfig({
    issuer: env.OAUTH_ISSUER!,
    resource: env.OAUTH_RESOURCE!,
    consentSigningSecret: env.OAUTH_CONSENT_SIGNING_SECRET!,
    signingPrivateJwk: JSON.parse(env.OAUTH_SIGNING_PRIVATE_JWK!) as never,
    signingKeyId: env.OAUTH_SIGNING_KEY_ID || undefined,
    redirectAllowlist: (env.OAUTH_REDIRECT_ALLOWLIST ?? "").split(",").map((s) => s.trim()).filter(Boolean),
    scopeCatalog: (env.OAUTH_SCOPE_CATALOG ?? "mcp:read,mcp:write").split(",").map((s) => s.trim()).filter(Boolean),
    defaultScopes: (env.OAUTH_DEFAULT_SCOPES ?? "mcp:read").split(",").map((s) => s.trim()).filter(Boolean),
    allowedOrigins: (env.OAUTH_ALLOWED_ORIGINS ?? env.OAUTH_ISSUER!).split(",").map((s) => s.trim()).filter(Boolean),
    dcr: { mode: "stateless" },
    dev: env.OAUTH_ALLOW_INSECURE_LOCALHOST === "true" ? { allowInsecureLocalhost: true } : undefined,
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
function isLoopback(url: string): boolean {
  try { return LOOPBACK_HOSTS.has(new URL(url).hostname); } catch { return false; }
}
function listEnv(env: Record<string, string | undefined>, k: string, def: string): string[] {
  return (env[k] ?? def).split(",").map((s) => s.trim()).filter(Boolean);
}
function mustEnv(env: Record<string, string | undefined>, k: string): string {
  const v = env[k];
  if (!v) throw new Error(`Missing env: ${k}`);
  return v;
}

function booleanEnv(env: Record<string, string | undefined>, k: string): boolean | undefined {
  const value = env[k];
  if (value === undefined || value === "") return undefined;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`Invalid env: ${k} must be 'true' or 'false'`);
}

export interface OidcIdentityFactories {
  google?: (config: GoogleConfig) => Promise<RedirectIdentityPort>;
  genericOidc?: (config: GenericOidcConfig) => Promise<RedirectIdentityPort>;
}

/** Build either shipped §17.6 RedirectIdentityPort from env. Shared with the
 *  gateway example so provider config and branch precedence cannot drift. */
export async function createOidcUpstreamFromEnv(
  env: Record<string, string | undefined>,
  factories: OidcIdentityFactories = {},
): Promise<{ identity: RedirectIdentityPort; callbackPath: string } | undefined> {
  if (env.GOOGLE_CLIENT_ID) {
    const redirectUri = mustEnv(env, "GOOGLE_REDIRECT_URI");
    const callbackPath = new URL(redirectUri).pathname;
    const identity = await (factories.google ?? createGoogleRedirectIdentity)({
      clientId: mustEnv(env, "GOOGLE_CLIENT_ID"),
      clientSecret: mustEnv(env, "GOOGLE_CLIENT_SECRET"),
      redirectUri,
      hostedDomain: env.GOOGLE_HOSTED_DOMAIN || undefined,
      subjectAllowlist: listEnv(env, "GOOGLE_SUBJECT_ALLOWLIST", ""),
      allowEmailAllowlist: booleanEnv(env, "GOOGLE_ALLOW_EMAIL_ALLOWLIST"),
    });
    return { identity, callbackPath };
  }
  if (env.OIDC_ISSUER) {
    const redirectUri = mustEnv(env, "OIDC_REDIRECT_URI");
    const callbackPath = new URL(redirectUri).pathname;
    const identity = await (factories.genericOidc ?? createGenericOidcRedirectIdentity)({
      issuer: mustEnv(env, "OIDC_ISSUER"),
      clientId: mustEnv(env, "OIDC_CLIENT_ID"),
      clientSecret: env.OIDC_CLIENT_SECRET || undefined,
      redirectUri,
      endpoints: "discover",
      scopes: env.OIDC_SCOPES || undefined,
      subjectAllowlist: listEnv(env, "OIDC_SUBJECT_ALLOWLIST", ""),
    });
    return { identity, callbackPath };
  }
  return undefined;
}

/** Ensure the state dir exists AND meets the full security bar — same bar the
 *  zero-setup branch gets from loadOrCreateQuickstartSecrets. Creates the dir 0700
 *  if absent; for a pre-existing dir, rejects a symlink or group/other-accessible
 *  mode (another local user could otherwise replace auth.db with state they
 *  control). Writes the managed `*` .gitignore into a dir we just made (or
 *  requires it already present + exact) so auth.db / audit.jsonl can't be committed.
 *
 *  Exported so the api-key-gateway example reuses the SAME fs-trust bar (the
 *  sibling-sweep rule — a control fixed in one path MUST be applied to every
 *  path that touches the state dir), not a second copy that could drift. */
export async function ensureStateDir(dir: string): Promise<void> {
  const created = await mkdir(dir, { recursive: true });
  if (created !== undefined) {
    if (process.platform !== "win32") await chmod(dir, 0o700);
  } else {
    await assertRealDir(dir); // pre-existing: real dir, not a symlink, not group/other-accessible
  }
  await ensureGitignore(dir, created !== undefined);
}

/** The standalone entry's wiring, factored out so it can be integration-tested
 *  without `app.listen()`. Selects Entra, Cloudflare Access, Google, or generic
 *  OIDC from env; otherwise uses quickstart secrets + console pairing. Returns
 *  the built app (+ store/config/dir). */
export async function buildExample(
  env: Record<string, string | undefined> = process.env,
  identityFactories: OidcIdentityFactories = {},
): Promise<{
  app: ReturnType<typeof Fastify>;
  store: ReturnType<typeof openSqliteStore>;
  config: BridgeConfig;
  dir: string;
}> {
  const dir = env.MCP_SSO_DIR ?? "./.mcp-sso";
  const sqliteFile = env.OAUTH_SQLITE_FILE ?? join(dir, "auth.db");
  const audit = new JsonlFileAudit(join(dir, "audit.jsonl"));

  if (env.ENTRA_TENANT_ID) {
    // §17.11 PRODUCTION: Entra redirect-flow. The upstream IdP (Entra app
    // assignment / Conditional Access) is the auth gate, so this is network-bound
    // (0.0.0.0) like Cloudflare — NOT loopback. ENTRA_REDIRECT_URI's pathname is
    // the callbackPath; createUpstreamRedirectFlow boot-asserts it equals
    // originOf(OAUTH_ISSUER) + callbackPath (a mismatch is silent breakage at the
    // IdP, so it fails closed at boot). The bridge's own signing material still
    // comes from OAUTH_* env (configFromEnv).
    await ensureStateDir(dir);
    const config = configFromEnv(env);
    const redirectUri = mustEnv(env, "ENTRA_REDIRECT_URI");
    const callbackPath = new URL(redirectUri).pathname;
    const identity = createEntraRedirectIdentity({
      tenantId: mustEnv(env, "ENTRA_TENANT_ID"),
      clientId: mustEnv(env, "ENTRA_CLIENT_ID"),
      clientSecret: env.ENTRA_CLIENT_SECRET,
      redirectUri,
      allowedTenantIds: listEnv(env, "ENTRA_ALLOWED_TENANT_IDS", ""),
      subjectAllowlist: listEnv(env, "ENTRA_SUBJECT_ALLOWLIST", ""),
    }, { scopeCatalog: config.scopeCatalog });
    const { app, store } = await buildApp({ config, upstream: { identity, callbackPath }, audit, sqliteFile });
    return { app, store, config, dir };
  }
  if (env.CF_ACCESS_AUDIENCE) {
    // PRODUCTION: Cloudflare Access + env signing material. This branch does NOT
    // run the quickstart helper, so create the state dir explicitly (sqlite open +
    // audit append otherwise fail on the missing parent).
    await ensureStateDir(dir);
    const config = configFromEnv(env);
    const identity = createCloudflareAccessIdentity({
      audience: mustEnv(env, "CF_ACCESS_AUDIENCE"),
      certsUrl: mustEnv(env, "CF_ACCESS_CERTS_URL"),
      issuer: mustEnv(env, "CF_ACCESS_ISSUER"),
      emailAllowlist: listEnv(env, "CF_ACCESS_EMAIL_ALLOWLIST", ""),
    });
    const { app, store } = await buildApp({ config, identity, audit, sqliteFile });
    return { app, store, config, dir };
  }
  if (env.GOOGLE_CLIENT_ID || env.OIDC_ISSUER) {
    // §17.6 + §17.11 PRODUCTION: Google or generic OIDC redirect flow. The
    // configured redirect URI's pathname is the mounted callback route; the
    // orchestrator boot-asserts the full URI equals issuerOrigin + callbackPath.
    const config = configFromEnv(env);
    const upstream = await createOidcUpstreamFromEnv(env, identityFactories);
    if (!upstream) throw new Error("OIDC identity branch selected without provider config");
    await ensureStateDir(dir);
    const { app, store } = await buildApp({ config, upstream, audit, sqliteFile });
    return { app, store, config, dir };
  }

  // ZERO-SETUP: quickstart secrets (creates the dir, secrets, .gitignore) + console
  // pairing. buildApp takes pairing OPTIONS and wires `audit` into the identity.
  const secrets = await loadOrCreateQuickstartSecrets({ dir });
  const port = Number(env.PORT ?? 3000);
  const issuer = env.OAUTH_ISSUER ?? `http://localhost:${port}`;
  const resource = env.OAUTH_RESOURCE ?? `http://localhost:${port}/mcp`;
  const config = createBridgeConfig({
    issuer,
    resource,
    consentSigningSecret: secrets.consentSigningSecret,
    signingPrivateJwk: secrets.signingPrivateJwk,
    redirectAllowlist: listEnv(env, "OAUTH_REDIRECT_ALLOWLIST", ""),
    scopeCatalog: listEnv(env, "OAUTH_SCOPE_CATALOG", "mcp:read,mcp:write"),
    defaultScopes: listEnv(env, "OAUTH_DEFAULT_SCOPES", "mcp:read"),
    allowedOrigins: listEnv(env, "OAUTH_ALLOWED_ORIGINS", issuer),
    dcr: { mode: "stateless" },
    dev: isLoopback(issuer) ? { allowInsecureLocalhost: true } : undefined,
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const { app, store } = await buildApp({ config, pairing: {}, audit, sqliteFile });
  return { app, store, config, dir };
}
