// API-key-gateway example (contracts §17.9 / docs/gateway-deployment.md).
//
// mcp-sso as the SSO front door for a token-only backend MCP server. The backend
// only accepts a static credential (BACKEND_API_KEY); users authenticate through a
// real IdP (Cloudflare Access / Entra / console pairing for local dev), the
// gateway verifies its own bridge-minted token on /mcp, and forwards the request
// to the backend with the static credential injected SERVER-SIDE. The backend
// credential never reaches an MCP client, a laptop, or a config file.
//
// buildGateway() is the factory (factored buildExample-style: it returns the app
// WITHOUT calling listen(), so the wiring is integration-testable in-process).
// buildGatewayExample(env, { backendUrl, getBackendCredential }) mirrors the
// fastify-sqlite example's identity branch selection. index.ts adds listen() +
// starts the stub backend.

import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { Readable, pipeline } from "node:stream";
import { join } from "node:path";
import { Bridge } from "../../src/adapters/bridge.ts";
import { createBridgeConfig, originOf, type BridgeConfig } from "../../src/config.ts";
import { OAuthError } from "../../src/errors.ts";
import { buildUnauthorizedChallenge } from "../../src/challenge.ts";
import { RequestAuthorizer, type RequestAuthResult } from "../../src/verifier.ts";
import { SystemClock } from "../../src/ports/clock.ts";
import { noopAudit, type AuditPort } from "../../src/ports/audit.ts";
import { JsonlFileAudit } from "../../src/audit/jsonl-file.ts";
import { openSqliteStore } from "../../src/store/sqlite.ts";
import { loadOrCreateQuickstartSecrets } from "../../src/quickstart.ts";
import { createCloudflareAccessIdentity } from "../../src/identity/cloudflare-access.ts";
import { createEntraRedirectIdentity } from "../../src/identity/entra-redirect.ts";
import type { IdentityPort, RedirectIdentityPort } from "../../src/ports/identity.ts";
import { createConsolePairingIdentity, type ConsolePairingOptions } from "../../src/identity/console-pairing.ts";
import { handlePairingAuthorize } from "../../src/adapters/pairing-flow.ts";
import { createUpstreamRedirectFlow } from "../../src/adapters/upstream-flow.ts";
import { isMcpPath, type NormRequest, type NormResponse } from "../../src/adapters/http.ts";
import { registerOAuthRoutes } from "../../src/adapters/fastify.ts";
// Reuse the fastify-sqlite example's env-wiring + fs-trust helpers rather than
// duplicate them — ensureStateDir is the security-critical state-dir bar (the
// sibling-sweep rule); configFromEnv / defaultListenHost are the same env switch.
import { configFromEnv, ensureStateDir, defaultListenHost } from "../fastify-sqlite/app.ts";

export interface GatewayOptions {
  config: BridgeConfig;
  /** Full backend /mcp endpoint the gateway proxies to (e.g. http://127.0.0.1:8788/mcp).
   *  Trusted deployer config — NOT user input — so the forward fetch is not SSRF-guarded
   *  (same rationale as §17.6 trusted-config fetches). */
  backendUrl: string;
  /** Accessor closure over BACKEND_API_KEY (read once at boot by index.ts). The
   *  gateway calls this only to build the outbound Authorization header; the value
   *  is never logged, audited, placed in a token claim, or returned to a client. */
  getBackendCredential: () => string;
  /** Header-based IdentityPort for the default authorize path (Cloudflare Access). */
  identity?: IdentityPort;
  /** Console-pairing OPTIONS — when set, the gateway mounts the pairing authorize surface. */
  pairing?: ConsolePairingOptions;
  /** §17.11 upstream redirect-flow identity + callback config (Entra redirect). */
  upstream?: { identity: RedirectIdentityPort; callbackPath?: string; flowTtlSeconds?: number };
  sqliteFile?: string; // defaults to :memory:
  identityHeader?: string;
  /** Audit sink for the Bridge + RequestAuthorizer (+ pairing). Default noopAudit. */
  audit?: AuditPort;
}

// Request headers the transparent proxy forwards to the backend (allowlist — fails
// closed when a new header appears; everything else, including the client's
// Authorization, is dropped). Per docs/gateway-deployment.md: MCP-Protocol-Version
// (every request after init), Accept (+ Content-Type on POST), mcp-session-id
// (stateful backends), Last-Event-ID (GET resume).
const FWD_REQUEST_HEADERS = ["mcp-protocol-version", "accept", "content-type", "mcp-session-id", "last-event-id"] as const;
// Response headers relayed back to the client (allowlist — never echo backend
// internals, Server, Set-Cookie, etc.).
const RELAY_RESPONSE_HEADERS = ["content-type", "mcp-session-id", "mcp-protocol-version"] as const;

/** Build the gateway app: OAuth routes + metadata (so MCP clients discover/register/
 *  authorize) + a transparent-proxy /mcp. Does not listen — the caller owns the socket. */
export async function buildGateway(opts: GatewayOptions): Promise<{
  app: FastifyInstance;
  store: ReturnType<typeof openSqliteStore>;
  bridge: Bridge;
  close: () => Promise<void>;
}> {
  const app = Fastify();
  const clock = new SystemClock();
  const store = openSqliteStore(opts.sqliteFile ?? ":memory:");
  const audit: AuditPort = opts.audit ?? noopAudit;
  const bridge = new Bridge({ config: opts.config, store, clock, audit });
  const authorizer = new RequestAuthorizer({ config: opts.config, clock, audit });

  const toNorm = (req: { query: unknown; body: unknown; headers: unknown; ip?: string }): NormRequest => ({
    query: req.query as NormRequest["query"], body: req.body, headers: req.headers as NormRequest["headers"], ip: req.ip,
  });
  const sendNorm = async (reply: FastifyReply, res: NormResponse): Promise<void> => {
    for (const [key, value] of Object.entries(res.headers)) reply.header(key, value);
    if (res.redirect) { await reply.redirect(res.redirect, res.status); return; }
    reply.code(res.status).send(res.body);
  };

  // --- OAuth routes + metadata (identical surface to examples/fastify-sqlite/app.ts) ---
  if (opts.upstream) {
    const upstream = createUpstreamRedirectFlow({
      bridge, identity: opts.upstream.identity, store, clock, audit,
      callbackPath: opts.upstream.callbackPath, flowTtlSeconds: opts.upstream.flowTtlSeconds,
    });
    await registerOAuthRoutes(app, { bridge, upstream });
  } else if (opts.pairing) {
    await registerOAuthRoutes(app, { bridge, skipAuthorize: true });
    const pairing = createConsolePairingIdentity({ ...opts.pairing, audit });
    app.get("/oauth/authorize", async (req, reply) => {
      await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "GET", toNorm(req as never)));
    });
    app.post("/oauth/authorize", async (req, reply) => {
      await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "POST", toNorm(req as never)));
    });
  } else {
    await registerOAuthRoutes(app, { bridge, identity: opts.identity, identityHeader: opts.identityHeader });
  }

  // Transparent proxy forwards the RAW /mcp body (do not re-serialize MCP JSON-RPC);
  // OAuth routes (/oauth/register) still receive a parsed object. This parser
  // overrides Fastify's built-in application/json handler and dispatches by URL —
  // using isMcpPath (pathname parse) so an absolute-form request-target is still
  // recognized as /mcp (a raw `=== "/mcp"` would JSON-parse it, forwarding
  // "[object Object]" and letting a tokenless malformed body trip Fastify's 400
  // before the 401 challenge).
  app.addContentTypeParser("application/json", { parseAs: "string" }, (req, body, done) => {
    if (isMcpPath(req.url)) done(null, body); // raw string — forwarded verbatim
    else { try { done(null, JSON.parse(String(body))); } catch (err) { done(err as Error, undefined); } }
  });

  // Origin gate — MCP Streamable HTTP DNS-rebinding MUST (servers MUST validate
  // Origin on every connection; 403 when present but not allowlisted). Scoped to /mcp
  // and in an onRequest hook so it runs BEFORE body parsing and for EVERY method
  // (POST/GET/DELETE) — not inside the POST handler (where a foreign-Origin malformed
  // body would trip the parser first, and GET/DELETE would bypass it). The SDK
  // transport's enableDnsRebindingProtection/allowedOrigins are off-by-default +
  // @deprecated and run inside handleRequest (after the bearer check), so they
  // cannot satisfy "before anything else". Absent Origin proceeds (MCP clients are
  // not browsers); a present Origin must match config.allowedOrigins or originOf(issuer).
  app.addHook("onRequest", async (request, reply) => {
    // isMcpPath PARSES the pathname (don't string-compare request.url): an absolute-form
    // request-target (`POST http://host/mcp`) routes here with request.url = the full
    // URL, so a raw `!== "/mcp"` check would skip the Origin gate. Same normalization
    // as the backend's auth gate (sibling-sweep) + the JSON parser above.
    if (!isMcpPath(request.url)) return; // OAuth routes manage their own Origin
    const rawOrigin = request.headers.origin;
    const origin = Array.isArray(rawOrigin) ? rawOrigin[0] : rawOrigin;
    if (origin !== undefined && !opts.config.allowedOrigins.includes(origin) && origin !== originOf(opts.config.issuer)) {
      reply.code(403).send({ jsonrpc: "2.0", error: { code: -32001, message: "Origin not allowed" }, id: null });
    }
  });

  // Bearer gate. authorize() THROWS on a missing/invalid/expired token — it does
  // not build the response. The handler MUST catch and answer with the OAuthError
  // status, a WWW-Authenticate challenge from buildUnauthorizedChallenge (the
  // resource_metadata URL is how MCP clients discover the AS — without it they
  // never start the OAuth flow), and a JSON-RPC error body. Returns the authorized
  // subject on success, or null once the challenge response has been sent.
  const authorizeOrChallenge = async (request: FastifyRequest, reply: FastifyReply): Promise<RequestAuthResult | null> => {
    try {
      return await authorizer.authorize({ authorization: request.headers.authorization });
    } catch (error) {
      const oe = error instanceof OAuthError ? error : new OAuthError("invalid_token", "Bearer token is invalid", 401);
      reply.header("www-authenticate", buildUnauthorizedChallenge(opts.config, { scope: opts.config.scopeCatalog, error: oe.code, errorDescription: oe.message }));
      reply.code(oe.status).send({ jsonrpc: "2.0", error: { code: -32001, message: `${oe.code}: ${oe.message}` }, id: null });
      return null;
    }
  };

  // Forward POST/GET to the backend: curated request-header allowlist, STRIP the
  // client Authorization, INJECT the backend credential, fetch, then relay status
  // + a curated response-header allowlist, PIPING the body (never buffering — SSE
  // streams through the same code path as JSON).
  const forward = async (method: "POST" | "GET", request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const headers: Record<string, string> = {};
    for (const h of FWD_REQUEST_HEADERS) {
      const v = readHeader(request.headers as Record<string, unknown>, h);
      if (v !== undefined) headers[h] = v;
    }
    // Strip + inject in one assignment: the client's per-user bridge token (aud-bound
    // to THIS gateway) is never forwarded — it would be replayable from backend logs.
    headers["authorization"] = `Bearer ${opts.getBackendCredential()}`;
    // Outbound target is derived from the TRUSTED backendUrl ONLY — never from the
    // request's host. A client can send an absolute-form request-target
    // (`POST http://attacker/mcp HTTP/1.1`), which Node's parser accepts and Fastify
    // still routes to /mcp; `new URL(request.url, backendUrl)` would then let the
    // attacker override the host and receive the injected `Authorization: Bearer
    // <BACKEND_API_KEY>` (exfiltrating the credential the gateway exists to protect).
    // Take ONLY the inbound query string (no host/path) from the request; host+path
    // come from backendUrl. (The gateway serves only /mcp, so backendUrl's path wins.)
    const backend = new URL(opts.backendUrl);
    const inboundQuery = safeQuery(request.url, opts.backendUrl);
    const target = `${backend.origin}${backend.pathname}${inboundQuery}`;
    // Tie the backend fetch to the INBOUND request lifecycle: when the client
    // disconnects, abort the upstream fetch (+ any in-flight SSE stream). A FIXED
    // timeout is intentionally NOT used — a stateful backend's GET SSE stream is
    // long-lived (server-initiated notifications) and a fixed deadline would sever
    // it mid-stream; the client connection is the correct bound for a proxy.
    const ac = new AbortController();
    const onClose = (): void => ac.abort();
    request.raw.on("close", onClose);
    const init: RequestInit = { method, headers, signal: ac.signal };
    if (method === "POST") init.body = request.body as string; // raw JSON-RPC (URL-aware parser)
    let backendResp: Response;
    try {
      backendResp = await fetch(target, init);
    } catch {
      // Upstream unreachable / client disconnected (abort). Shaped 502 — no internal
      // detail, no framework-default body (the forward fetch is the one place a
      // network error can escape; the bearer gate's errors are shaped separately).
      request.raw.off("close", onClose);
      reply.code(502).send({ jsonrpc: "2.0", error: { code: -32001, message: "backend unreachable" }, id: null });
      return;
    }
    reply.hijack();
    const raw = reply.raw;
    raw.statusCode = backendResp.status;
    for (const h of RELAY_RESPONSE_HEADERS) {
      const v = backendResp.headers.get(h);
      if (v) raw.setHeader(h, v);
    }
    if (backendResp.body) {
      // pipeline (not a bare .pipe()) forwards ALL stream errors to the callback and
      // destroys both ends — a mid-stream backend/SSE error can't raise
      // uncaughtException and crash the gateway (reply.hijack() detaches Fastify's
      // own error handling from this relay path).
      pipeline(Readable.fromWeb(backendResp.body), raw, () => { request.raw.off("close", onClose); });
    } else {
      request.raw.off("close", onClose);
      raw.end();
    }
  };

  // All three methods sit behind the SAME Origin + bearer gate. POST and GET are
  // forwarded; DELETE returns an explicit 405 (the stub backend has no session
  // termination) rather than being silently dropped (docs/gateway-deployment.md).
  app.post("/mcp", async (request, reply) => {
    if (!(await authorizeOrChallenge(request, reply))) return;
    await forward("POST", request, reply);
  });
  app.get("/mcp", async (request, reply) => {
    if (!(await authorizeOrChallenge(request, reply))) return;
    await forward("GET", request, reply);
  });
  app.delete("/mcp", async (request, reply) => {
    if (!(await authorizeOrChallenge(request, reply))) return;
    reply.code(405).send({ jsonrpc: "2.0", error: { code: -32001, message: "DELETE /mcp not supported (backend has no session termination)" }, id: null });
  });

  return { app, store, bridge, close: async () => { await store.close(); } };
}

function readHeader(headers: Record<string, unknown>, name: string): string | undefined {
  const v = headers[name];
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return typeof v[0] === "string" ? v[0] : undefined;
  return undefined;
}

/** Extract ONLY the query string from an inbound request URL. The host is discarded
 *  (see forward()): an absolute-form request-target must not redirect the outbound
 *  fetch to an attacker host. */
function safeQuery(requestUrl: string, backendUrl: string): string {
  try { return new URL(requestUrl, backendUrl).search; } catch { return ""; }
}

// --- env helpers (trivial; inlined rather than imported to keep the example readable) ---
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
function isLoopback(url: string): boolean { try { return LOOPBACK_HOSTS.has(new URL(url).hostname); } catch { return false; } }
function listEnv(env: Record<string, string | undefined>, k: string, def: string): string[] {
  return (env[k] ?? def).split(",").map((s) => s.trim()).filter(Boolean);
}
function mustEnv(env: Record<string, string | undefined>, k: string): string { const v = env[k]; if (!v) throw new Error(`Missing env: ${k}`); return v; }

export { defaultListenHost };

/** The standalone entry's wiring, factored out so it is integration-testable without
 *  app.listen(). Selects identity exactly like examples/fastify-sqlite (Entra redirect
 *  → Cloudflare Access → zero-setup console pairing). The backend credential is passed
 *  in as a closure — it NEVER enters createBridgeConfig (which rejects unknown keys
 *  with a boot AuthConfigError, contracts §5); the two paths stay fully separate. */
export async function buildGatewayExample(
  env: Record<string, string | undefined> = process.env,
  deps: { backendUrl: string; getBackendCredential: () => string },
): Promise<{ app: FastifyInstance; store: ReturnType<typeof openSqliteStore>; config: BridgeConfig; dir: string }> {
  const dir = env.MCP_SSO_DIR ?? "./.mcp-sso";
  const sqliteFile = env.OAUTH_SQLITE_FILE ?? join(dir, "auth.db");
  const audit = new JsonlFileAudit(join(dir, "audit.jsonl"));

  if (env.ENTRA_TENANT_ID) {
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
    const { app, store } = await buildGateway({ config, backendUrl: deps.backendUrl, getBackendCredential: deps.getBackendCredential, upstream: { identity, callbackPath }, audit, sqliteFile });
    return { app, store, config, dir };
  }
  if (env.CF_ACCESS_AUDIENCE) {
    await ensureStateDir(dir);
    const config = configFromEnv(env);
    const identity = createCloudflareAccessIdentity({
      audience: mustEnv(env, "CF_ACCESS_AUDIENCE"),
      certsUrl: mustEnv(env, "CF_ACCESS_CERTS_URL"),
      issuer: mustEnv(env, "CF_ACCESS_ISSUER"),
      emailAllowlist: listEnv(env, "CF_ACCESS_EMAIL_ALLOWLIST", ""),
    });
    const { app, store } = await buildGateway({ config, backendUrl: deps.backendUrl, getBackendCredential: deps.getBackendCredential, identity, audit, sqliteFile });
    return { app, store, config, dir };
  }

  // ZERO-SETUP: quickstart secrets + console pairing.
  const secrets = await loadOrCreateQuickstartSecrets({ dir });
  const port = Number(env.PORT ?? 3000);
  const issuer = env.OAUTH_ISSUER ?? `http://localhost:${port}`;
  const resource = env.OAUTH_RESOURCE ?? `${issuer}/mcp`;
  const config = createBridgeConfig({
    issuer, resource,
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
  const { app, store } = await buildGateway({ config, backendUrl: deps.backendUrl, getBackendCredential: deps.getBackendCredential, pairing: {}, audit, sqliteFile });
  return { app, store, config, dir };
}
