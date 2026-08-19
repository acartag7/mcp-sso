// Runnable example: Fastify + sqlite. The standalone entry (index.ts) wires the
// zero-setup path — quickstart secrets (§17.8) + console pairing (§17.5) + a JSONL
// audit sink — so the server boots with NO signing/consent env config and an
// operator pastes a one-time code from the console. buildApp() also still supports
// a header-based IdentityPort (used by the e2e test). The verify gate
// (test/e2e-mcp-sdk.test.ts + test/e2e-pairing.test.ts) imports buildApp().
//
// CONSUMER IMPORT MAP — this example imports mcp-sso's source directly
// (`../../src/...`) because it lives in-repo and tests the unbuilt source. A
// package consumer imports the SAME symbols from the PUBLISHED entry points
// (full map: docs/contracts.md §15). Most symbols come from the root; the
// non-root ones, and the one subpath gotcha:
//
//   stores:           "mcp-sso/store/sqlite"  (openSqliteStore)
//                     "mcp-sso/store/memory"  (createMemoryStore)
//                     "mcp-sso/store/mysql"   (createMysqlStore)
//   fastify adapter:  "mcp-sso/fastify"       (registerOAuthRoutes)
//                     ← NOT "mcp-sso/adapters/fastify" (that's the in-repo source
//                       path; the published subpath drops the "adapters/" segment)
//   identities:       "mcp-sso/identity/cloudflare-access" (createCloudflareAccessIdentity)
//                     "mcp-sso/identity/entra"        (createEntraRedirectIdentity)
//                     "mcp-sso/identity/google"       (createGoogleRedirectIdentity)
//                     "mcp-sso/identity/generic-oidc" (createGenericOidcRedirectIdentity)
//                     "mcp-sso/identity/console-pairing" (createConsolePairingIdentity)
//
// Root-exported from `mcp-sso` (consumers import these from the root, not `../../src`):
//   Bridge, RequestAuthorizer, createBridgeConfig, buildUnauthorizedChallenge, OAuthError,
//   SystemClock, JsonlFileAudit, originOf, loadOrCreateQuickstartSecrets,
//   handlePairingAuthorize, createUpstreamRedirectFlow, isMcpPath,
//   NormRequest / NormResponse, assertCallbackPath, ensureStateDir, assertRealDir
//   (the last five are the consumer-facing example helpers — contracts §15 DX).

import Fastify, { type FastifyReply } from "fastify";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Bridge } from "../../src/adapters/bridge.ts";
import { AuthConfigError, createBridgeConfig, originOf, pathAfterOrigin, type BridgeConfig } from "../../src/config.ts";
import {
  assertRedirectAllowlistEntries, type RedirectAllowlistMode,
} from "../../src/redirect.ts";
import { validateAllowedOrigins } from "../../src/allowed-origin.ts";
import { OAuthError, oauthErrorBody } from "../../src/errors.ts";
import { buildUnauthorizedChallenge } from "../../src/challenge.ts";
import { RequestAuthorizer } from "../../src/verifier.ts";
import { SystemClock } from "../../src/ports/clock.ts";
import { noopAudit, type AuditPort } from "../../src/ports/audit.ts";
import type { RateLimitPort } from "../../src/ports/rate-limit.ts";
import { JsonlFileAudit } from "../../src/audit/jsonl-file.ts";
import { openSqliteStore } from "../../src/store/sqlite.ts";
import { loadOrCreateQuickstartSecrets } from "../../src/quickstart.ts";
import { ensureStateDir } from "../../src/state-dir.ts";
import { createCloudflareAccessIdentity } from "../../src/identity/cloudflare-access.ts";
import { createEntraRedirectIdentity } from "../../src/identity/entra-redirect.ts";
import type { GroupAuthorization } from "../../src/identity/entra-groups.ts";
import { createGoogleRedirectIdentity, type GoogleConfig } from "../../src/identity/google.ts";
import { createGenericOidcRedirectIdentity, type GenericOidcConfig } from "../../src/identity/generic-oidc.ts";
import type { IdentityPort, RedirectIdentityPort } from "../../src/ports/identity.ts";
import type { ClientRegistration, ClientStore } from "../../src/ports/client-store.ts";
import { createConsolePairingIdentity, type ConsolePairingOptions } from "../../src/identity/console-pairing.ts";
import { handlePairingAuthorize } from "../../src/adapters/pairing-flow.ts";
import { createUpstreamRedirectFlow } from "../../src/adapters/upstream-flow.ts";
import { assertCallbackPath } from "../../src/adapters/upstream-flow-internals.ts";
import {
  headersFromDistinct, isMcpPath, OAUTH_POST_BODY_MAX_BYTES, readHeader, semanticOAuthBody,
  type NormRequest, type NormResponse,
} from "../../src/adapters/http.ts";
import { queryOccurrencesFromUrl } from "../../src/adapters/authorize-params.ts";
import {
  addOAuthFormContentTypeParser, FASTIFY_PAIRING_AUTHORIZE_RATE_LIMIT, registerOAuthRoutes,
} from "../../src/adapters/fastify.ts";
import {
  registerProtectedResourceRateLimit,
  type ProtectedResourceRateLimitOptions,
} from "../../src/adapters/fastify-protected-resource-rate-limit.ts";
import {
  assertLoopbackStarterBeforeState, assertSafeDeploymentCombination,
} from "../../src/deployment-guard.ts";
import {
  createDcrRegistrationRateLimitPort, installDcrRegistrationRateLimit,
} from "./registration-rate-limit.ts";
import { trustedProxiesFromEnv, trustedProxiesFromOptions } from "./trusted-proxy.ts";

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
   *  builds `createUpstreamRedirectFlow` with the SAME store/clock/audit/rateLimit
   *  the Bridge uses (the composition root passes the shared instances — §17.11). */
  upstream?: { identity: RedirectIdentityPort; callbackPath?: string; flowTtlSeconds?: number };
  sqliteFile?: string; // defaults to :memory:
  identityHeader?: string;
  /** Audit sink for the Bridge + RequestAuthorizer + pairing. Default noopAudit. */
  audit?: AuditPort;
  /** Core OAuth limiter. Stored mode receives a finite process-local default. */
  rateLimit?: RateLimitPort;
  /** Mandatory `/mcp` Fastify budget. Defaults to 60 requests / 60 seconds / IP. */
  protectedResourceRateLimit?: ProtectedResourceRateLimitOptions;
  /** Exact proxy IP/CIDR allowlist for Fastify request.ip. Absent means trustProxy:false. */
  trustedProxies?: readonly string[];
  /** Local starter only: explicitly acknowledge the unsafe default combination. */
  acknowledgeUnsafeStatelessDefaults?: true;
}

/** Build the example Fastify app: OAuth routes + a protected /mcp (MCP server). */
export async function buildApp(opts: ExampleOptions) {
  const config = opts.config;
  const acknowledged = opts.acknowledgeUnsafeStatelessDefaults === true;
  const rateLimitCandidate = opts.rateLimit
    ?? (config.dcr.mode === "stored" ? createDcrRegistrationRateLimitPort() : undefined);
  const rateLimit = assertSafeDeploymentCombination({
    config,
    rateLimit: rateLimitCandidate,
    ...(acknowledged ? { acknowledgeUnsafeStatelessDefaults: true } : {}),
  }, { emitAcknowledgementWarning: false });
  const trustedProxies = trustedProxiesFromOptions(opts);
  const app = Fastify({ trustProxy: trustedProxies ?? false });
  const protectedRateLimit = await registerProtectedResourceRateLimit(app, opts.protectedResourceRateLimit);
  installDcrRegistrationRateLimit(app);
  const protectedRoute = { config: { rateLimit: {
    max: protectedRateLimit.max,
    timeWindow: protectedRateLimit.timeWindowMs,
    groupId: protectedRateLimit.groupId,
  } } };
  const clock = new SystemClock();
  const store = openSqliteStore(opts.sqliteFile ?? ":memory:");
  const audit: AuditPort = opts.audit ?? noopAudit;
  const bridge = new Bridge({ config, store, clock, audit, rateLimit,
    ...(acknowledged ? { acknowledgeUnsafeStatelessDefaults: true } : {}) });
  const authorizer = new RequestAuthorizer({ config, clock, audit });

  const toNorm = (req: { query: unknown; body: unknown; headers: unknown; ip?: string; raw?: { url?: string; headersDistinct?: Record<string, string[] | undefined> } }): NormRequest => {
    const headers = headersFromDistinct(req.raw?.headersDistinct, req.headers as NormRequest["headers"]);
    return {
      query: req.raw?.url !== undefined ? queryOccurrencesFromUrl(req.raw.url) : req.query as NormRequest["query"],
      // Same media gate the built-in adapters apply (contracts §9.6): a body a
      // content-type parser produced for an unsupported media type must not reach
      // OAuth field selection on this caller-owned pairing route.
      body: semanticOAuthBody(req.body, headers),
      headers,
      ip: req.ip,
    };
  };
  const sendNorm = async (reply: FastifyReply, res: NormResponse): Promise<void> => {
    for (const [key, value] of Object.entries(res.headers)) reply.header(key, value);
    if (res.redirect) { await reply.redirect(res.redirect, res.status); return; }
    reply.code(res.status).send(res.body);
  };

  if (opts.upstream) {
    // §17.11 upstream redirect-flow mode: the bridge delegates /oauth/authorize +
    // the callback to the orchestrator, built here with the SAME store/clock/audit
    // the Bridge uses (the composition root owns the shared instances). The
    // limiter travels too: one operator-supplied port must cover upstream:<ip>
    // (authorize + callback, §6.7), not just the Bridge's own keys.
    const upstream = createUpstreamRedirectFlow({
      bridge, identity: opts.upstream.identity, store, clock, audit, rateLimit,
      callbackPath: opts.upstream.callbackPath, flowTtlSeconds: opts.upstream.flowTtlSeconds,
    });
    await registerOAuthRoutes(app, { bridge, upstream });
  } else if (opts.pairing) {
    // Zero-setup mode: registerOAuthRoutes skips /oauth/authorize; we mount a
    // GET (render pairing page) + POST (verify code → consent page) via the
    // framework-free handlePairingAuthorize orchestrator.
    await registerOAuthRoutes(app, { bridge, skipAuthorize: true });
    const pairing = createConsolePairingIdentity({ ...opts.pairing, audit });
    await app.register(async (pairingApp) => {
      addOAuthFormContentTypeParser(pairingApp);
      pairingApp.get("/oauth/authorize", {
        config: { rateLimit: FASTIFY_PAIRING_AUTHORIZE_RATE_LIMIT },
      }, async (req, reply) => {
        await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "GET", toNorm(req as never)));
      });
      pairingApp.post("/oauth/authorize", {
        bodyLimit: OAUTH_POST_BODY_MAX_BYTES,
        config: { rateLimit: FASTIFY_PAIRING_AUTHORIZE_RATE_LIMIT },
      }, async (req, reply) => {
        await sendNorm(reply, await handlePairingAuthorize({ bridge, pairing }, "POST", toNorm(req as never)));
      });
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
  // match config.allowedOrigins (whose env default is originOf(issuer)) or the
  // server's own originOf(issuer) (mirrors src/authorize.ts assertOrigin). The
  // boot-validated allowlist entries are matched exactly. The OAuth routes have
  // their own origin handling, so
  // this hook is scoped to /mcp only.
  app.addHook("onRequest", async (request, reply) => {
    if (!isMcpPath(request.url)) return; // OAuth routes manage their own Origin; isMcpPath parses the pathname (absolute-form-safe)
    const origin = readHeader(
      headersFromDistinct(request.raw.headersDistinct, request.headers as NormRequest["headers"]),
      "origin",
    );
    if (origin.ambiguous || (origin.value !== undefined
      && !config.allowedOrigins.includes(origin.value)
      && origin.value !== originOf(config.issuer))) {
      reply.code(403).send({ jsonrpc: "2.0", error: { code: -32001, message: "Origin not allowed" }, id: null });
      return;
    }
  });

  // Protected /mcp: verify the bridge-issued access token, then delegate to an MCP server.
  app.post("/mcp", protectedRoute, async (request, reply) => {
    let auth;
    try {
      auth = await authorizer.authorize({
        authorization: headersFromDistinct(
          request.raw.headersDistinct,
          request.headers as NormRequest["headers"],
        ).authorization,
      });
    } catch (error) {
      const oe = error instanceof OAuthError ? error : new OAuthError("invalid_token", "Bearer token is invalid", 401);
      reply.header("www-authenticate", buildUnauthorizedChallenge(config, { scope: config.scopeCatalog, error: oe.code, errorDescription: oe.message }));
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

export const UNSAFE_NON_LOOPBACK_PAIRING_ENV = "MCP_SSO_UNSAFE_ALLOW_NON_LOOPBACK_PAIRING";
const LOOPBACK_LISTEN_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

/** Default listen host by mode. Console pairing binds LOOPBACK by default (its
 *  trust envelope is "whoever can read the process's stderr IS the operator" —
 *  a non-loopback bind exposes the pairing authorize surface + the printed-code
 *  attempt budget to the network). Cloudflare and every redirect-flow path bind
 *  0.0.0.0 (network deployment — the real IdP is the gate, unlike pairing's
 *  loopback envelope; the callback must be reachable by the IdP). */
export function defaultListenHost(env: Record<string, string | undefined> = process.env): string {
  return productionIdentityConfigured(env) ? "0.0.0.0" : "127.0.0.1";
}

/** Fail the console-pairing examples before quickstart secrets or any other
 *  state side effect when HOST escapes the supported loopback envelope. The
 *  deliberately unsafe override is exact and loud; it changes only the listen
 *  host decision, never the separate issuer/resource loopback preflight. */
export function assertConsolePairingListenHostBeforeState(
  env: Record<string, string | undefined>,
): void {
  const host = env.HOST ?? defaultListenHost(env);
  if (LOOPBACK_LISTEN_HOSTS.has(host)) return;
  if (env[UNSAFE_NON_LOOPBACK_PAIRING_ENV] !== "true") {
    throw new AuthConfigError(
      `console-pairing examples require a loopback HOST (localhost, 127.0.0.1, or ::1); ` +
        `set ${UNSAFE_NON_LOOPBACK_PAIRING_ENV}=true only for deliberate temporary non-loopback testing`,
    );
  }
  console.error(
    `[mcp-sso] DANGER: ${UNSAFE_NON_LOOPBACK_PAIRING_ENV}=true permits console pairing on non-loopback HOST=${host}. ` +
      "Anyone who can reach this port can attempt the pairing identity gate; use a real IdP for network exposure.",
  );
}

/** Parse the redirect trust mode before any quickstart persistence. This mirrors
 *  `snapshotRedirectAllowlistMode`; `createBridgeConfig` remains the authoritative
 *  second check once signing material exists. Keeping unknown values as errors
 *  avoids the `value || undefined` shape that silently restores built-in trust. */
export function redirectAllowlistModeFromEnv(
  env: Record<string, string | undefined>,
  redirectAllowlist: readonly string[],
): RedirectAllowlistMode | undefined {
  const raw = env.OAUTH_REDIRECT_ALLOWLIST_MODE;
  if (raw === undefined) return undefined;
  if (raw !== "extend" && raw !== "replace") {
    throw new AuthConfigError('redirectAllowlistMode must be "extend" or "replace"');
  }
  if (raw === "replace" && redirectAllowlist.length === 0) {
    throw new AuthConfigError(
      'redirectAllowlistMode "replace" requires at least one redirectAllowlist entry; '
      + "with none, no redirect_uri could ever be accepted",
    );
  }
  return raw;
}

/** Parse the allowlist and its composition mode as one boot policy. Callers
 *  choose the composition-root default, but cannot accidentally validate the
 *  mode against a different list from the one they later install. */
export function redirectAllowlistPolicyFromEnv(
  env: Record<string, string | undefined>,
  defaultEntries: string,
): { redirectAllowlist: string[]; redirectAllowlistMode: RedirectAllowlistMode | undefined } {
  const redirectAllowlist = assertRedirectAllowlistEntries(
    (env.OAUTH_REDIRECT_ALLOWLIST ?? defaultEntries)
      .split(",").map((entry) => entry.trim()).filter(Boolean),
  );
  return {
    redirectAllowlist,
    redirectAllowlistMode: redirectAllowlistModeFromEnv(env, redirectAllowlist),
  };
}

interface ProductionDcrBinding {
  dcr: BridgeConfig["dcr"];
  rateLimit?: RateLimitPort;
  bind(store: ReturnType<typeof openSqliteStore>): void;
}

/** Select the production Fastify/SQLite DCR mode before state is opened. Stored
 * mode publishes a stable ClientStore port immediately, then binds that port to
 * the example's already-opened SqliteStore before the app is returned. */
export function fastifySqliteDcrFromEnv(
  env: Record<string, string | undefined>,
): ProductionDcrBinding {
  const mode = env.OAUTH_DCR_MODE ?? "stateless";
  if (mode === "stateless") {
    return { dcr: { mode }, bind() {} };
  }
  if (mode !== "stored") {
    throw new AuthConfigError('OAUTH_DCR_MODE must be "stateless" or "stored"');
  }
  let sqlite: ReturnType<typeof openSqliteStore> | undefined;
  const store: ClientStore = Object.freeze({
    async save(client: ClientRegistration): Promise<void> {
      if (!sqlite) throw new Error("fastify-sqlite stored DCR store is not ready");
      await sqlite.save(client);
    },
    async find(clientId: string): Promise<ClientRegistration | null> {
      if (!sqlite) throw new Error("fastify-sqlite stored DCR store is not ready");
      return await sqlite.find(clientId);
    },
  });
  return {
    dcr: { mode, store },
    rateLimit: createDcrRegistrationRateLimitPort(),
    bind(value) { sqlite = value; },
  };
}

/** Read config from env (the production path; standalone index.ts uses quickstart
 *  secrets instead). Accepts an env object so the wiring is testable without
 *  mutating the real process.env. */
export function configFromEnv(
  env: Record<string, string | undefined> = process.env,
  dcr: BridgeConfig["dcr"] = { mode: "stateless" },
): BridgeConfig {
  const required = ["OAUTH_ISSUER", "OAUTH_RESOURCE", "OAUTH_CONSENT_SIGNING_SECRET", "OAUTH_SIGNING_PRIVATE_JWK"];
  const missing = required.filter((k) => !env[k]);
  if (missing.length) throw new Error(`Missing env: ${missing.join(", ")}`);
  const { redirectAllowlist, redirectAllowlistMode } = redirectAllowlistPolicyFromEnv(env, "");
  return createBridgeConfig({
    issuer: env.OAUTH_ISSUER!,
    resource: env.OAUTH_RESOURCE!,
    consentSigningSecret: env.OAUTH_CONSENT_SIGNING_SECRET!,
    signingPrivateJwk: JSON.parse(env.OAUTH_SIGNING_PRIVATE_JWK!) as never,
    signingKeyId: env.OAUTH_SIGNING_KEY_ID || undefined,
    redirectAllowlist,
    redirectAllowlistMode,
    scopeCatalog: (env.OAUTH_SCOPE_CATALOG ?? "mcp:read,mcp:write").split(",").map((s) => s.trim()).filter(Boolean),
    defaultScopes: (env.OAUTH_DEFAULT_SCOPES ?? "mcp:read").split(",").map((s) => s.trim()).filter(Boolean),
    allowedOrigins: allowedOriginsFromEnv(env, env.OAUTH_ISSUER!),
    cimd: { enabled: true },
    dcr,
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
export function allowedOriginsFromEnv(
  env: Record<string, string | undefined>, issuer: string,
): string[] {
  let issuerOrigin = issuer;
  try { issuerOrigin = originOf(issuer); } catch { /* createBridgeConfig reports the issuer */ }
  const raw = env.OAUTH_ALLOWED_ORIGINS;
  return validateAllowedOrigins(raw === "" ? [] : (raw ?? issuerOrigin).split(","));
}
function mustEnv(env: Record<string, string | undefined>, k: string): string {
  const v = env[k];
  if (!v) throw new Error(`Missing env: ${k}`);
  return v;
}

/** Parse the shipped examples' complete Entra group-authorization object.
 *  Semantic validation stays in createEntraRedirectIdentity, where the parsed
 *  object and the bridge scope catalog meet. */
export function entraGroupAuthorizationFromEnv(
  env: Record<string, string | undefined>,
): GroupAuthorization | undefined {
  const raw = env.ENTRA_GROUP_AUTHORIZATION_JSON;
  if (raw === undefined) return undefined;
  if (raw.trim() === "") {
    throw new AuthConfigError("ENTRA_GROUP_AUTHORIZATION_JSON must be a non-empty JSON object");
  }
  try {
    return JSON.parse(raw) as GroupAuthorization;
  } catch {
    throw new AuthConfigError("ENTRA_GROUP_AUTHORIZATION_JSON must be valid JSON");
  }
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

/** Presence selects a production OIDC branch; a present blank value must reach
 *  mustEnv/the provider guard and boot-fail, never fall through to pairing. */
export function oidcProviderConfigured(env: Record<string, string | undefined>): boolean {
  return env.GOOGLE_CLIENT_ID !== undefined || env.OIDC_ISSUER !== undefined;
}

/** All real-IdP selectors use presence, not truthiness: blank production config
 *  is a boot error and must never select the console-pairing fallback. */
export function productionIdentityConfigured(env: Record<string, string | undefined>): boolean {
  return env.ENTRA_TENANT_ID !== undefined || env.CF_ACCESS_AUDIENCE !== undefined || oidcProviderConfigured(env);
}

const IDENTITY_PROVIDER_SELECTORS = [
  "ENTRA_TENANT_ID", "CF_ACCESS_AUDIENCE", "GOOGLE_CLIENT_ID", "OIDC_ISSUER",
] as const;

/** Reject ambiguous example wiring before any stateful boot work. Presence is
 *  intentional: a blank selector remains selected and therefore counts. */
export function assertSingleIdentityProviderSelector(env: Record<string, string | undefined>): void {
  const present = IDENTITY_PROVIDER_SELECTORS.filter((key) => env[key] !== undefined);
  if (present.length > 1) {
    throw new AuthConfigError(
      `exactly one identity provider selector may be present; found: ${present.join(", ")}`,
    );
  }
}

/** Build either shipped §17.6 RedirectIdentityPort from env. Shared with the
 *  gateway example so provider config and branch precedence cannot drift. */
export async function createOidcUpstreamFromEnv(
  env: Record<string, string | undefined>,
  config: BridgeConfig,
  factories: OidcIdentityFactories = {},
): Promise<{ identity: RedirectIdentityPort; callbackPath: string } | undefined> {
  if (env.GOOGLE_CLIENT_ID !== undefined) {
    const redirectUri = mustEnv(env, "GOOGLE_REDIRECT_URI");
    const callbackPath = new URL(redirectUri).pathname;
    assertUpstreamConfigBeforeState(config, redirectUri, callbackPath);
    const identity = await (factories.google ?? createGoogleRedirectIdentity)({
      clientId: mustEnv(env, "GOOGLE_CLIENT_ID"),
      clientSecret: mustEnv(env, "GOOGLE_CLIENT_SECRET"),
      redirectUri,
      hostedDomain: env.GOOGLE_HOSTED_DOMAIN,
      subjectAllowlist: listEnv(env, "GOOGLE_SUBJECT_ALLOWLIST", ""),
      allowEmailAllowlist: booleanEnv(env, "GOOGLE_ALLOW_EMAIL_ALLOWLIST"),
    });
    return { identity, callbackPath };
  }
  if (env.OIDC_ISSUER !== undefined) {
    const redirectUri = mustEnv(env, "OIDC_REDIRECT_URI");
    const callbackPath = new URL(redirectUri).pathname;
    assertUpstreamConfigBeforeState(config, redirectUri, callbackPath);
    const identity = await (factories.genericOidc ?? createGenericOidcRedirectIdentity)({
      issuer: mustEnv(env, "OIDC_ISSUER"),
      clientId: mustEnv(env, "OIDC_CLIENT_ID"),
      clientSecret: env.OIDC_CLIENT_SECRET,
      redirectUri,
      endpoints: "discover",
      scopes: env.OIDC_SCOPES,
      subjectAllowlist: listEnv(env, "OIDC_SUBJECT_ALLOWLIST", ""),
    });
    return { identity, callbackPath };
  }
  return undefined;
}

/** Run the orchestrator's pure redirect boot assertions before provider discovery,
 *  state-dir creation, or sqlite open. The real orchestrator repeats them when the
 *  routes mount; this early mirror keeps example boot rejection side-effect free. */
export function assertUpstreamConfigBeforeState(
  config: BridgeConfig,
  redirectUri: string,
  callbackPath = "/oauth/callback",
): void {
  const issuerOrigin = originOf(config.issuer);
  assertCallbackPath(callbackPath, issuerOrigin, pathAfterOrigin(config.resource));
  if (redirectUri.includes("?") || redirectUri.includes("#")) {
    throw new AuthConfigError("identity.redirectUri must not contain a query or fragment");
  }
  if (redirectUri !== issuerOrigin + callbackPath) {
    throw new AuthConfigError(`identity.redirectUri must equal issuerOrigin + callbackPath ('${issuerOrigin + callbackPath}')`);
  }
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
  assertSingleIdentityProviderSelector(env);
  const productionDcr = productionIdentityConfigured(env)
    ? fastifySqliteDcrFromEnv(env)
    : undefined;
  const trustedProxies = trustedProxiesFromEnv(env);
  const dir = env.MCP_SSO_DIR ?? "./.mcp-sso";
  const sqliteFile = env.OAUTH_SQLITE_FILE ?? join(dir, "auth.db");
  const audit = new JsonlFileAudit(join(dir, "audit.jsonl"));

  if (env.ENTRA_TENANT_ID !== undefined) {
    // §17.11 PRODUCTION: Entra redirect-flow. The upstream IdP (Entra app
    // assignment / Conditional Access) is the auth gate, so this is network-bound
    // (0.0.0.0) like Cloudflare — NOT loopback. ENTRA_REDIRECT_URI's pathname is
    // the callbackPath; createUpstreamRedirectFlow boot-asserts it equals
    // originOf(OAUTH_ISSUER) + callbackPath (a mismatch is silent breakage at the
    // IdP, so it fails closed at boot). The bridge's own signing material still
    // comes from OAUTH_* env (configFromEnv).
    const config = configFromEnv(env, productionDcr!.dcr);
    const redirectUri = mustEnv(env, "ENTRA_REDIRECT_URI");
    const callbackPath = new URL(redirectUri).pathname;
    const identity = createEntraRedirectIdentity({
      tenantId: mustEnv(env, "ENTRA_TENANT_ID"),
      clientId: mustEnv(env, "ENTRA_CLIENT_ID"),
      clientSecret: env.ENTRA_CLIENT_SECRET,
      redirectUri,
      allowedTenantIds: listEnv(env, "ENTRA_ALLOWED_TENANT_IDS", ""),
      subjectAllowlist: listEnv(env, "ENTRA_SUBJECT_ALLOWLIST", ""),
      groupAuthorization: entraGroupAuthorizationFromEnv(env),
    }, { scopeCatalog: config.scopeCatalog });
    assertUpstreamConfigBeforeState(config, identity.redirectUri, callbackPath);
    assertSafeDeploymentCombination({
      config, rateLimit: productionDcr!.rateLimit,
    }, { emitAcknowledgementWarning: false });
    await ensureStateDir(dir);
    const { app, store } = await buildApp({
      config, rateLimit: productionDcr!.rateLimit,
      upstream: { identity, callbackPath }, audit, sqliteFile, trustedProxies,
    });
    productionDcr!.bind(store);
    return { app, store, config, dir };
  }
  if (env.CF_ACCESS_AUDIENCE !== undefined) {
    // PRODUCTION: Cloudflare Access + env signing material. This branch does NOT
    // run the quickstart helper, so create the state dir explicitly (sqlite open +
    // audit append otherwise fail on the missing parent).
    const config = configFromEnv(env, productionDcr!.dcr);
    const identity = createCloudflareAccessIdentity({
      audience: mustEnv(env, "CF_ACCESS_AUDIENCE"),
      certsUrl: mustEnv(env, "CF_ACCESS_CERTS_URL"),
      issuer: mustEnv(env, "CF_ACCESS_ISSUER"),
      emailAllowlist: listEnv(env, "CF_ACCESS_EMAIL_ALLOWLIST", ""),
    });
    assertSafeDeploymentCombination({
      config, rateLimit: productionDcr!.rateLimit,
    }, { emitAcknowledgementWarning: false });
    await ensureStateDir(dir);
    const { app, store } = await buildApp({
      config, rateLimit: productionDcr!.rateLimit,
      identity, audit, sqliteFile, trustedProxies,
    });
    productionDcr!.bind(store);
    return { app, store, config, dir };
  }
  if (oidcProviderConfigured(env)) {
    // §17.6 + §17.11 PRODUCTION: Google or generic OIDC redirect flow. The
    // configured redirect URI's pathname is the mounted callback route; the
    // orchestrator boot-asserts the full URI equals issuerOrigin + callbackPath.
    const config = configFromEnv(env, productionDcr!.dcr);
    assertSafeDeploymentCombination({
      config, rateLimit: productionDcr!.rateLimit,
    }, { emitAcknowledgementWarning: false });
    const upstream = await createOidcUpstreamFromEnv(env, config, identityFactories);
    if (!upstream) throw new Error("OIDC identity branch selected without provider config");
    await ensureStateDir(dir);
    const { app, store } = await buildApp({
      config, rateLimit: productionDcr!.rateLimit,
      upstream, audit, sqliteFile, trustedProxies,
    });
    productionDcr!.bind(store);
    return { app, store, config, dir };
  }

  // ZERO-SETUP: quickstart secrets (creates the dir, secrets, .gitignore) + console
  // pairing. buildApp takes pairing OPTIONS and wires `audit` into the identity.
  const port = Number(env.PORT ?? 3000);
  const issuer = env.OAUTH_ISSUER ?? `http://localhost:${port}`;
  const resource = env.OAUTH_RESOURCE ?? `http://localhost:${port}/mcp`;
  assertLoopbackStarterBeforeState(issuer, resource);
  assertConsolePairingListenHostBeforeState(env);
  const allowedOrigins = allowedOriginsFromEnv(env, issuer);
  const { redirectAllowlist, redirectAllowlistMode } = redirectAllowlistPolicyFromEnv(
    env, "http://localhost,http://127.0.0.1",
  );
  const secrets = await loadOrCreateQuickstartSecrets({ dir });
  const config = createBridgeConfig({
    issuer,
    resource,
    consentSigningSecret: secrets.consentSigningSecret,
    signingPrivateJwk: secrets.signingPrivateJwk,
    // Explicit local-composition default; an explicitly empty env value removes it.
    redirectAllowlist,
    // Same env seam as the production branch above — the quickstart path is the
    // sibling that used to get missed when a config option was threaded once.
    redirectAllowlistMode,
    scopeCatalog: listEnv(env, "OAUTH_SCOPE_CATALOG", "mcp:read,mcp:write"),
    defaultScopes: listEnv(env, "OAUTH_DEFAULT_SCOPES", "mcp:read"),
    allowedOrigins,
    cimd: { enabled: true },
    dcr: { mode: "stateless" },
    dev: isLoopback(issuer) ? { allowInsecureLocalhost: true } : undefined,
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const { app, store } = await buildApp({ config, pairing: {}, audit, sqliteFile, trustedProxies });
  return { app, store, config, dir };
}
