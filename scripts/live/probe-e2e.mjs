// Headless end-to-end proof of the shipped example composition for the legs the
// provider probes cannot reach: the §17.2 machine-client grant, both shipped
// audit sinks fed by one Bridge, the §17.10 Redis limiter over a real
// connection, refresh rotation and RFC 7009 revocation, and the OFFICIAL MCP
// SDK client calling the protected /mcp over a real loopback socket.
//
// Identity is a probe-local port on the probe's OWN in-process app, so this
// file makes no identity-provider claim — the three provider probes carry
// those. Machine-client rows live in a process-local store because no shipped
// store implements the atomic §17.2 extension. Stored-DCR runs bind that port
// to SQLite; stateless runs exercise the global opaque-client policy without a
// registration store. Codes, refresh families and consent state always go
// through the shipped SQLite store. No secret, token, or provider identifier
// is written to output.
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Redis } from "ioredis";
import { buildApp } from "../../examples/fastify-sqlite/app.ts";
import { combineAudit } from "../../src/audit/combine.ts";
import { JsonlFileAudit } from "../../src/audit/jsonl-file.ts";
import { WebhookAudit } from "../../src/audit/webhook.ts";
import { createBridgeConfig } from "../../src/config.ts";
import { pkceChallenge } from "../../src/crypto.ts";
import { disableMachineClient, provisionMachineClient } from "../../src/machine-client.ts";
import { SystemClock } from "../../src/ports/clock.ts";
import { createRedisRateLimit } from "../../src/rate-limit/redis.ts";
import {
  containsCredential, createProbeClientStore, extractConsentToken, form, parseJsonl, sdkPing,
} from "./probe-e2e-support.mjs";
import { runIdentityCompletionLeg } from "./probe-e2e-identity-support.mjs";
import { assertProbeClientRedirect } from "./probe-redirect-support.mjs";

for (const name of ["OAUTH_ISSUER", "OAUTH_CONSENT_SIGNING_SECRET", "OAUTH_DCR_MODE", "REDIS_URL"]) {
  if (typeof process.env[name] !== "string" || process.env[name].length === 0) {
    throw new Error(`${name} must be provided for the end-to-end probe`);
  }
}
const dcrMode = process.env.OAUTH_DCR_MODE;
if (dcrMode !== "stored" && dcrMode !== "stateless") {
  throw new Error('OAUTH_DCR_MODE must be "stored" or "stateless" for the end-to-end probe');
}
let callback;
try {
  callback = assertProbeClientRedirect(process.env.PROBE_APP_CALLBACK);
} catch {
  throw new Error("PROBE_APP_CALLBACK must be a web callback URL the effective allowlist admits");
}

const out = [];
const ok = (label, condition, detail = "") => {
  out.push(`${condition ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return condition;
};
const TOKEN_LIMIT = 20;
const ISSUER = process.env.OAUTH_ISSUER;
const RESOURCE = `${ISSUER}/mcp`;
const SUBJECT = "live-probe-user";
const IDENTITY_HEADER = "x-mcp-sso-probe-identity";
// Every credential this run creates or submits, recorded where it is produced
// so the leak scan cannot fall behind the flow.
const secrets = [];
const secret = (label, value) => { secrets.push([label, value]); return value; };
const identityToken = secret("probe identity token", randomBytes(24).toString("base64url"));
const collectorToken = secret("webhook collector token", randomBytes(24).toString("base64url"));
const sessionValue = secret("identity completion session cookie", randomBytes(24).toString("base64url"));
const completionThrowText = secret("identity completion thrown text", randomBytes(24).toString("base64url"));
// Every audit event this run expects, recorded where it is caused so the
// receipt cannot fall behind the flow either. Compared as an exact sequence.
const expected = [];
const expect = (event, status, times = 1) => {
  for (let i = 0; i < times; i += 1) expected.push(`${event}/${status}`);
};
const SDK_AUTH_REQUESTS = 3; // initialize + notification + tool call, per session
const identity = {
  async verify(input) {
    return input === identityToken
      ? { ok: true, identity: { subject: SUBJECT } }
      : { ok: false, reason: "probe_identity_rejected" };
  },
};
let tokenCalls = 0;
const tokenPost = (app, params) => {
  tokenCalls++;
  return app.inject({
    method: "POST", url: "/oauth/token",
    headers: { "content-type": "application/x-www-form-urlencoded" }, payload: form(params),
  });
};
const settle = async (ready, deadlineMs) => {
  const until = Date.now() + deadlineMs;
  while (!(await ready()) && Date.now() < until) await new Promise((resolve) => setTimeout(resolve, 25));
  return await ready();
};

let failures = 0;
let app;
let store;
let stateDir;
let redis;

try {
  stateDir = await mkdtemp(join(tmpdir(), "mcp-sso-live-e2e-"));
  const jsonlPath = join(stateDir, "audit.jsonl");
  const posted = [];
  const audit = combineAudit(
    new JsonlFileAudit(jsonlPath),
    new WebhookAudit("https://collector.example/ingest", {
      headers: { authorization: `Bearer ${collectorToken}` },
      fetchImpl: async (_url, init) => { posted.push(JSON.parse(init.body)); return new Response(null, { status: 204 }); },
    }),
  );
  redis = new Redis(process.env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
  // ioredis would otherwise print its own connection error, which names the
  // host and port, to stderr; reachability is reported as a row below instead.
  redis.on("error", () => {});
  let redisReachable = false;
  try {
    await redis.connect();
    redisReachable = true;
  } catch {
    // reported as its own row below; the probe cannot continue without it
  }
  if (!ok("Redis limiter backend reachable", redisReachable)) throw new Error("Redis unreachable");
  const rateLimit = createRedisRateLimit(redis, {
    windowSeconds: 60, limit: TOKEN_LIMIT, keyPrefix: `mcp-sso:live:${randomBytes(8).toString("hex")}:`,
  });
  const clientStore = dcrMode === "stored" ? createProbeClientStore() : undefined;
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const signingJwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "live" };
  secret("signing private key", signingJwk.d);
  secret("consent signing credential", process.env.OAUTH_CONSENT_SIGNING_SECRET);
  const config = createBridgeConfig({
    issuer: ISSUER, resource: RESOURCE,
    consentSigningSecret: process.env.OAUTH_CONSENT_SIGNING_SECRET,
    signingPrivateJwk: signingJwk, signingKeyId: "live",
    redirectAllowlist: [callback], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: [ISSUER],
    dcr: dcrMode === "stored" ? { mode: "stored", store: clientStore.store } : { mode: "stateless" },
    ...(dcrMode === "stored" ? { clientCredentials: { enabled: true } } : {}),
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3_600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const built = await buildApp({
    config, identity, identityHeader: IDENTITY_HEADER, audit, rateLimit, sqliteFile: join(stateDir, "auth.db"),
  });
  app = built.app;
  store = built.store;
  clientStore?.bind(store);
  const clock = new SystemClock();
  if (!ok("probe composition uses the selected DCR mode", config.dcr.mode === dcrMode, dcrMode)) failures++;

  // Claims-only website login uses the same shipped bridge dependencies, then
  // crosses every framework adapter. The helper returns booleans only; no
  // cookie, credential, provider name, or thrown text reaches probe output.
  const identityCompletion = await runIdentityCompletionLeg({
    bridge: built.bridge, store, clock, audit, rateLimit, sessionValue, throwText: completionThrowText,
  });
  for (let i = 0; i < 3; i++) {
    expect("identity.verify", "success");
    expect("oauth.upstream.callback", "success");
    expect("identity.verify", "success");
    expect("oauth.upstream.callback", "failure");
    expect("oauth.upstream.callback", "failure");
  }
  if (!ok("claims-only completion delivers verified claims and the host response through all adapters",
    identityCompletion.verifiedClaimsAndResponse)) failures++;
  if (!ok("claims-only completion preserves both Set-Cookie fields through all adapters",
    identityCompletion.twoCookies)) failures++;
  if (!ok("claims-only completion produces no consent HTML or MCP token",
    identityCompletion.noOAuthArtifacts)) failures++;
  if (!ok("claims-only completion failure is consumed, cleared, fixed, audited, and redacted",
    identityCompletion.failureContract)) failures++;
  if (!ok("claims-only completion charges only website-login keys",
    identityCompletion.websiteLoginKeys)) failures++;

  // 1. Authorization-code leg through the shipped routes, probe-local identity.
  const registration = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
    payload: JSON.stringify({ redirect_uris: [callback], application_type: "web" }),
  });
  const clientId = registration.statusCode === 201 ? registration.json().client_id : undefined;
  expect("oauth.register", "success");
  const registrationLabel = dcrMode === "stored"
    ? "DCR registers a client into the shipped SQLite store"
    : "DCR returns an opaque client without a registration store";
  if (!ok(registrationLabel,
    registration.statusCode === 201 && typeof clientId === "string", `HTTP ${registration.statusCode}`)) failures++;

  // The #278 mode differential, on the exact running composition: stored mode
  // rejects an unknown opaque id, while stateless mode applies the global
  // redirect allowlist and admits it. This proves the selected mode reached
  // authorization rather than trusting the preflight knob alone.
  const differential = await app.inject({
    method: "GET",
    url: `/oauth/authorize?${new URLSearchParams({
      response_type: "code", client_id: "mcpdc_live_probe_unknown", redirect_uri: callback,
      code_challenge: pkceChallenge("live-e2e-differential-verifier-0123456789abcdef"),
      code_challenge_method: "S256", scope: "mcp:read", state: "live-e2e-differential",
    })}`,
    headers: { [IDENTITY_HEADER]: identityToken },
  });
  expect("identity.verify", "success");
  expect("oauth.authorize.prepare", dcrMode === "stored" ? "failure" : "success");
  const differentialConsent = differential.statusCode === 200
    ? secret("mode differential consent token", extractConsentToken(differential.body))
    : undefined;
  if (!ok("selected DCR mode applies its documented unknown-client policy",
    dcrMode === "stored"
      ? differential.statusCode === 401 && differential.json().error === "invalid_client"
      : typeof differentialConsent === "string" && differentialConsent.length > 0,
    `${dcrMode}, HTTP ${differential.statusCode}`)) failures++;

  /** One authorization-code grant end to end. Each call mints its OWN refresh
   *  family, which is what lets replay revocation and RFC 7009 revocation be
   *  proved separately — a family the replay already revoked cannot show
   *  whether revoke works, and vice versa. */
  const authorizationCodeGrant = async (label, state) => {
    const grantVerifier = secret(`${label} PKCE verifier`, `live-e2e-probe-verifier-${state}-0123456789abcdef`);
    const authorize = await app.inject({
      method: "GET",
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: "code", client_id: clientId ?? "fixture-registration-failed", redirect_uri: callback,
        code_challenge: pkceChallenge(grantVerifier), code_challenge_method: "S256", scope: "mcp:read", state,
      })}`,
      headers: { [IDENTITY_HEADER]: identityToken },
    });
    expect("identity.verify", "success");
    expect("oauth.authorize.prepare", "success");
    const consent = secret(`${label} consent token`, authorize.statusCode === 200 ? extractConsentToken(authorize.body) : undefined);
    if (!ok(`${label}: verified identity reaches the consent page`, consent !== undefined,
      `HTTP ${authorize.statusCode}`)) failures++;
    const approve = await app.inject({
      method: "POST", url: "/oauth/authorize/approve",
      headers: { "content-type": "application/x-www-form-urlencoded", origin: ISSUER },
      payload: form({ consent_token: consent ?? "fixture-no-consent", approved: "true" }),
    });
    expect("oauth.authorize.approve", "success");
    const granted = secret(`${label} authorization code`, approve.statusCode === 302 ? new URL(approve.headers.location).searchParams.get("code") : null);
    if (!ok(`${label}: consent approval redirects with an authorization code`,
      typeof granted === "string" && granted.length > 0, `HTTP ${approve.statusCode}`)) failures++;
    const minted = await tokenPost(app, {
      grant_type: "authorization_code", code: granted ?? "fixture-no-code", redirect_uri: callback,
      client_id: clientId ?? "fixture-registration-failed", code_verifier: grantVerifier,
    });
    expect("oauth.token.authorization_code", "success");
    const tokens = minted.statusCode === 200 ? minted.json() : {};
    secret(`${label} access token`, tokens.access_token);
    secret(`${label} refresh token`, tokens.refresh_token);
    if (!ok(`${label}: authorization_code mints access and refresh tokens`,
      typeof tokens.access_token === "string" && typeof tokens.refresh_token === "string",
      `HTTP ${minted.statusCode}`)) failures++;
    return { ...tokens, consent, code: granted, verifier: grantVerifier };
  };
  const userTokens = await authorizationCodeGrant("replay family", "live-e2e-replay");
  const consentToken = userTokens.consent;
  const code = userTokens.code;
  const verifier = userTokens.verifier;

  // 2. The OFFICIAL MCP SDK client over a real loopback socket.
  const base = await app.listen({ host: "127.0.0.1", port: 0 });
  const userPing = await sdkPing(base, userTokens.access_token ?? "fixture-no-token");
  expect("auth.request", "success", SDK_AUTH_REQUESTS);
  if (!ok("official SDK client completes a tool call with the user token", userPing === `pong: ${SUBJECT}`,
    userPing === undefined ? "no text content" : "tool call answered")) failures++;
  const unauthenticated = await fetch(new URL("/mcp", base), {
    method: "POST", headers: { "content-type": "application/json" }, body: "{}",
  });
  expect("auth.request", "failure");
  if (!ok("protected /mcp refuses an unauthenticated call with the RFC 9728 challenge",
    unauthenticated.status === 401
      && /^Bearer resource_metadata="/.test(unauthenticated.headers.get("www-authenticate") ?? ""),
    `HTTP ${unauthenticated.status}`)) failures++;

  // 3. Machine clients contractually require stored DCR. Stored runs prove the
  // whole machine leg; stateless runs retain the user DCR flow and its mode
  // differential without pretending the incompatible feature was exercised.
  let limiterAuditEvent = "oauth.token.authorization_code";
  let limiterRequest = () => tokenPost(app, {
    grant_type: "authorization_code", code: "live-probe-invalid-code", redirect_uri: callback,
    client_id: clientId ?? "fixture-registration-failed",
    code_verifier: "live-e2e-limiter-verifier-0123456789abcdef",
  });
  if (dcrMode === "stored" && clientStore !== undefined) {
    const machineDeps = { store: clientStore.store, clock, audit, catalog: config.scopeCatalog, resource: RESOURCE };
    const provisioned = await provisionMachineClient(machineDeps, { allowedScopes: ["mcp:read"], name: "live-probe" });
    expect("oauth.client.provision", "success");
    secret("machine client secret", provisioned.clientSecret);
    if (!ok("machine credential provisioned into the process-local store",
      /^mcs_[A-Za-z0-9_-]{43}$/.test(provisioned.clientSecret))) failures++;
    const machineForm = {
      grant_type: "client_credentials", client_id: provisioned.clientId,
      client_secret: provisioned.clientSecret, resource: RESOURCE, scope: "mcp:read",
    };
    const machineToken = await tokenPost(app, machineForm);
    expect("oauth.token.client_credentials", "success");
    const machineAccess = secret("machine access token",
      machineToken.statusCode === 200 ? machineToken.json().access_token : undefined);
    if (!ok("client_credentials mints an access token", typeof machineAccess === "string",
      `HTTP ${machineToken.statusCode}`)) failures++;
    const machinePing = await sdkPing(base, machineAccess ?? "fixture-no-token");
    expect("auth.request", "success", SDK_AUTH_REQUESTS);
    if (!ok("official SDK client completes a tool call with the machine token",
      machinePing === `pong: ${provisioned.clientId}`,
      machinePing === undefined ? "no text content" : "tool call answered")) failures++;
    const rejectedSecret = secret("rejected machine client secret", `mcs_${"A".repeat(43)}`);
    const wrongSecret = await tokenPost(app, { ...machineForm, client_secret: rejectedSecret });
    expect("oauth.token.client_credentials", "failure");
    if (!ok("a wrong client_secret is refused as invalid_client",
      wrongSecret.statusCode === 401 && wrongSecret.json().error === "invalid_client",
      `HTTP ${wrongSecret.statusCode}`)) failures++;
    const disabled = await disableMachineClient(machineDeps, provisioned.clientId);
    expect("oauth.client.disable", "success");
    const afterDisable = await tokenPost(app, machineForm);
    expect("oauth.token.client_credentials", "failure");
    if (!ok("a disabled credential is refused as invalid_client",
      disabled.clientId === provisioned.clientId
        && afterDisable.statusCode === 401 && afterDisable.json().error === "invalid_client",
      `HTTP ${afterDisable.statusCode}`)) failures++;
    limiterAuditEvent = "oauth.token.client_credentials";
    limiterRequest = () => tokenPost(app, machineForm);
  }

  // 4a. Rotation, then REPLAY of the consumed predecessor: the replay is
  // refused AND the live successor dies with it, which is family revocation
  // rather than a single-token rejection.
  const refresh = (token) => tokenPost(app, {
    grant_type: "refresh_token", refresh_token: token ?? "fixture-no-refresh", client_id: clientId,
  });
  const refreshed = await refresh(userTokens.refresh_token);
  expect("oauth.token.refresh", "success");
  const rotatedTokens = refreshed.statusCode === 200 ? refreshed.json() : {};
  const rotated = secret("replay family rotated refresh token", rotatedTokens.refresh_token);
  secret("replay family rotated access token", rotatedTokens.access_token);
  if (!ok("refresh rotates the refresh token",
    typeof rotated === "string" && rotated !== userTokens.refresh_token, `HTTP ${refreshed.statusCode}`)) failures++;
  const replayed = await refresh(userTokens.refresh_token);
  const afterReplay = await refresh(rotated);
  expect("oauth.token.refresh", "failure", 2);
  if (!ok("replaying a consumed refresh token is refused and revokes its whole family",
    replayed.statusCode === 400 && replayed.json().error === "invalid_grant"
      && afterReplay.statusCode === 400 && afterReplay.json().error === "invalid_grant",
    `replay HTTP ${replayed.statusCode}, live successor HTTP ${afterReplay.statusCode}`)) failures++;

  // 4b. RFC 7009 revocation, on its OWN family — the family above is already
  // revoked, so it could not tell a working revoke endpoint from a broken one.
  const revocationTokens = await authorizationCodeGrant("revocation family", "live-e2e-revoke");
  const revocationRefreshed = await refresh(revocationTokens.refresh_token);
  expect("oauth.token.refresh", "success");
  const revocationRotatedTokens = revocationRefreshed.statusCode === 200 ? revocationRefreshed.json() : {};
  const revocationRotated = secret("revocation family rotated refresh token", revocationRotatedTokens.refresh_token);
  secret("revocation family rotated access token", revocationRotatedTokens.access_token);
  if (!ok("the revocation family rotates before it is revoked",
    typeof revocationRotated === "string" && revocationRotated !== revocationTokens.refresh_token,
    `HTTP ${revocationRefreshed.statusCode}`)) failures++;
  const revoke = await app.inject({
    method: "POST", url: "/oauth/revoke",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: form({ token: revocationRotated ?? "fixture-no-refresh" }),
  });
  expect("oauth.revoke", "success");
  const afterRevoke = await refresh(revocationRotated);
  expect("oauth.token.refresh", "failure");
  if (!ok("/oauth/revoke answers 200 and the revoked refresh token is refused as invalid_grant",
    revoke.statusCode === 200 && afterRevoke.statusCode === 400 && afterRevoke.json().error === "invalid_grant",
    `HTTP ${revoke.statusCode} then ${afterRevoke.statusCode}`)) failures++;

  // 5. Redis limiter admits exactly the remaining window budget, then refuses.
  // Last: it exhausts the shared bucket for this address.
  const remainingBudget = Math.max(0, TOKEN_LIMIT - tokenCalls);
  const burst = remainingBudget + 2;
  let admitted = 0;
  let limited = 0;
  for (let i = 0; i < burst; i++) {
    const response = await limiterRequest();
    if (response.statusCode === 429) limited++;
    else admitted++;
  }
  expect(limiterAuditEvent, "failure", admitted);
  if (!ok("Redis limiter admits exactly the remaining window budget and refuses past it",
    admitted === remainingBudget && limited === 2,
    `${admitted}/${remainingBudget} admitted, ${limited} refused with 429`)) failures++;

  // 6. Both shipped sinks recorded the same ordered flow, without any credential.
  let fileEvents = [];
  await settle(async () => {
    fileEvents = parseJsonl(await readFile(jsonlPath, "utf8").catch(() => ""));
    return posted.length > 0 && fileEvents.length >= posted.length;
  }, 2_000);
  if (!ok("JSONL and webhook sinks received the same ordered events",
    fileEvents.length > 0 && JSON.stringify(fileEvents) === JSON.stringify(posted),
    `${fileEvents.length} file rows, ${posted.length} webhook posts`)) failures++;
  // The receipt is the sequence the run recorded as it happened, compared
  // exactly — not a hand-written subsequence that can fall behind the flow in
  // either kind or count.
  const observedKinds = fileEvents.map((event) => `${event.event}/${event.status}`);
  if (!ok("the audit sinks contain exactly the events this run caused, in order",
    JSON.stringify(observedKinds) === JSON.stringify(expected),
    `${observedKinds.length} emitted vs ${expected.length} expected`)) failures++;
  const evidence = `${JSON.stringify(fileEvents)}\n${JSON.stringify(posted)}`;
  // Every value the run minted, not a sample of them: a sink that publishes a
  // token missing from this list would leave all the rows green.
  // The registry, not a second hand-written list: every credential the run
  // created or submitted was recorded where it was produced.
  const credentials = secrets;
  for (const [name, value] of credentials) {
    if (!ok(`audit sinks never published the ${name}`, !containsCredential(evidence, [value]))) failures++;
  }
} catch {
  failures++;
  out.push("FAIL  probe aborted before completion");
} finally {
  if (app !== undefined) {
    try {
      await app.close();
    } catch {
      failures++;
      out.push("FAIL  probe cleanup failed");
    }
  }
  if (store !== undefined) {
    try {
      await store.close();
    } catch {
      failures++;
      out.push("FAIL  probe store cleanup failed");
    }
  }
  if (redis !== undefined) {
    try {
      redis.disconnect();
    } catch {
      failures++;
      out.push("FAIL  probe limiter cleanup failed");
    }
  }
  if (stateDir !== undefined) {
    try {
      await rm(stateDir, { recursive: true, force: true });
    } catch {
      failures++;
      out.push("FAIL  probe state cleanup failed");
    }
  }
  console.log(out.join("\n"));
  console.log(`\n${out.filter((line) => line.startsWith("PASS")).length}/${out.length} checks passed`);
  process.exitCode = failures > 0 ? 1 : 0;
}
