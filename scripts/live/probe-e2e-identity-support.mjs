// Live claims-only completion leg for probe-e2e.mjs. This module has no CLI;
// the release probe calls it with the same Bridge, StorePort, ClockPort,
// AuditPort, and Redis-backed RateLimitPort as the shipped example composition.
import Fastify from "fastify";
import express from "express";
import { createServer } from "node:http";
import { createOAuthRouter } from "../../src/adapters/express.ts";
import { registerOAuthRoutes } from "../../src/adapters/fastify.ts";
import { createOAuthApp } from "../../src/adapters/hono.ts";
import { createUpstreamRedirectFlow } from "../../src/adapters/upstream-flow.ts";

const SUBJECT = "live-identity-completion-user";
const HOST_BODY = "identity completion accepted";

async function fastifyDriver(bridge, flow) {
  const app = Fastify();
  await registerOAuthRoutes(app, { bridge, skipAuthorize: true, identityFlow: flow });
  const base = await app.listen({ host: "127.0.0.1", port: 0 });
  return {
    async get(path, cookie) {
      const response = await fetch(base + path, { redirect: "manual", ...(cookie ? { headers: { cookie } } : {}) });
      return {
        status: response.status,
        location: response.headers.get("location") ?? undefined,
        cookies: response.headers.getSetCookie(),
        body: await response.text(),
      };
    },
    async close() { await app.close(); },
  };
}

async function expressDriver(bridge, flow) {
  const app = express();
  app.use(createOAuthRouter({ bridge, skipAuthorize: true, identityFlow: flow }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("identity completion listener did not expose a port");
  const base = `http://127.0.0.1:${address.port}`;
  return {
    async get(path, cookie) {
      const response = await fetch(base + path, { redirect: "manual", ...(cookie ? { headers: { cookie } } : {}) });
      return {
        status: response.status,
        location: response.headers.get("location") ?? undefined,
        cookies: response.headers.getSetCookie(),
        body: await response.text(),
      };
    },
    async close() { await new Promise((resolve) => server.close(() => resolve())); },
  };
}

async function honoDriver(bridge, flow) {
  const app = createOAuthApp({ bridge, skipAuthorize: true, identityFlow: flow, clientIp: () => "127.0.0.1" });
  const server = createServer(async (request, response) => {
    try {
      const headers = new Headers();
      for (let i = 0; i < request.rawHeaders.length; i += 2) headers.append(request.rawHeaders[i], request.rawHeaders[i + 1]);
      const mapped = await app.fetch(new Request(`http://${request.headers.host}${request.url}`, { method: request.method, headers }));
      response.statusCode = mapped.status;
      mapped.headers.forEach((value, key) => { if (key !== "set-cookie") response.setHeader(key, value); });
      const cookies = mapped.headers.getSetCookie();
      if (cookies.length > 0) response.setHeader("set-cookie", cookies);
      response.end(Buffer.from(await mapped.arrayBuffer()));
    } catch {
      response.statusCode = 500;
      response.end();
    }
  });
  server.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("identity completion listener did not expose a port");
  const base = `http://127.0.0.1:${address.port}`;
  return {
    async get(path, cookie) {
      const response = await fetch(base + path, { redirect: "manual", ...(cookie ? { headers: { cookie } } : {}) });
      return {
        status: response.status,
        location: response.headers.get("location") ?? undefined,
        cookies: response.headers.getSetCookie(),
        body: await response.text(),
      };
    },
    async close() { await new Promise((resolve) => server.close(() => resolve())); },
  };
}

const ADAPTERS = [fastifyDriver, expressDriver, honoDriver];

function callbackCookie(response) {
  const cookie = response.cookies[0]?.split(";", 1)[0];
  if (typeof cookie !== "string" || cookie.length === 0) throw new Error("identity completion did not set its flow cookie");
  return cookie;
}

function callbackPath(start, code) {
  if (typeof start.location !== "string") throw new Error("identity completion did not redirect");
  const state = new URL(start.location).searchParams.get("state");
  if (state === null) throw new Error("identity completion redirect omitted state");
  return `/login/callback?${new URLSearchParams({ state, code })}`;
}

function cookieNames(response) {
  return response.cookies.map((cookie) => cookie.split("=", 1)[0]);
}

function fixedFailure(response) {
  let body;
  try { body = JSON.parse(response.body); } catch { return false; }
  return response.status === 500
    && response.location === undefined
    && body?.error === "internal_error"
    && body?.error_description === "OAuth request failed";
}

export async function runIdentityCompletionLeg({ bridge, store, clock, audit, rateLimit, sessionValue, throwText }) {
  const events = [];
  const keys = [];
  const capturedAudit = {
    async writeAuthEvent(event) {
      events.push(structuredClone(event));
      await audit.writeAuthEvent(event);
    },
  };
  const capturedRateLimit = {
    async check(key) {
      keys.push(key);
      return await rateLimit.check(key);
    },
  };
  const checks = {
    verifiedClaimsAndResponse: true,
    twoCookies: true,
    noOAuthArtifacts: true,
    failureContract: true,
    websiteLoginKeys: true,
  };

  for (const makeDriver of ADAPTERS) {
    let successExchanges = 0;
    let observed;
    const successIdentity = {
      redirectUri: `${bridge.config.issuer}/login/callback`,
      buildAuthorizationUrl({ state }) { return `${bridge.config.issuer}/identity-check?${new URLSearchParams({ state })}`; },
      async exchangeAndVerify() {
        successExchanges += 1;
        return { ok: true, identity: { subject: SUBJECT, claims: { assurance: "verified" } } };
      },
    };
    const successFlow = createUpstreamRedirectFlow({
      bridge, identity: successIdentity, store, clock, audit: capturedAudit, rateLimit: capturedRateLimit,
      complete: "identity",
      onIdentity(identity) {
        observed = identity;
        return {
          status: 201,
          headers: { "content-type": "text/plain; charset=utf-8", "x-identity-completion": "delivered", "SeT-CoOkIe": `probe-session=${sessionValue}; Path=/; Secure; HttpOnly` },
          body: HOST_BODY,
        };
      },
    });
    const successDriver = await makeDriver(bridge, successFlow);
    try {
      const start = await successDriver.get("/login");
      const before = events.length;
      const response = await successDriver.get(callbackPath(start, "success"), callbackCookie(start));
      const slice = events.slice(before);
      checks.verifiedClaimsAndResponse &&= successExchanges === 1
        && observed?.subject === SUBJECT
        && observed?.claims?.assurance === "verified"
        && Object.isFrozen(observed)
        && response.status === 201
        && response.body === HOST_BODY
        && response.location === undefined;
      checks.twoCookies &&= JSON.stringify(cookieNames(response)) === JSON.stringify(["probe-session", "__Host-mcp-sso-identity"]);
      checks.noOAuthArtifacts &&= !/consent_token|<form|access_token|refresh_token|eyJ[A-Za-z0-9_-]{20,}/i.test(response.body)
        && slice.every((event) => !event.event.startsWith("oauth.authorize") && !event.event.startsWith("oauth.token"));
    } finally {
      await successDriver.close();
    }

    let failureExchanges = 0;
    let completions = 0;
    const failureIdentity = {
      redirectUri: `${bridge.config.issuer}/login/callback`,
      buildAuthorizationUrl({ state }) { return `${bridge.config.issuer}/identity-check?${new URLSearchParams({ state })}`; },
      async exchangeAndVerify() {
        failureExchanges += 1;
        return { ok: true, identity: { subject: SUBJECT } };
      },
    };
    const failureFlow = createUpstreamRedirectFlow({
      bridge, identity: failureIdentity, store, clock, audit: capturedAudit, rateLimit: capturedRateLimit,
      complete: "identity",
      onIdentity() { completions += 1; throw new Error(throwText); },
    });
    const failureDriver = await makeDriver(bridge, failureFlow);
    const stderr = [];
    const originalError = console.error;
    try {
      const start = await failureDriver.get("/login");
      const path = callbackPath(start, "failure");
      const cookie = callbackCookie(start);
      const before = events.length;
      console.error = (...values) => { stderr.push(values.join(" ")); };
      const response = await failureDriver.get(path, cookie);
      const failureEvents = events.slice(before);
      const replay = await failureDriver.get(path, cookie);
      checks.failureContract &&= fixedFailure(response)
        && JSON.stringify(cookieNames(response)) === JSON.stringify(["__Host-mcp-sso-identity"])
        && JSON.stringify(failureEvents.map((event) => [event.event, event.status, event.reason])) === JSON.stringify([
          ["identity.verify", "success", undefined],
          ["oauth.upstream.callback", "failure", "completion_failed"],
        ])
        && replay.status === 400
        && cookieNames(replay).includes("__Host-mcp-sso-identity")
        && failureExchanges === 1
        && completions === 1
        && !`${response.body}\n${JSON.stringify(failureEvents)}\n${stderr.join("\n")}`.includes(throwText);
    } finally {
      console.error = originalError;
      await failureDriver.close();
    }
  }

  checks.websiteLoginKeys = keys.length === ADAPTERS.length * 5
    && keys.every((key) => /^website-login:[^:]+(?::[^:]+)*$/.test(key))
    && keys.every((key) => !key.startsWith("upstream:"));
  return checks;
}
