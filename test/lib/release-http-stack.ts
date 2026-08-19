import assert from "node:assert/strict";
import { createServer, request, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";
import Fastify from "fastify";
import { Bridge } from "../../src/adapters/bridge.ts";
import { createOAuthRouter } from "../../src/adapters/express.ts";
import { registerOAuthRoutes } from "../../src/adapters/fastify.ts";
import { createOAuthApp } from "../../src/adapters/hono.ts";
import { headersFromDistinct, isMcpPath, readHeader } from "../../src/adapters/http.ts";
import type { UpstreamRedirectFlow } from "../../src/adapters/upstream-flow.ts";
import { buildUnauthorizedChallenge } from "../../src/challenge.ts";
import { originOf, type BridgeConfig } from "../../src/config.ts";
import { OAuthError } from "../../src/errors.ts";
import type { IdentityPort } from "../../src/ports/identity.ts";
import { RequestAuthorizer } from "../../src/verifier.ts";

export interface HttpResponse { status: number; headers: Record<string, string | string[] | undefined>; body: string }
export interface MountedStack { base: string; close(): Promise<void>; request?(input: Request): Promise<Response> }
export type AuthorizeMode = { identity: IdentityPort; identityHeader?: string } | { upstream: UpstreamRedirectFlow };

export function fetchLoopbackOnly(realFetch: typeof fetch, input: URL | Request | string, init?: RequestInit): Promise<Response> {
  const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
  if (url.protocol === "http:" && url.hostname === "127.0.0.1") {
    return realFetch(input, { ...init, redirect: "manual" }).then((response) => {
      if (response.status >= 300 && response.status < 400) throw new Error("unexpected loopback redirect");
      return response;
    });
  }
  throw new Error(`unexpected network request: ${url.origin}${url.pathname}`);
}

export async function attemptCleanup(label: string, action: () => Promise<unknown>, errors: Error[]): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([action(), new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} cleanup timed out`)), 5_000);
    })]);
  } catch (error) {
    errors.push(new Error(`${label} cleanup failed`, { cause: error }));
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

export function httpCall(base: string, method: string, path: string, headers: Record<string, string> = {}, body?: string): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, base);
    const req = request({ hostname: url.hostname, port: url.port, path: `${url.pathname}${url.search}`, method, headers, timeout: 10_000 }, (res) => {
      let output = "";
      res.setEncoding("utf8"); res.on("data", (chunk: string) => { output += chunk; });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: output }));
    });
    req.on("timeout", () => req.destroy(new Error(`${method} ${path} timed out`)));
    req.on("error", reject); if (body !== undefined) req.write(body); req.end();
  });
}

export const http = {
  get: (base: string, path: string, headers: Record<string, string> = {}) => httpCall(base, "GET", path, headers),
  postForm: (base: string, path: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
    httpCall(base, "POST", path, { "content-type": "application/x-www-form-urlencoded", ...headers }, new URLSearchParams(body).toString()),
  postJson: (base: string, path: string, body: unknown, headers: Record<string, string> = {}) =>
    httpCall(base, "POST", path, { "content-type": "application/json", ...headers }, JSON.stringify(body)),
};

function allowedOrigin(config: BridgeConfig, rawHeaders: IncomingMessage["headersDistinct"], headers: IncomingMessage["headers"]): boolean {
  const origin = readHeader(headersFromDistinct(rawHeaders, headers), "origin");
  return !origin.ambiguous && (origin.value === undefined || config.allowedOrigins.includes(origin.value) || origin.value === originOf(config.issuer));
}

async function serveMcp(req: IncomingMessage, res: ServerResponse, parsedBody: unknown, authorizer: RequestAuthorizer, config: BridgeConfig): Promise<void> {
  let subject: string;
  try {
    subject = (await authorizer.authorize({
      authorization: headersFromDistinct(req.headersDistinct, req.headers).authorization,
    })).subject;
  }
  catch (error) {
    const oauth = error instanceof OAuthError ? error : new OAuthError("invalid_token", "Bearer token is invalid", 401);
    res.writeHead(oauth.status, { "content-type": "application/json", "www-authenticate": buildUnauthorizedChallenge(config, {
      scope: config.scopeCatalog, error: oauth.code, errorDescription: oauth.message,
    }) });
    res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: oauth.code }, id: null })); return;
  }
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  const server = new McpServer({ name: "release-stack", version: "1" });
  server.tool("ping", "return the authenticated subject", async () => ({ content: [{ type: "text" as const, text: `pong: ${subject}` }] }));
  try { await server.connect(transport); await transport.handleRequest(req, res, parsedBody); }
  finally { await server.close(); }
}

function adapterOptions(bridge: Bridge, mode: AuthorizeMode) {
  return "upstream" in mode
    ? { bridge, upstream: mode.upstream }
    : { bridge, identity: mode.identity, identityHeader: mode.identityHeader };
}

async function mountFastify(bridge: Bridge, authorizer: RequestAuthorizer, config: BridgeConfig, mode: AuthorizeMode): Promise<MountedStack> {
  const app = Fastify();
  app.addHook("onRequest", async (req, reply) => {
    if (isMcpPath(req.url) && !allowedOrigin(config, req.raw.headersDistinct, req.raw.headers)) {
      reply.code(403).send({ jsonrpc: "2.0", error: { code: -32001, message: "Origin not allowed" }, id: null });
    }
  });
  await registerOAuthRoutes(app, adapterOptions(bridge, mode));
  app.post("/mcp", async (req, reply) => { reply.hijack(); await serveMcp(req.raw, reply.raw, req.body, authorizer, config); });
  const base = await app.listen({ host: "127.0.0.1", port: 0 });
  return { base, close: () => app.close() };
}

async function mountExpress(bridge: Bridge, authorizer: RequestAuthorizer, config: BridgeConfig, mode: AuthorizeMode): Promise<MountedStack> {
  const app = express();
  app.use((req, res, next) => {
    if (req.path === "/mcp" && !allowedOrigin(config, req.headersDistinct, req.headers)) {
      res.status(403).json({ jsonrpc: "2.0", error: { code: -32001, message: "Origin not allowed" }, id: null }); return;
    }
    next();
  });
  app.use("/mcp", express.json()); app.use("/", createOAuthRouter(adapterOptions(bridge, mode)));
  app.post("/mcp", (req, res) => { void serveMcp(req, res, req.body, authorizer, config); });
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => { server.once("listening", resolve); server.once("error", reject); });
  const port = (server.address() as { port: number }).port;
  return { base: `http://127.0.0.1:${port}`, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

async function mountHono(bridge: Bridge, authorizer: RequestAuthorizer, config: BridgeConfig, mode: AuthorizeMode): Promise<MountedStack> {
  // §6.7: hono has no framework req.ip. The stack's stored-DCR legs need an
  // extractor; mirror the loopback address fastify/express derive on the same
  // server so adapter behavior stays comparable.
  const app = createOAuthApp({ ...adapterOptions(bridge, mode), clientIp: () => "127.0.0.1" });
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
    if (url.pathname === "/mcp") {
      if (!allowedOrigin(config, req.headersDistinct, req.headers)) { res.writeHead(403); res.end(); return; }
      void serveMcp(req, res, undefined, authorizer, config); return;
    }
    void (async () => {
      const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk as Buffer);
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(",") : value);
      const init: RequestInit & { duplex?: "half" } = { method: req.method ?? "GET", headers };
      if (req.method !== "GET" && req.method !== "HEAD") { init.body = Buffer.concat(chunks); init.duplex = "half"; }
      const response = await app.fetch(new Request(`http://${req.headers.host}${req.url}`, init));
      const responseHeaders: Record<string, string> = {}; response.headers.forEach((value, key) => { responseHeaders[key] = value; });
      res.writeHead(response.status, responseHeaders); res.end(Buffer.from(await response.arrayBuffer()));
    })().catch(() => { if (!res.headersSent) res.writeHead(500); res.end(); });
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const port = (server.address() as { port: number }).port;
  return { base: `http://127.0.0.1:${port}`, close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    request: async (input) => app.fetch(input) };
}

export function mountStack(kind: "fastify" | "express" | "hono", bridge: Bridge, authorizer: RequestAuthorizer,
  config: BridgeConfig, mode: AuthorizeMode): Promise<MountedStack> {
  if (kind === "fastify") return mountFastify(bridge, authorizer, config, mode);
  if (kind === "express") return mountExpress(bridge, authorizer, config, mode);
  return mountHono(bridge, authorizer, config, mode);
}

export async function sdkPing(base: string, token: string, expected: string): Promise<void> {
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } });
  const client = new Client({ name: "release-stack", version: "1" }, { capabilities: {} });
  try {
    await client.connect(transport); const result = await client.callTool({ name: "ping", arguments: {} });
    const visible = (result.content as Array<{ type: string; text?: string }>).find((part) => part.type === "text")?.text;
    assert.equal(visible, expected);
  } finally { await client.close(); await transport.close(); }
}
