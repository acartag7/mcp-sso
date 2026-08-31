import { createServer, type IncomingHttpHeaders, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import express from "express";
import Fastify from "fastify";
import type { Hono } from "hono";
import { Bridge } from "../../src/adapters/bridge.ts";
import { createOAuthRouter } from "../../src/adapters/express.ts";
import { registerOAuthRoutes } from "../../src/adapters/fastify.ts";
import { createOAuthApp } from "../../src/adapters/hono.ts";
import { headersFromDistinct, readHeader } from "../../src/adapters/http.ts";
import { buildUnauthorizedChallenge } from "../../src/challenge.ts";
import { originOf, type BridgeConfig } from "../../src/config.ts";
import { OAuthError } from "../../src/errors.ts";
import type { IdentityPort } from "../../src/ports/identity.ts";
import { RequestAuthorizer } from "../../src/verifier.ts";
import type { AdapterKind, BodyValue, HeaderMap, ProtectedResource } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";

const DISTINCT_HEADERS = Symbol("parityDistinctHeaders");
const RAW_OUTCOMES = new WeakMap<Response, Outcome>();
interface ExtendedRequest extends Request { [DISTINCT_HEADERS]?: Record<string, string[] | undefined> }
interface Outcome { status: number; headers: Record<string, string | string[]>; body: Buffer }
type ProtectedHandler = (distinct: Record<string, string[] | undefined>, normalized?: IncomingHttpHeaders) => Promise<Outcome>;
export interface MountedHost {
  base: string; close(): Promise<void>; failure(): Error | undefined;
}

export async function mountHost(args: {
  adapter: AdapterKind; bridge: Bridge; authorizer: RequestAuthorizer;
  config: BridgeConfig; identity: IdentityPort; protectedResource: ProtectedResource;
}): Promise<MountedHost> {
  const failures: Error[] = [];
  const protectedHandler = (distinct: Record<string, string[] | undefined>, normalized?: IncomingHttpHeaders) =>
    protectedOutcome(distinct, normalized, args.authorizer, args.config, args.protectedResource);
  if (args.adapter === "fastify") return mountFastify(args.bridge, args.identity, protectedHandler, failures);
  if (args.adapter === "express") return mountExpress(args.bridge, args.identity, protectedHandler, failures);
  return mountHono(args.bridge, args.identity, protectedHandler, failures);
}

async function protectedOutcome(
  distinct: Record<string, string[] | undefined>, normalized: IncomingHttpHeaders | undefined,
  authorizer: RequestAuthorizer, config: BridgeConfig, protectedResource: ProtectedResource,
): Promise<Outcome> {
  const headers = headersFromDistinct(distinct, normalized);
  const origin = readHeader(headers, "origin");
  if (origin.ambiguous || (origin.value !== undefined
    && origin.value !== originOf(config.issuer) && !config.allowedOrigins.includes(origin.value))) {
    return jsonRpc(403, "Origin not allowed");
  }
  try {
    await authorizer.authorize({ authorization: headers.authorization,
      ...(protectedResource.requiredScope === null ? {} : { requiredScope: protectedResource.requiredScope }) });
  } catch (error) {
    const oauth = error instanceof OAuthError ? error : new OAuthError("invalid_token", "Bearer token is invalid", 401);
    const outcome = jsonRpc(oauth.status, `${oauth.code}: ${oauth.message}`);
    outcome.headers["www-authenticate"] = buildUnauthorizedChallenge(config, {
      scope: config.scopeCatalog, error: oauth.code, errorDescription: oauth.message,
    });
    return outcome;
  }
  if (!protectedResource.success) throw new FixtureRunnerError("protected handler ran without given.protectedResource.success");
  return { status: protectedResource.success.status, headers: explicitHeaders(protectedResource.success.headers),
    body: encodeBody(protectedResource.success.body) };
}

async function mountFastify(
  bridge: Bridge, identity: IdentityPort, handler: ProtectedHandler, failures: Error[],
): Promise<MountedHost> {
  const app = Fastify(); await registerOAuthRoutes(app, { bridge, identity });
  app.all("/mcp", async (request, reply) => {
    reply.hijack(); await writeNode(reply.raw, await guarded(handler(request.raw.headersDistinct, request.raw.headers), failures));
  });
  const base = await app.listen({ host: "127.0.0.1", port: 0 });
  return mounted(base, () => app.close(), failures);
}

async function mountExpress(
  bridge: Bridge, identity: IdentityPort, handler: ProtectedHandler, failures: Error[],
): Promise<MountedHost> {
  const app = express(); app.use("/", createOAuthRouter({ bridge, identity }));
  app.all("/mcp", (request, response) => {
    void guarded(handler(request.headersDistinct, request.headers), failures).then((outcome) => writeNode(response, outcome));
  });
  const server = app.listen(0, "127.0.0.1"); await listening(server);
  const port = addressPort(server); return mounted(`http://127.0.0.1:${port}`, () => closeServer(server), failures);
}

async function mountHono(
  bridge: Bridge, identity: IdentityPort, handler: ProtectedHandler, failures: Error[],
): Promise<MountedHost> {
  const app = createOAuthApp({ bridge, identity, clientIp: () => "127.0.0.1" });
  app.all("/mcp", async (context) => {
    const request = context.req.raw as ExtendedRequest;
    return responseFrom(await guarded(handler(request[DISTINCT_HEADERS] ?? {}), failures));
  });
  const server = createServer((incoming, outgoing) => {
    void dispatchHono(app, incoming, outgoing, failures);
  });
  server.listen(0, "127.0.0.1"); await listening(server);
  const port = addressPort(server); return mounted(`http://127.0.0.1:${port}`, () => closeServer(server), failures);
}

async function dispatchHono(app: Hono, incoming: IncomingMessage, outgoing: ServerResponse, failures: Error[]): Promise<void> {
  try {
    const chunks: Buffer[] = []; for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
    const headers = new Headers();
    for (let index = 0; index < incoming.rawHeaders.length; index += 2) headers.append(incoming.rawHeaders[index]!, incoming.rawHeaders[index + 1]!);
    const init: RequestInit & { duplex?: "half" } = { method: incoming.method, headers };
    if (incoming.method !== "GET" && incoming.method !== "HEAD") { init.body = Buffer.concat(chunks); init.duplex = "half"; }
    const request = new Request(`http://${incoming.headers.host}${incoming.url}`, init) as ExtendedRequest;
    request[DISTINCT_HEADERS] = incoming.headersDistinct;
    const response = await app.fetch(request);
    const raw = RAW_OUTCOMES.get(response);
    if (raw) { await writeNode(outgoing, raw); return; }
    const responseHeaders: Record<string, string | string[]> = {};
    response.headers.forEach((value, name) => { responseHeaders[name] = value; });
    const cookies = response.headers.getSetCookie(); if (cookies.length > 0) responseHeaders["set-cookie"] = cookies;
    await writeNode(outgoing, { status: response.status, headers: responseHeaders,
      body: Buffer.from(await response.arrayBuffer()) });
  } catch (error) {
    failures.push(asError(error)); if (!outgoing.headersSent) outgoing.writeHead(500); outgoing.end();
  }
}

async function guarded(promise: Promise<Outcome>, failures: Error[]): Promise<Outcome> {
  try { return await promise; }
  catch (error) { failures.push(asError(error)); return jsonRpc(500, "fixture host failure"); }
}
function mounted(base: string, close: () => Promise<void>, failures: Error[]): MountedHost {
  return { base, close, failure: () => failures[0] };
}
function jsonRpc(status: number, message: string): Outcome {
  return { status, headers: { "content-type": "application/json; charset=utf-8" },
    body: Buffer.from(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message }, id: null })) };
}
function explicitHeaders(headers: HeaderMap): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [name, raw] of Object.entries(headers)) {
    const values = Array.isArray(raw) ? raw : [raw];
    if (!values.every((value) => typeof value === "string")) throw new FixtureRunnerError(`protected response header ${name} contains a capture`);
    result[name] = values.length === 1 ? values[0] as string : values as string[];
  }
  return result;
}
function encodeBody(body: BodyValue): Buffer { return "absent" in body ? Buffer.alloc(0) : Buffer.from(typeof body.value === "string" ? body.value : JSON.stringify(body.value)); }
async function writeNode(response: ServerResponse, outcome: Outcome): Promise<void> { response.writeHead(outcome.status, outcome.headers); response.end(outcome.body); }
function responseFrom(outcome: Outcome): Response {
  const headers = new Headers();
  for (const [name, raw] of Object.entries(outcome.headers)) for (const value of Array.isArray(raw) ? raw : [raw]) headers.append(name, value);
  const response = new Response(outcome.body.byteLength === 0 ? null : outcome.body, { status: outcome.status, headers });
  RAW_OUTCOMES.set(response, outcome); return response;
}
function listening(server: Server): Promise<void> { return new Promise((resolve, reject) => { server.once("listening", resolve); server.once("error", reject); }); }
function closeServer(server: Server): Promise<void> { return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
function addressPort(server: Server): number { const address = server.address(); if (!address || typeof address === "string") throw new Error("fixture host did not bind a TCP port"); return address.port; }
function asError(error: unknown): Error { return error instanceof Error ? error : new Error("non-Error fixture host failure"); }
