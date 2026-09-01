import { createServer, type IncomingHttpHeaders, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import express from "express";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import type { Hono } from "hono";
import type { Bridge } from "../../src/adapters/bridge.ts";
import { createOAuthRouter } from "../../src/adapters/express.ts";
import { registerOAuthRoutes } from "../../src/adapters/fastify.ts";
import { createOAuthApp } from "../../src/adapters/hono.ts";
import type { BridgeConfig } from "../../src/config.ts";
import type { IdentityPort } from "../../src/ports/identity.ts";
import type { RequestAuthorizer } from "../../src/verifier.ts";
import { FixtureRunnerError } from "./error.ts";
import { protectedOutcome, type HostOutcome } from "./protected-handler.ts";
import type { AdapterKind, ProtectedResource } from "./types.ts";

const HOST = "127.0.0.1";
/** The corpus header bounds leave worst-case fixture header blocks far above
 *  Node's parser default, so every mounted server parses blocks no schema-valid
 *  fixture can exceed instead of rejecting one for size. */
const MAX_HEADER_BYTES = 131072;
const MCP_PATH = "/mcp";
export const ECHO_PATH = "/__echo";
const JSON_RPC_CONTENT_TYPE = "application/json; charset=utf-8";
const JSON_RPC_ERROR_CODE = -32001;
const HOST_FAILURE = "fixture host failure";
const NO_TCP_PORT = "fixture host did not bind a TCP port";
const HIJACK_MISSED = "fixture host reached the fastify /mcp handler after the hijack";
const NON_ERROR_THROW = "fixture host threw a value that is not an Error";
const NULL_BODY_STATUS = new Set([101, 204, 205, 304]);

/** Node occurrence metadata carried across the Fetch boundary the Hono mount
 *  crosses. A Fetch `Request` joins repeated headers into one comma-separated
 *  field, hiding the ambiguity the Origin gate refuses, so the Node server
 *  stashes `IncomingMessage.headersDistinct` under this symbol. */
const DISTINCT_HEADERS = Symbol("parityDistinctHeaders");
/** The exact outcome a `/mcp` Hono handler computed, keyed by the `Response` it
 *  returned. `Response` lowercases header names and joins repeated occurrences,
 *  so the Node server writes this recorded outcome instead of that rendering. */
/** The computed `/mcp` outcome, carried on the stashed Fetch `Request`. Hono
 *  wraps HEAD responses in a bodyless `Response` that renders joined headers,
 *  so the dispatcher reads the outcome from the request instead of the
 *  `Response` it cannot trust for wire shape. */
const STASHED_OUTCOME = Symbol("parityStashedOutcome");

interface StashedRequest extends Request {
  [DISTINCT_HEADERS]?: Record<string, string[] | undefined>;
  [STASHED_OUTCOME]?: HostOutcome;
}

export interface MountedHost {
  base: string;
  close(): Promise<void>;
  failure(): Error | undefined;
}

export interface MountHostInput {
  adapter: AdapterKind; bridge: Bridge; authorizer: RequestAuthorizer;
  config: BridgeConfig; identity: IdentityPort; protectedResource: ProtectedResource;
}

interface AdapterRoutes { bridge: Bridge; identity: IdentityPort }

type ProtectedRun = (
  distinct: Record<string, string[] | undefined> | undefined, normalized?: IncomingHttpHeaders,
) => Promise<HostOutcome>;

/** Compose the reference implementation behind one framework adapter on a
 *  loopback port: the library's OAuth routes through that adapter's public API,
 *  and the fixture's protected `/mcp` route beside them. The host exposes its
 *  base URL, the first failure it recorded, and a prompt close, so a run's
 *  ports and sockets never outlive the fixture that opened them. */
export async function mountHost(input: MountHostInput): Promise<MountedHost> {
  const failures: Error[] = [];
  const run: ProtectedRun = async (distinct, normalized) => await protectedOutcome({
    ...distinct === undefined ? {} : { distinct },
    ...normalized === undefined ? {} : { normalized },
    authorizer: input.authorizer, config: input.config, protectedResource: input.protectedResource,
  });
  const routes: AdapterRoutes = { bridge: input.bridge, identity: input.identity };
  if (input.adapter === "fastify") return await mountFastify(routes, run, failures);
  if (input.adapter === "express") return await mountExpress(routes, run, failures);
  return await mountHono(routes, run, failures);
}

/** Fastify parses the body after the route-level `onRequest` hook, so the hook
 *  hijacks the reply and answers there: the Origin gate decides before any body
 *  is read, on every method and every media type. */
async function mountFastify(routes: AdapterRoutes, run: ProtectedRun, failures: Error[]): Promise<MountedHost> {
  const app = Fastify({ forceCloseConnections: true, http: { maxHeaderSize: MAX_HEADER_BYTES } });
  await registerOAuthRoutes(app, routes);
  const onRequest = async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    reply.hijack();
    await respondNode(reply.raw, () => run(request.raw.headersDistinct, request.raw.headers), failures);
  };
  app.all(MCP_PATH, { onRequest }, async (): Promise<never> => {
    const error = new FixtureRunnerError(HIJACK_MISSED);
    failures.push(error); throw error;
  });
  const base = await app.listen({ host: HOST, port: 0 });
  return mounted(base, async () => { await app.close(); }, failures);
}

/** Express parses bodies only where a parser is mounted, and the OAuth router
 *  mounts its own on the OAuth POST paths alone, so `/mcp` reaches the handler
 *  with the body untouched on every method. */
async function mountExpress(routes: AdapterRoutes, run: ProtectedRun, failures: Error[]): Promise<MountedHost> {
  const app = express();
  app.use("/", createOAuthRouter(routes));
  app.all(MCP_PATH, (request, response) => {
    void respondNode(response, () => run(request.headersDistinct, request.headers), failures);
  });
  const server = createServer({ maxHeaderSize: MAX_HEADER_BYTES }, app);
  server.listen(0, HOST);
  await listening(server);
  return mounted(`http://${HOST}:${addressPort(server)}`, async () => { await closeServer(server); }, failures);
}

/** Hono has no Node server of its own, so this mount owns one. `clientIp` is
 *  supplied because stored DCR refuses to boot without an extractor and the
 *  stateless default warns; loopback is what `req.ip` yields on the others. */
async function mountHono(routes: AdapterRoutes, run: ProtectedRun, failures: Error[]): Promise<MountedHost> {
  const app = createOAuthApp({ ...routes, clientIp: () => HOST });
  // The mount's one body-reading sink: `/mcp` must answer before any body
  // handling and the OAuth routes bound their own bodies, so this route reads
  // the buffered body back verbatim for the buffering guarantee.
  app.post(ECHO_PATH, async (context) => new Response(await context.req.arrayBuffer()));
  app.all(MCP_PATH, async (context) => {
    const stashed = context.req.raw as StashedRequest;
    return await honoResponse(() => run(stashed[DISTINCT_HEADERS]), failures, stashed);
  });
  const server = createServer({ maxHeaderSize: MAX_HEADER_BYTES }, (incoming, outgoing) => { void dispatchHono(app, incoming, outgoing, failures); });
  server.listen(0, HOST);
  await listening(server);
  return mounted(`http://${HOST}:${addressPort(server)}`, async () => { await closeServer(server); }, failures);
}

/** Translate one Node request into the Fetch request Hono answers, then write
 *  the answer back. `/mcp` dispatches from the headers alone and its bytes are
 *  drained unread, so its Origin gate decides exactly when the other mounts
 *  decide; every other route buffers the body whole, unbounded by the runner
 *  (§19.1) because the OAuth routes enforce their own raw-body budgets. A throw
 *  here is recorded and answered with a bare 500. */
async function dispatchHono(app: Hono, incoming: IncomingMessage, outgoing: ServerResponse, failures: Error[]): Promise<void> {
  try {
    if (isMcpTarget(incoming.url)) {
      const stashed = honoRequest(incoming);
      const response = await app.fetch(stashed);
      const carried = stashed[STASHED_OUTCOME];
      await writeOutcome(outgoing, () => carried ?? outcomeFromResponse(response), failures);
      incoming.resume();
      return;
    }
    const response = await app.fetch(honoRequest(incoming, await readBody(incoming)));
    await writeOutcome(outgoing, () => outcomeFromResponse(response), failures);
  } catch (error) { failures.push(asError(error)); bareFailure(outgoing); }
}

/** Write the computed outcome, answering the shared failure document when the
 *  outcome cannot be rendered, exactly as the Node mounts answer it. */
async function writeOutcome(
  outgoing: ServerResponse, run: () => HostOutcome | Promise<HostOutcome>, failures: Error[],
): Promise<void> {
  const outcome = await guarded(run, failures);
  try { writeNode(outgoing, outcome); }
  catch (error) {
    failures.push(asError(error));
    try { writeNode(outgoing, failureOutcome()); }
    catch { bareFailure(outgoing); }
  }
}

function isMcpTarget(url: string | undefined): boolean {
  return new URL(url ?? "/", `http://${HOST}`).pathname === MCP_PATH;
}

function honoRequest(incoming: IncomingMessage, body?: Buffer): StashedRequest {
  const headers = new Headers();
  const raw = incoming.rawHeaders;
  for (let index = 0; index + 1 < raw.length; index += 2) headers.append(raw[index]!, raw[index + 1]!);
  const method = (incoming.method ?? "GET").toUpperCase();
  const init: RequestInit & { duplex?: "half" } = { method, headers };
  if (body !== undefined && method !== "GET" && method !== "HEAD") { init.body = body; init.duplex = "half"; }
  const url = `http://${incoming.headers.host ?? HOST}${incoming.url ?? "/"}`;
  const request = new Request(url, init) as StashedRequest;
  request[DISTINCT_HEADERS] = incoming.headersDistinct;
  return request;
}

/** Buffer the request body whole. The only client is the fixture runner on
 *  loopback, so the buffer's size follows the fixture, never a runner-side
 *  bound that could reject a schema-valid request (§19.1). */
function readBody(incoming: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    incoming.on("data", (chunk: Buffer) => { chunks.push(chunk); });
    incoming.on("end", () => resolve(Buffer.concat(chunks)));
    incoming.on("error", reject);
  });
}

async function honoResponse(
  runOutcome: () => Promise<HostOutcome>, failures: Error[], stashed?: StashedRequest,
): Promise<Response> {
  const outcome = await guarded(runOutcome, failures);
  if (stashed) stashed[STASHED_OUTCOME] = outcome;
  try { return responseFrom(outcome); }
  catch (error) { failures.push(asError(error)); return responseFrom(failureOutcome()); }
}

function responseFrom(outcome: HostOutcome): Response {
  const headers = new Headers();
  for (const [name, value] of Object.entries(outcome.headers)) {
    for (const occurrence of Array.isArray(value) ? value : [value]) headers.append(name, occurrence);
  }
  const bodyless = outcome.body.byteLength === 0 || NULL_BODY_STATUS.has(outcome.status);
  return new Response(bodyless ? null : outcome.body, { status: outcome.status, headers });
}

async function outcomeFromResponse(response: Response): Promise<HostOutcome> {
  const headers: Record<string, string | string[]> = {};
  response.headers.forEach((value, name) => { headers[name] = value; });
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) headers["set-cookie"] = cookies;
  return { status: response.status, headers, body: Buffer.from(await response.arrayBuffer()) };
}

async function respondNode(outgoing: ServerResponse, runOutcome: () => Promise<HostOutcome>, failures: Error[]): Promise<void> {
  const outcome = await guarded(runOutcome, failures);
  try { writeNode(outgoing, outcome); }
  catch (error) {
    failures.push(asError(error));
    try { writeNode(outgoing, failureOutcome()); }
    catch { bareFailure(outgoing); }
  }
}

/** A handler throw is the fixture's defect, not the client's: record it and
 *  answer the JSON-RPC 500 so the request completes and `failure()` names it. */
async function guarded(runOutcome: () => HostOutcome | Promise<HostOutcome>, failures: Error[]): Promise<HostOutcome> {
  try { return await runOutcome(); }
  catch (error) { failures.push(asError(error)); return failureOutcome(); }
}

function failureOutcome(): HostOutcome {
  const document = { jsonrpc: "2.0", error: { code: JSON_RPC_ERROR_CODE, message: HOST_FAILURE }, id: null };
  const body = Buffer.from(JSON.stringify(document), "utf8");
  return { status: 500, headers: { "content-type": JSON_RPC_CONTENT_TYPE }, body };
}

function writeNode(outgoing: ServerResponse, outcome: HostOutcome): void {
  const declared = outcome.headers["content-length"];
  const wireLength = NULL_BODY_STATUS.has(outcome.status) ? 0 : outcome.body.byteLength;
  if (declared !== undefined) {
    if (Array.isArray(declared) || Number(declared) !== wireLength) {
      throw new FixtureRunnerError(
        `declared content-length ${JSON.stringify(declared)} is not one occurrence matching the ${wireLength} wire bytes of the encoded body`,
      );
    }
  }
  outgoing.writeHead(outcome.status, outcome.headers);
  outgoing.end(NULL_BODY_STATUS.has(outcome.status) ? undefined : outcome.body);
}

function bareFailure(outgoing: ServerResponse): void {
  if (!outgoing.headersSent) outgoing.writeHead(500);
  outgoing.end();
}

function mounted(base: string, close: () => Promise<void>, failures: Error[]): MountedHost {
  return { base, close, failure: () => failures[0] };
}

function listening(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("listening", () => resolve());
    server.once("error", reject);
  });
}

/** Destroy live sockets first: a client holding a keep-alive connection would
 *  otherwise keep `close` pending until the idle timeout. A second call
 *  resolves rather than reporting that the server is already down. */
async function closeServer(server: Server): Promise<void> {
  const closed = new Promise<void>((resolve) => { server.close(() => { resolve(); }); });
  server.closeAllConnections();
  await closed;
}

function addressPort(server: Server): number {
  const address = server.address();
  if (address === null || typeof address === "string") throw new FixtureRunnerError(NO_TCP_PORT);
  return address.port;
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new FixtureRunnerError(`${NON_ERROR_THROW}: ${String(error)}`);
}
