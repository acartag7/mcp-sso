// Token-only stub backend MCP server (gateway-deployment.md transparent-proxy target).
//
// The gateway (app.ts) stands in front of this as the SSO door: MCP clients never
// reach here directly. The gateway validates a bridge-minted token on /mcp, then
// forwards the request with BACKEND_API_KEY injected server-side (Authorization:
// Bearer <key>) — this backend accepts ONLY that static credential. The key never
// reaches a client, a config file, or a laptop; it lives in the gateway process.
//
// Shape (contracts §17.9 / docs/gateway-deployment.md "transparent proxy"):
//   - POST /mcp  → a real MCP server (the official SDK Streamable HTTP transport,
//                  stateless) so the proxied JSON-RPC round trip is genuine.
//   - GET  /mcp  → a BOUNDED SSE stream. A production stateful backend's GET stays
//                  open for server-initiated notifications; the gateway PIPES that
//                  long-lived stream the same way it pipes this bounded one. The
//                  stub keeps it short so the gateway's streaming-forward path is
//                  exercised deterministically (no hang in tests / single-run demo).
//   - DELETE /mcp → intentionally NOT registered. The gateway returns an explicit
//                  405 for it (the backend does not terminate sessions) rather than
//                  silently dropping it — the rule in gateway-deployment.md.

import Fastify, { type FastifyInstance } from "fastify";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

export interface BackendOptions {
  /** The static credential the gateway injects. The backend accepts only this
   *  exact `Bearer <apiKey>` value; anything else is 401'd. */
  apiKey: string;
  /** Test seam (production backends pass nothing): records what the backend
   *  received on each authorized /mcp request, so a test can PROVE the gateway
   *  injected the backend key and stripped the client's bridge token, and that
   *  transport headers (mcp-session-id / mcp-protocol-version) were forwarded. */
  recordReceived?: (entry: BackendReceived) => void;
}

export interface BackendReceived {
  method: string;
  /** The Authorization header the backend saw. Must be `Bearer <apiKey>` and
   *  must NEVER be the client's bridge token (the gateway strips it). */
  authorization?: string;
  mcpSessionId?: string;
  mcpProtocolVersion?: string;
  /** Forwarded transport headers the gateway's allowlist admits (proves forwarding). */
  accept?: string;
  lastEventId?: string;
  /** Every header name the backend received — so a test can prove the gateway's
   *  forward is an ALLOWLIST (fail-closed): a client header NOT in the allowlist
   *  (x-client-secret, cookie, …) must be absent here. */
  receivedHeaderNames: string[];
}

export interface BuiltBackend {
  app: FastifyInstance;
  close: () => Promise<void>;
}

/** Build the stub backend. Does not call listen() — the caller owns the socket
 *  (the gateway points at the resulting origin). */
export async function buildBackend(opts: BackendOptions): Promise<BuiltBackend> {
  const app = Fastify();

  // Token-only gate on EVERY /mcp method. The gateway injects the key; a direct
  // (non-proxied) call without it is rejected — defense-in-depth, since only the
  // gateway can reach this backend in the intended topology (NetworkPolicy +
  // loopback bind keep it private). The pathname is PARSED (not a raw string check
  // on request.url): an absolute-form request-target (`POST http://host/mcp`) still
  // routes here while request.url is the full URL, so `request.url === "/mcp"` would
  // skip the gate and bypass the credential check. Normalize first.
  app.addHook("onRequest", async (request, reply) => {
    let pathname: string;
    try { pathname = new URL(request.url, "http://localhost").pathname; } catch { return; }
    if (pathname !== "/mcp") return;
    const raw = request.headers.authorization;
    const got = Array.isArray(raw) ? raw[0] : raw;
    if (got !== `Bearer ${opts.apiKey}`) {
      reply.code(401).send({ jsonrpc: "2.0", error: { code: -32001, message: "invalid backend credential" }, id: null });
      return;
    }
    opts.recordReceived?.({
      method: request.method,
      authorization: got,
      mcpSessionId: readHeader(request.headers, "mcp-session-id"),
      mcpProtocolVersion: readHeader(request.headers, "mcp-protocol-version"),
      accept: readHeader(request.headers, "accept"),
      lastEventId: readHeader(request.headers, "last-event-id"),
      receivedHeaderNames: Object.keys(request.headers),
    });
  });

  // POST: real MCP server (stateless SDK transport), one tool. The tool output is
  // the proof the proxied round trip reached the backend (the test asserts the
  // client received THIS marker, not anything the gateway could have synthesized).
  app.post("/mcp", async (request, reply) => {
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    const mcp = new McpServer({ name: "mcp-sso-gateway-backend", version: "0.0.1" });
    mcp.tool("status", "backend reachability + identity proof", async () => ({
      content: [{ type: "text" as const, text: JSON.stringify({ ok: true, backend: "stub-backend-v1", via: "api-key-gateway" }) }],
    }));
    await mcp.connect(transport);
    reply.hijack();
    try {
      await transport.handleRequest(request.raw, reply.raw, request.body);
    } finally {
      await mcp.close();
    }
  });

  // GET: bounded SSE. The gateway forwards GET and PIPES the stream through (it
  // does not buffer). Short + closed here so the path is deterministic.
  app.get("/mcp", async (_request, reply) => {
    reply.hijack();
    reply.raw.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", "connection": "keep-alive" });
    reply.raw.write("event: open\ndata: {\"connected\":true}\n\n");
    reply.raw.write("data: {\"backend\":\"stub-backend-v1\",\"transport\":\"sse\"}\n\n");
    reply.raw.end();
  });

  // DELETE: deliberately absent — the gateway returns 405.

  return { app, close: async () => { await app.close(); } };
}

function readHeader(headers: Record<string, unknown>, name: string): string | undefined {
  const v = headers[name];
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return typeof v[0] === "string" ? v[0] : undefined;
  return undefined;
}
