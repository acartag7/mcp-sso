// Behavioural units for scripts/live/probe-e2e.mjs, kept importable so the
// suite executes them instead of grepping the probe's source for their names.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

/** A ClientStore that carries the §17.2 atomic machine-client extension for a
 *  probe run. DCR clients go to the SQLite store the example opens; machine rows
 *  live in this process because no shipped store implements the extension —
 *  the probe row that uses this store says exactly that. `bind` attaches the
 *  SQLite store once the example has opened it. */
export function createProbeClientStore() {
  const machineRows = new Map();
  let sqlite;
  const requireSqlite = () => {
    if (sqlite === undefined) throw new Error("probe client store is not bound to SQLite yet");
    return sqlite;
  };
  const store = Object.freeze({
    async save(client) {
      await requireSqlite().save(client);
    },
    async find(clientId) {
      const row = machineRows.get(clientId);
      if (row !== undefined) return structuredClone(row.client);
      return await requireSqlite().find(clientId);
    },
    async createMachineClient(client, audit) {
      if (machineRows.has(client.clientId)) return false;
      machineRows.set(client.clientId, { client: structuredClone(client), audit: structuredClone(audit) });
      return true;
    },
    async compareAndSwapMachineClient(expectedVersion, client, audit) {
      const current = machineRows.get(client.clientId);
      if (current === undefined || current.client.version !== expectedVersion) return false;
      machineRows.set(client.clientId, { client: structuredClone(client), audit: structuredClone(audit) });
      return true;
    },
  });
  return { store, bind(value) { sqlite = value; } };
}

/** The consent form's signed token, or undefined when the page is not a consent page. */
export function extractConsentToken(html) {
  if (typeof html !== "string") return undefined;
  const match = /name="consent_token" value="([^"]+)"/.exec(html);
  return match?.[1];
}

/** URL-encoded form body for the token, approve, and revoke routes. */
export const form = (params) => new URLSearchParams(params).toString();

/** Parse a JSONL audit file; a malformed line is a parse failure, not a skip. */
export function parseJsonl(text) {
  if (typeof text !== "string" || text.trim() === "") return [];
  return text.trim().split("\n").map((line) => JSON.parse(line));
}

/** True when any secret value appears verbatim in the text. Values that are not
 *  non-empty strings make the check fail closed by returning true. */
export function containsCredential(text, values) {
  return values.some((value) => typeof value !== "string" || value.length === 0 || text.includes(value));
}

/** Race a promise against a hard deadline. The MCP SDK transport overrides
 *  requestInit.signal, so the abort lever is transport.close() in the caller. */
export function withTimeout(promise, ms, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    promise.then((value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); });
  });
}

/** Drive the OFFICIAL MCP SDK client — transport, initialize handshake, and the
 *  `ping` tool — against a listening `/mcp` with a bearer token. Resolves to
 *  the tool's text content, or undefined when any step fails. */
export async function sdkPing(base, token, timeoutMs = 10_000) {
  const transport = new StreamableHTTPClientTransport(new URL("/mcp", base), {
    requestInit: { headers: { authorization: `Bearer ${token}` } },
  });
  const client = new Client({ name: "mcp-sso-live-probe", version: "0.0.1" }, { capabilities: {} });
  try {
    await withTimeout(client.connect(transport), timeoutMs, "MCP client connect");
    const result = await withTimeout(client.callTool({ name: "ping", arguments: {} }), timeoutMs, "MCP client callTool");
    if (result.isError === true) return undefined;
    return (result.content ?? []).find((part) => part.type === "text")?.text;
  } catch {
    return undefined;
  } finally {
    try { await client.close(); } catch { /* the transport close below is the abort lever */ }
    try { await transport.close(); } catch { /* nothing left to release */ }
  }
}
