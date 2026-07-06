// Integration test of the REAL PROCESS: `node examples/fastify-sqlite/index.ts`
// spawned as a child, driven over real HTTP. This is the only test that exercises
// listen() + the entry's main() + the default SIGTERM behavior — none of which
// buildExample/buildApp (in-process) can reach. Also covers threat-model row 27
// (the off-loopback pairing warning index.ts prints). TEST-ONLY: spawns the
// shipped entry; no src/examples changes.

import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url)); // repo root (parent of test/)
const ENTRY = "examples/fastify-sqlite/index.ts";

/** Probe an ephemeral port by briefly listening on it (PORT=0 is useless here:
 *  index.ts prints the REQUESTED port, so the actual bound port would be
 *  undiscoverable). Returns a port that was free at probe time. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      if (addr && typeof addr === "object") {
        const port = addr.port;
        s.close(() => resolve(port));
      } else {
        s.close();
        reject(new Error("could not bind a free port"));
      }
    });
  });
}

/** Wait until the child's stderr matches `regex`, failing the test on timeout or
 *  early exit (hang-guard: every wait is bounded). Returns the full captured stderr. */
function waitForStderr(child: ChildProcess, regex: RegExp, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = "";
    const onStderr = (chunk: Buffer | string): void => {
      buf += chunk.toString();
      if (regex.test(buf)) finish(undefined, buf);
    };
    const onExit = (): void => finish(new Error(`child exited before matching ${regex}; stderr:\n${buf.slice(-2000)}`));
    let timer: NodeJS.Timeout | undefined = setTimeout(() => finish(new Error(`timed out after ${timeoutMs}ms waiting for ${regex}; stderr:\n${buf.slice(-2000)}`)), timeoutMs);
    function finish(err: Error | undefined, captured?: string): void {
      if (timer) { clearTimeout(timer); timer = undefined; }
      child.stderr?.off("data", onStderr);
      child.off("exit", onExit);
      if (err) reject(err); else resolve(captured as string);
    }
    child.stderr?.on("data", onStderr);
    child.on("exit", onExit);
  });
}

/** Send `signal` and resolve on exit (bounded); rejects if the child doesn't exit. */
function waitForExitAfter(child: ChildProcess, signal: NodeJS.Signals, timeoutMs: number): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return new Promise((resolve, reject) => {
    let timer: NodeJS.Timeout | undefined = setTimeout(() => finish(new Error(`child did not exit ${timeoutMs}ms after ${signal}`)), timeoutMs);
    const onExit = (code: number | null, sig: NodeJS.Signals | null): void => finish(undefined, { code, signal: sig });
    function finish(err: Error | undefined, out?: { code: number | null; signal: NodeJS.Signals | null }): void {
      if (timer) { clearTimeout(timer); timer = undefined; }
      child.off("exit", onExit);
      if (err) reject(err); else resolve(out as { code: number | null; signal: NodeJS.Signals | null });
    }
    child.on("exit", onExit);
    child.kill(signal);
  });
}

function killHard(child: ChildProcess): void {
  // Liveness-only guard: `child.killed` is true the instant ANY signal (incl. the
  // SIGTERM waitForExitAfter already sent) is delivered, so checking !child.killed
  // would skip the SIGKILL exactly when a child that survived SIGTERM needs it most.
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
}

async function assertWellKnownServed(base: string): Promise<void> {
  const prm = await fetch(`${base}/.well-known/oauth-protected-resource`);
  assert.equal(prm.status, 200);
  assert.equal(typeof (await prm.json() as { resource: unknown }).resource, "string", "PRM has a resource");
  const as = await fetch(`${base}/.well-known/oauth-authorization-server`);
  assert.equal(as.status, 200);
  assert.equal(typeof (await as.json() as { issuer: unknown }).issuer, "string", "AS metadata has an issuer");
}

test("integration — spawned index.ts: readiness, .well-known served, /mcp 401+challenge, SIGTERM exits", async () => {
  const port = await freePort();
  const tmp = await mkdtemp(join(tmpdir(), "mcp-sso-spawn-"));
  const dir = join(tmp, "state"); // does NOT exist — buildExample creates it fresh (quickstart refuses an existing dir with no .gitignore)
  const base = `http://127.0.0.1:${port}`;
  // Inherit a working env, force the zero-setup branch + our port/dir. Pin HOST so
  // an ambient HOST (e.g. a developer's HOST=0.0.0.0) can't break the readiness regex.
  const env = { ...process.env, MCP_SSO_DIR: dir, PORT: String(port), HOST: "127.0.0.1", CF_ACCESS_AUDIENCE: "" };
  const child = spawn("node", [ENTRY], { cwd: REPO, env, stdio: ["ignore", "pipe", "pipe"] });
  try {
    await waitForStderr(child, new RegExp(`mcp-sso example listening on 127\\.0\\.0\\.1:${port}`), 15_000);
    await assertWellKnownServed(base);

    // /mcp with no token → 401 + the RFC 9728 resource_metadata challenge (fix #1).
    const mcp = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "0" } }, id: 1 }),
    });
    assert.equal(mcp.status, 401);
    assert.match(mcp.headers.get("www-authenticate") ?? "", /^Bearer resource_metadata=/);

    // index.ts installs NO signal handler — SIGTERM must terminate it promptly (graceful
    // shutdown would be a src change, out of scope). Assert exit-by-SIGTERM (code null).
    const exited = await waitForExitAfter(child, "SIGTERM", 5_000);
    assert.equal(exited.code, null, "terminated by signal, not a numeric exit code");
    assert.equal(exited.signal, "SIGTERM");
  } finally {
    killHard(child);
    await rm(tmp, { recursive: true, force: true });
  }
});

test("integration — spawned index.ts: HOST=0.0.0.0 prints the off-loopback pairing WARNING (threat-model row 27)", async () => {
  // The host SELECTION (loopback vs 0.0.0.0) is unit-tested in integration-example;
  // this asserts the LOUD stderr WARNING that selection triggers — the operator
  // signal that the single-operator pairing envelope has been breached.
  const port = await freePort();
  const tmp = await mkdtemp(join(tmpdir(), "mcp-sso-spawn-warn-"));
  const dir = join(tmp, "state"); // does NOT exist — buildExample creates it
  const env = { ...process.env, MCP_SSO_DIR: dir, PORT: String(port), HOST: "0.0.0.0", CF_ACCESS_AUDIENCE: "" };
  const child = spawn("node", [ENTRY], { cwd: REPO, env, stdio: ["ignore", "pipe", "pipe"] });
  try {
    const stderr = await waitForStderr(child, /mcp-sso example listening on 0\.0\.0\.0:/, 15_000);
    assert.match(stderr, /\[mcp-sso\] WARNING: console pairing is bound to 0\.0\.0\.0 \(non-loopback\)/, "off-loopback warning printed before listen");
    const exited = await waitForExitAfter(child, "SIGTERM", 5_000);
    assert.equal(exited.signal, "SIGTERM");
  } finally {
    killHard(child);
    await rm(tmp, { recursive: true, force: true });
  }
});
