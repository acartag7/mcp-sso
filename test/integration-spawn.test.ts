// Integration tests of the REAL PROCESSES:
// `node examples/fastify-sqlite/index.ts` and
// `node examples/api-key-gateway/index.ts`, spawned as children. These are the
// only tests that exercise listen() + each entry's main() ordering, which the
// in-process builders cannot reach. Also covers threat-model row 27's
// pre-listen refusal of an off-loopback pairing bind.

import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url)); // repo root (parent of test/)
const ENTRY = "examples/fastify-sqlite/index.ts";
const GATEWAY_ENTRY = "examples/api-key-gateway/index.ts";

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

/** Capture stderr through natural process close, bounded so an entrypoint boot
 *  regression cannot hang the suite. */
function waitForClose(child: ChildProcess, timeoutMs: number): Promise<{ code: number | null; signal: NodeJS.Signals | null; stderr: string }> {
  return new Promise((resolve, reject) => {
    let stderr = "";
    const onStderr = (chunk: Buffer | string): void => { stderr += chunk.toString(); };
    let timer: NodeJS.Timeout | undefined = setTimeout(
      () => finish(new Error(`child did not close within ${timeoutMs}ms; stderr:\n${stderr.slice(-2000)}`)),
      timeoutMs,
    );
    const onClose = (code: number | null, signal: NodeJS.Signals | null): void =>
      finish(undefined, { code, signal, stderr });
    function finish(
      error: Error | undefined,
      result?: { code: number | null; signal: NodeJS.Signals | null; stderr: string },
    ): void {
      if (timer) { clearTimeout(timer); timer = undefined; }
      child.stderr?.off("data", onStderr);
      child.off("close", onClose);
      if (error) reject(error); else resolve(result as { code: number | null; signal: NodeJS.Signals | null; stderr: string });
    }
    child.stderr?.on("data", onStderr);
    child.on("close", onClose);
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

/** fetch with a hard deadline: if the spawned server accepts the socket but a route
 *  never completes, an unbounded fetch would hang CI (node --test has no per-test
 *  timeout). AbortSignal.timeout rejects after 10s. (Codex P2: bare fetches.) */
async function fetchBounded(url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(10_000) });
}

async function assertWellKnownServed(base: string): Promise<void> {
  const prm = await fetchBounded(`${base}/.well-known/oauth-protected-resource`);
  assert.equal(prm.status, 200);
  assert.equal(typeof (await prm.json() as { resource: unknown }).resource, "string", "PRM has a resource");
  const as = await fetchBounded(`${base}/.well-known/oauth-authorization-server`);
  assert.equal(as.status, 200);
  assert.equal(typeof (await as.json() as { issuer: unknown }).issuer, "string", "AS metadata has an issuer");
}

/** Build a hermetic env for the spawned example: inherit a working runtime env
 *  (PATH/HOME/…), then SWEEP every identity/config var so ambient shell
 *  config can't make buildExample boot with a different issuer/resource/scope
 *  catalog (or fail validation) before the readiness check. `overrides` then pins
 *  exactly the inputs the test wants. (Codex P2: spreading raw process.env leaked
 *  the developer's OAUTH_* into the child.) */
function childEnv(overrides: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const k of Object.keys(env)) {
    if (k.startsWith("OAUTH_") || k.startsWith("MCP_SSO_") || k.startsWith("CF_ACCESS_") || k.startsWith("ENTRA_") || k.startsWith("GOOGLE_") || k.startsWith("OIDC_") || k.startsWith("BACKEND_")) delete env[k];
  }
  return Object.assign(env, overrides);
}

test("integration — spawned index.ts: readiness, .well-known served, /mcp 401+challenge, SIGTERM exits", async () => {
  const port = await freePort();
  const tmp = await mkdtemp(join(tmpdir(), "mcp-sso-spawn-"));
  const dir = join(tmp, "state"); // does NOT exist — buildExample creates it fresh (quickstart refuses an existing dir with no .gitignore)
  const base = `http://127.0.0.1:${port}`;
  // Hermetic env: zero-setup branch (all provider selectors are absent) + our
  // port/dir, pinned HOST, and no ambient OAUTH_*/provider config.
  const env = childEnv({ MCP_SSO_DIR: dir, PORT: String(port), HOST: "127.0.0.1" });
  const child = spawn("node", [ENTRY], { cwd: REPO, env, stdio: ["ignore", "pipe", "pipe"] });
  try {
    await waitForStderr(child, new RegExp(`mcp-sso example listening on 127\\.0\\.0\\.1:${port}`), 15_000);
    await assertWellKnownServed(base);

    // /mcp with no token → 401 + the RFC 9728 resource_metadata challenge (fix #1).
    const mcp = await fetchBounded(`${base}/mcp`, {
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

test("integration — both spawned entries refuse no-IdP HOST=0.0.0.0 before state or backend listen", async () => {
  const tmp = await mkdtemp(join(tmpdir(), "mcp-sso-spawn-nonloopback-"));
  const occupied = createServer();
  await new Promise<void>((resolve, reject) => {
    occupied.once("error", reject);
    occupied.listen(0, "127.0.0.1", resolve);
  });
  const address = occupied.address();
  assert.ok(address && typeof address === "object", "occupied backend has a TCP address");
  try {
    for (const [name, entry, extra] of [
      ["fastify", ENTRY, {}],
      ["gateway", GATEWAY_ENTRY, {
        BACKEND_API_KEY: randomBytes(32).toString("base64url"),
        BACKEND_HOST: "127.0.0.1",
        BACKEND_PORT: String(address.port),
      }],
    ] as const) {
      const dir = join(tmp, name);
      const env = childEnv({ MCP_SSO_DIR: dir, HOST: "0.0.0.0", ...extra });
      const child = spawn("node", [entry], { cwd: REPO, env, stdio: ["ignore", "pipe", "pipe"] });
      try {
        const exited = await waitForClose(child, 15_000);
        assert.notEqual(exited.code, 0, `${name}: unsafe bind exits nonzero`);
        assert.match(exited.stderr, /MCP_SSO_UNSAFE_ALLOW_NON_LOOPBACK_PAIRING=true/);
        assert.doesNotMatch(exited.stderr, /EADDRINUSE/, `${name}: refusal precedes backend listen`);
        assert.equal(existsSync(dir), false, `${name}: no state directory`);
      } finally {
        killHard(child);
      }
    }
  } finally {
    await new Promise<void>((resolve, reject) =>
      occupied.close((error) => { if (error) reject(error); else resolve(); })
    );
    await rm(tmp, { recursive: true, force: true });
  }
});

test("integration — gateway occupied backend bind leaves no quickstart state", async () => {
  const tmp = await mkdtemp(join(tmpdir(), "mcp-sso-spawn-backend-bind-"));
  const dir = join(tmp, "state");
  const occupied = createServer();
  await new Promise<void>((resolve, reject) => {
    occupied.once("error", reject);
    occupied.listen(0, "127.0.0.1", resolve);
  });
  const address = occupied.address();
  assert.ok(address && typeof address === "object", "occupied backend has a TCP address");
  const env = childEnv({
    MCP_SSO_DIR: dir,
    HOST: "127.0.0.1",
    BACKEND_API_KEY: randomBytes(32).toString("base64url"),
    BACKEND_HOST: "127.0.0.1",
    BACKEND_PORT: String(address.port),
  });
  const child = spawn("node", [GATEWAY_ENTRY], { cwd: REPO, env, stdio: ["ignore", "pipe", "pipe"] });
  try {
    const exited = await waitForClose(child, 15_000);
    assert.notEqual(exited.code, 0, "occupied backend bind exits nonzero");
    assert.match(exited.stderr, /EADDRINUSE/);
    assert.equal(existsSync(dir), false, "backend bind failure precedes quickstart state creation");
  } finally {
    killHard(child);
    await new Promise<void>((resolve, reject) =>
      occupied.close((error) => { if (error) reject(error); else resolve(); })
    );
    await rm(tmp, { recursive: true, force: true });
  }
});

test("integration — gateway entrypoint rejects ambiguous providers before backend listen", async () => {
  const occupied = createServer();
  await new Promise<void>((resolve, reject) => {
    occupied.once("error", reject);
    occupied.listen(0, "127.0.0.1", resolve);
  });
  const address = occupied.address();
  assert.ok(address && typeof address === "object", "occupied backend has a TCP address");
  const env = childEnv({
    BACKEND_API_KEY: randomBytes(32).toString("base64url"),
    BACKEND_HOST: "127.0.0.1",
    BACKEND_PORT: String(address.port),
    ENTRA_TENANT_ID: "tenant-a",
    CF_ACCESS_AUDIENCE: "audience-b",
  });
  const child = spawn("node", [GATEWAY_ENTRY], { cwd: REPO, env, stdio: ["ignore", "pipe", "pipe"] });
  try {
    const exited = await waitForClose(child, 10_000);
    assert.notEqual(exited.code, 0, "ambiguous provider configuration exits nonzero");
    assert.match(exited.stderr, /exactly one identity provider selector may be present/);
    assert.doesNotMatch(exited.stderr, /EADDRINUSE/, "provider validation runs before the occupied backend port is used");
  } finally {
    killHard(child);
    await new Promise<void>((resolve, reject) =>
      occupied.close((error) => { if (error) reject(error); else resolve(); })
    );
  }
});

test("integration — gateway entrypoint rejects invalid redirect modes before backend listen or state", async () => {
  const tmp = await mkdtemp(join(tmpdir(), "mcp-sso-spawn-redirect-mode-"));
  const occupied = createServer();
  await new Promise<void>((resolve, reject) => {
    occupied.once("error", reject);
    occupied.listen(0, "127.0.0.1", resolve);
  });
  const address = occupied.address();
  assert.ok(address && typeof address === "object", "occupied backend has a TCP address");
  try {
    for (const [label, mode] of [["blank", ""], ["unknown", "Replace"]] as const) {
      const dir = join(tmp, label);
      const env = childEnv({
        MCP_SSO_DIR: dir,
        OAUTH_REDIRECT_ALLOWLIST_MODE: mode,
        BACKEND_API_KEY: randomBytes(32).toString("base64url"),
        BACKEND_HOST: "127.0.0.1",
        BACKEND_PORT: String(address.port),
      });
      const child = spawn("node", [GATEWAY_ENTRY], { cwd: REPO, env, stdio: ["ignore", "pipe", "pipe"] });
      try {
        const exited = await waitForClose(child, 10_000);
        assert.notEqual(exited.code, 0, `${label}: invalid redirect mode exits nonzero`);
        assert.match(exited.stderr, /redirectAllowlistMode must be "extend" or "replace"/);
        assert.doesNotMatch(exited.stderr, /EADDRINUSE/, `${label}: mode validation precedes backend listen`);
        assert.equal(existsSync(dir), false, `${label}: mode validation precedes state creation`);
      } finally {
        killHard(child);
      }
    }
  } finally {
    await new Promise<void>((resolve, reject) =>
      occupied.close((error) => { if (error) reject(error); else resolve(); })
    );
    await rm(tmp, { recursive: true, force: true });
  }
});

test("integration — gateway entrypoint rejects malformed proxy trust before backend listen or state", async () => {
  const tmp = await mkdtemp(join(tmpdir(), "mcp-sso-spawn-proxy-trust-"));
  const dir = join(tmp, "state");
  const occupied = createServer();
  await new Promise<void>((resolve, reject) => {
    occupied.once("error", reject);
    occupied.listen(0, "127.0.0.1", resolve);
  });
  const address = occupied.address();
  assert.ok(address && typeof address === "object", "occupied backend has a TCP address");
  const env = childEnv({
    MCP_SSO_DIR: dir,
    HOST: "127.0.0.1",
    MCP_SSO_TRUSTED_PROXIES: "not-an-ip",
    BACKEND_API_KEY: randomBytes(32).toString("base64url"),
    BACKEND_HOST: "127.0.0.1",
    BACKEND_PORT: String(address.port),
  });
  const child = spawn("node", [GATEWAY_ENTRY], { cwd: REPO, env, stdio: ["ignore", "pipe", "pipe"] });
  try {
    const exited = await waitForClose(child, 15_000);
    assert.notEqual(exited.code, 0, "malformed proxy trust exits nonzero");
    assert.match(exited.stderr, /trusted proxies must be 1\.\.32 unique IP or CIDR entries/);
    assert.doesNotMatch(exited.stderr, /EADDRINUSE/, "proxy validation precedes the occupied backend listener");
    assert.equal(existsSync(dir), false, "proxy validation precedes state creation");
  } finally {
    killHard(child);
    await new Promise<void>((resolve, reject) =>
      occupied.close((error) => { if (error) reject(error); else resolve(); })
    );
    await rm(tmp, { recursive: true, force: true });
  }
});
