// Tests for `mcp-sso init` (contracts §15 "Init CLI"). Three layers:
//  1. unit: the scaffolder writes the right files, refuses to clobber, parses the
//     `init` subcommand;
//  2. compile: the generated server.ts typechecks (tsc --noEmit, mcp-sso mapped to the
//     repo's src via paths — so a type error in the composition root fails here, even
//     though node's native TS would run it);
//  3. spawn (gated on dist): scaffold -> boot the generated server -> discovery +
//     register + /mcp 401+challenge (the automated done-bar: a stranger's
//     `npm i mcp-sso && npx mcp-sso init && npm install && npm start` boots a working
//     server; the full Claude Code client round-trip is the library's e2e-mcp-sdk test).

import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { run } from "../src/bin/init.ts";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const DIST_INIT = join(REPO, "dist", "bin", "init.js");
const hasDist = (): boolean => existsSync(DIST_INIT);

/** The compile + spawn tests need the BUILT dist (the generated server imports the
 *  `mcp-sso` package, whose exports point at ./dist; tsc/node won't follow .ts source).
 *  Build it if absent so these run in the plain `pnpm test` gate (which precedes build)
 *  — a one-time ~3s `tsc -p tsconfig.build.json`, not a side effect a consumer sees. */
async function ensureDist(): Promise<void> {
  if (hasDist()) return;
  const tsc = join(REPO, "node_modules", "typescript", "bin", "tsc");
  const res = await new Promise<{ code: number | null; out: string }>((resolveP) => {
    const p = spawn("node", [tsc, "-p", join(REPO, "tsconfig.build.json")], { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    const take = (c: Buffer): void => { out += c.toString(); };
    p.stdout.on("data", take); p.stderr.on("data", take);
    p.on("close", (code) => resolveP({ code, out }));
  });
  if (res.code !== 0) throw new Error(`bin-init: building dist for the compile/spawn tests failed (tsc exit ${res.code}):\n${res.out}`);
}

async function scaffold(target: string): Promise<string[]> {
  // run() reads its own version via new URL("../../package.json", import.meta.url)
  // — relative to src/bin/init.ts in dev, which resolves to the repo package.json.
  return run(["node", "init.ts", "init", target]);
}

test("bin init: scaffolds 4 files with a valid, exact-pinned package.json", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-init-unit-"));
  try {
    const written = await scaffold(dir);
    assert.deepEqual(written.sort(), [".gitignore", "README.md", "package.json", "server.ts"].sort());
    for (const f of written) assert.ok(existsSync(join(dir, f)), `${f} written`);

    const pkg = JSON.parse(await readFile(join(dir, "package.json"), "utf8")) as Record<string, unknown>;
    assert.equal(pkg.name, basename(dir), "name is the target dir basename");
    assert.equal(pkg.type, "module");
    assert.equal((pkg.scripts as { start: string }).start, "node server.ts");
    const deps = pkg.dependencies as Record<string, string>;
    assert.equal(deps["mcp-sso"], "0.2.2", "mcp-sso pinned to the running version");
    assert.equal(deps.fastify, "5.8.5", "fastify exact-pinned (no ^/~)");
    assert.equal(deps["@modelcontextprotocol/sdk"], "1.29.0", "MCP SDK exact-pinned");
    assert.ok(!/[\^~]/.test(Object.values(deps).join(" ")), "no version ranges — exact pins only");

    const server = await readFile(join(dir, "server.ts"), "utf8");
    for (const marker of ['from "mcp-sso"', "registerOAuthRoutes", "isMcpPath", "loadOrCreateQuickstartSecrets", "createConsolePairingIdentity", "handlePairingAuthorize"]) {
      assert.ok(server.includes(marker), `server.ts composition root includes ${marker}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("bin init: refuses to clobber an existing file (fail closed)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-init-clobber-"));
  try {
    await writeFile(join(dir, "README.md"), "mine\n"); // pre-existing consumer file
    await assert.rejects(scaffold(dir), /refusing to overwrite.*README\.md/);
    // The pre-existing file is untouched; no other file was written.
    assert.equal(await readFile(join(dir, "README.md"), "utf8"), "mine\n");
    assert.equal(existsSync(join(dir, "package.json")), false, "no partial scaffold");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("bin init: the literal `init` subcommand is required", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-init-subcmd-"));
  try {
    await assert.rejects(run(["node", "init.ts", "generate", dir]), /unknown subcommand "generate"/);
    const written = await run(["node", "init.ts", "init", dir]); // the supported subcommand
    assert.ok(written.includes("package.json"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("bin init: the generated server.ts typechecks against the built package (tsc --noEmit)", async () => {
  // The generated server.ts imports `mcp-sso` (the package), so type-checking it needs
  // the built .d.ts — the package's exports point at ./dist, and tsc (nodenext) won't
  // follow exports targets that are .ts source. A node_modules/mcp-sso symlink to the
  // repo resolves the real exports to the built declarations.
  await ensureDist();
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-compile-"));
  const proj = join(base, "proj");
  try {
    await spawnScaffold(proj);
    await linkDeps(proj);
    const tsconfig = {
      compilerOptions: {
        module: "nodenext", moduleResolution: "nodenext", target: "ES2023", lib: ["ES2023"],
        strict: true, noEmit: true, skipLibCheck: true, types: ["node"],
      },
      include: ["server.ts"],
    };
    await writeFile(join(proj, "tsconfig.json"), JSON.stringify(tsconfig, null, 2));
    const tsc = join(REPO, "node_modules", "typescript", "bin", "tsc");
    const res = await new Promise<{ code: number | null; out: string }>((resolveP) => {
      const p = spawn("node", [tsc, "--noEmit", "-p", join(proj, "tsconfig.json")], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      const take = (c: Buffer): void => { out += c.toString(); };
      p.stdout.on("data", take); p.stderr.on("data", take);
      p.on("close", (code) => resolveP({ code, out }));
    });
    assert.equal(res.code, 0, `generated server.ts must typecheck against the built package; tsc output:\n${res.out}`);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

// --- spawn layer (the done-bar) — gated on dist (the test gate runs before build) ---

function freePort(): Promise<number> {
  return new Promise((resolveP, reject) => {
    const s = createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      if (addr && typeof addr === "object") { const port = addr.port; s.close(() => resolveP(port)); }
      else { s.close(); reject(new Error("could not bind")); }
    });
  });
}

function waitFor(child: ChildProcess, regex: RegExp, timeoutMs: number): Promise<string> {
  return new Promise((resolveP, reject) => {
    let buf = "";
    const onStderr = (c: Buffer | string): void => { buf += c.toString(); if (regex.test(buf)) finish(undefined); };
    const onExit = (): void => finish(new Error(`child exited before ${regex}; stderr:\n${buf.slice(-1500)}`));
    let timer: NodeJS.Timeout | undefined = setTimeout(() => finish(new Error(`timed out waiting for ${regex}; stderr:\n${buf.slice(-1500)}`)), timeoutMs);
    function finish(err?: Error): void { if (timer) { clearTimeout(timer); timer = undefined; } child.stderr?.off("data", onStderr); child.off("exit", onExit); if (err) reject(err); else resolveP(buf); }
    child.stderr?.on("data", onStderr);
    child.on("exit", onExit);
  });
}

test("bin init (spawn): scaffolded server boots + serves discovery/register/mcp challenge", async () => {
  await ensureDist();
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-spawn-"));
  const proj = join(base, "proj");
  const dir = join(base, "state"); // does NOT exist — loadOrCreateQuickstartSecrets creates it
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  try {
    await spawnScaffold(proj); // node dist/bin/init.js init <proj>
    await linkDeps(proj);      // node_modules/{mcp-sso,fastify,@modelcontextprotocol} → repo
    const child = spawn("node", ["server.ts"], {
      cwd: proj,
      env: { ...process.env, MCP_SSO_DIR: dir, PORT: String(port), HOST: "127.0.0.1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    try {
      await waitFor(child, new RegExp(`mcp-sso listening on 127.0.0.1:${port}`), 15_000);
      const prm = await fetch(`${origin}/.well-known/oauth-protected-resource`, { signal: AbortSignal.timeout(10_000) });
      assert.equal(prm.status, 200, "PRM discovery served");
      const reg = await fetch(`${origin}/oauth/register`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["http://localhost:4321/callback"] }),
        signal: AbortSignal.timeout(10_000),
      });
      assert.equal(reg.status, 201, "DCR register works");
      assert.match((await reg.json() as { client_id: string }).client_id, /^mcpdc_/, "real client_id");
      const mcp = await fetch(`${origin}/mcp`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "initialize", id: 1 }),
        signal: AbortSignal.timeout(10_000),
      });
      assert.equal(mcp.status, 401, "tokenless /mcp → 401");
      assert.match(mcp.headers.get("www-authenticate") ?? "", /^Bearer resource_metadata=/, "RFC 9728 challenge");
    } finally {
      if (child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL"); }
    }
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init: the published bin has a node shebang (npx exec needs it)", async () => {
  await ensureDist();
  const firstLine = (await readFile(DIST_INIT, "utf8")).split("\n")[0];
  assert.equal(firstLine, "#!/usr/bin/env node", "dist/bin/init.js must start with a node shebang so `npx mcp-sso init` can exec it");
});

test("bin init: runs when invoked through a symlink (npm exposes bins via symlinks)", async () => {
  // P1 regression: import.meta.url resolves to the real file while process.argv[1]
  // retains npm's .bin symlink; the entry guard must realpath both sides.
  await ensureDist();
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-symlink-"));
  const link = join(base, "mcp-sso"); // mimics node_modules/.bin/mcp-sso
  const proj = join(base, "proj");
  try {
    await symlink(DIST_INIT, link);
    const res = await new Promise<{ code: number | null; out: string }>((resolveP) => {
      const p = spawn("node", [link, "init", proj], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      const take = (c: Buffer): void => { out += c.toString(); };
      p.stdout.on("data", take); p.stderr.on("data", take);
      p.on("close", (code) => resolveP({ code, out }));
    });
    assert.equal(res.code, 0, `symlink invocation failed (isMain must match under a symlink); output:\n${res.out}`);
    assert.ok(existsSync(join(proj, "package.json")), "symlink-invoked bin scaffolded the project");
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init: refuses a symlink in the target (no write outside the target via O_NOFOLLOW)", { skip: process.platform === "win32" }, async () => {
  // P2 regression: a pre-existing dangling symlink at a scaffold path would let a
  // check-then-write follow it and write outside the target. writeExclusive (O_NOFOLLOW)
  // refuses it — the hard enforcement behind the access() pre-check's best-effort UX.
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-symlinktarget-"));
  const target = join(base, "proj");
  try {
    await mkdir(target, { recursive: true });
    await symlink(join(base, "elsewhere.txt"), join(target, "server.ts")); // dangling symlink at a scaffold path
    await assert.rejects(scaffold(target), /symlink/, "a symlink at a scaffold path is refused, not followed");
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

async function spawnScaffold(proj: string): Promise<void> {
  await mkdir(proj, { recursive: true });
  const res = await new Promise<{ code: number | null; stderr: string }>((resolveP) => {
    const p = spawn("node", [DIST_INIT, "init", proj], { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    p.stderr.on("data", (c: Buffer) => { stderr += c.toString(); });
    p.on("close", (code) => resolveP({ code, stderr }));
  });
  assert.equal(res.code, 0, `init scaffold failed; stderr:\n${res.stderr}`);
}

/** Link the repo's mcp-sso + fastify + the MCP SDK + @types into the scaffolded project
 *  so `import "mcp-sso"` etc. resolve WITHOUT an npm install (the generated package.json
 *  pins them; a real consumer runs `npm install`). mcp-sso → the repo, so its exports
 *  resolve to the BUILT dist (the test gate runs after `pnpm build`, or skips via hasDist). */
async function linkDeps(proj: string): Promise<void> {
  const nm = join(proj, "node_modules");
  await mkdir(nm, { recursive: true });
  await symlink(REPO, join(nm, "mcp-sso"));
  await symlink(join(REPO, "node_modules", "fastify"), join(nm, "fastify"));
  await symlink(join(REPO, "node_modules", "@modelcontextprotocol"), join(nm, "@modelcontextprotocol"));
  await symlink(join(REPO, "node_modules", "@types"), join(nm, "@types"));
}

async function symlink(target: string, linkPath: string): Promise<void> {
  const { symlink } = await import("node:fs/promises");
  try { await symlink(target, linkPath, "dir"); } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
}
