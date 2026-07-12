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
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { pkceChallenge } from "../src/crypto.ts";
import { run } from "../src/bin/init.ts";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const DIST_INIT = join(REPO, "dist", "bin", "init.js");

/** The compile + spawn tests need the BUILT dist (the generated server imports the
 *  `mcp-sso` package, whose exports point at ./dist; tsc/node won't follow .ts source).
 *  Build it ONCE per test process — always fresh, never the stale dist a developer may
 *  have left from a prior edit (the test gate runs before `pnpm build`, so building here
 *  is what makes these tests exercise the CURRENT source). */
let distEnsured = false;
async function ensureDist(): Promise<void> {
  if (distEnsured) return;
  distEnsured = true;
  // Clean build (rm dist first, like `pnpm build`): a bare `tsc` overwrites current
  // outputs but leaves stale files from deleted source modules, which could let a
  // removed subpath still resolve locally. Start from a clean dist.
  await rm(join(REPO, "dist"), { recursive: true, force: true });
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

test("bin init: scaffolds 5 files with a valid, exact-pinned package.json", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-init-unit-"));
  try {
    const written = await scaffold(dir);
    assert.deepEqual(written.sort(), [".gitignore", ".npmrc", "README.md", "package.json", "server.ts"].sort());
    for (const f of written) assert.ok(existsSync(join(dir, f)), `${f} written`);

    const pkg = JSON.parse(await readFile(join(dir, "package.json"), "utf8")) as Record<string, unknown>;
    assert.equal(pkg.name, basename(dir), "name is the target dir basename");
    assert.equal(pkg.type, "module");
    assert.equal((pkg.scripts as { start: string }).start, "node server.ts");
    const deps = pkg.dependencies as Record<string, string>;
    // The generated pins must MATCH the repo's own versions (the template hardcodes
    // fastify/SDK; assert they track the repo's devDeps so a bump can't silently leave
    // the scaffold on untested versions — and doesn't go stale on an mcp-sso bump).
    const repoPkg = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as { version: string; devDependencies: Record<string, string> };
    assert.equal(deps["mcp-sso"], repoPkg.version, "mcp-sso pinned to the running (repo) version");
    assert.equal(deps.fastify, repoPkg.devDependencies.fastify, "fastify pinned to the repo's tested devDependency");
    assert.equal(deps["@modelcontextprotocol/sdk"], repoPkg.devDependencies["@modelcontextprotocol/sdk"], "MCP SDK pinned to the repo's tested devDependency");
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

test("bin init: the printed `cd` is POSIX shell-escaped (spaces + metacharacters)", async () => {
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-shellquote-"));
  const target = join(base, "My Server"); // a space — unquoted `cd` would split here
  try {
    const orig = console.log;
    let captured = "";
    console.log = ((s: string) => { captured += s; }) as typeof console.log;
    try { await run(["node", "init.ts", "init", target]); }
    finally { console.log = orig; }
    assert.ok(captured.includes(`cd '${target}'`), "the cd target is single-quoted (POSIX shell-escape), safe for spaces/metacharacters");
  } finally {
    await rm(base, { recursive: true, force: true });
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

test("bin init (spawn): full pairing round-trip — register → code → consent → token → SDK callTool", async () => {
  // The automated done-bar: a stranger's `npx mcp-sso init && npm install && npm start`
  // boots a server an operator pairs with via a console code, then an MCP client calls a
  // protected tool. Drives the WHOLE flow (not just the tokenless challenge) through the
  // OFFICIAL SDK client against the spawned generated server.
  await ensureDist();
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-spawn-"));
  const proj = join(base, "proj");
  const stateDir = join(base, "state");
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  const redirect = "http://localhost:4321/callback";
  const subject = "console-operator"; // the default pairing subject
  try {
    await spawnScaffold(proj);
    await linkDeps(proj);
    const child = spawn("node", ["server.ts"], {
      cwd: proj,
      // No OAUTH_ISSUER override: the default is http://127.0.0.1:PORT (matches the HOST
      // bind), so the test exercises the real default config, not a masked one.
      env: { ...process.env, MCP_SSO_DIR: stateDir, PORT: String(port), HOST: "127.0.0.1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderrBuf = "";
    child.stderr?.on("data", (c: Buffer) => { stderrBuf += c.toString(); });
    try {
      await waitFor(child, new RegExp(`mcp-sso listening on 127.0.0.1:${port}`), 15_000);

      // discovery + register
      const prm = await fetchBounded(`${origin}/.well-known/oauth-protected-resource`);
      assert.equal(prm.status, 200, "PRM discovery served");
      const reg = await fetchBounded(`${origin}/oauth/register`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: [redirect] }),
      });
      assert.equal(reg.status, 201, "DCR register works");
      const clientId = (await reg.json() as { client_id: string }).client_id;
      assert.match(clientId, /^mcpdc_/, "real client_id");

      // GET /oauth/authorize → the server prints the pairing code to stderr + returns the page
      const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
      const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirect, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "s1" });
      const authPage = await fetchBounded(`${origin}/oauth/authorize?${q}`);
      assert.equal(authPage.status, 200);
      const authHtml = await authPage.text();
      const nonce = extractField(authHtml, "pairing_nonce");
      const code = extractCode(stderrBuf); // printed by the GET (lazy, on /oauth/authorize)
      assert.ok(code, "the server printed a pairing code after /oauth/authorize");

      // POST the code → consent page; approve → auth code; exchange → access token
      const consentPage = await fetchBounded(`${origin}/oauth/authorize`, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ ...Object.fromEntries(q), pairing_code: code, pairing_nonce: nonce }).toString(),
      });
      assert.equal(consentPage.status, 200, "code accepted → consent page");
      const consentToken = extractField(await consentPage.text(), "consent_token");
      const approve = await fetchBounded(`${origin}/oauth/authorize/approve`, {
        method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", origin: origin },
        body: new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString(),
      });
      assert.equal(approve.status, 302, "approve → 302 with an auth code");
      const authCode = new URL(approve.headers.get("location") ?? "").searchParams.get("code");
      assert.ok(authCode, "auth code in the redirect");
      const tokenResp = await fetchBounded(`${origin}/oauth/token`, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code: authCode as string, redirect_uri: redirect, client_id: clientId, code_verifier: verifier }).toString(),
      });
      assert.equal(tokenResp.status, 200, "token exchange");
      const accessToken = (await tokenResp.json() as { access_token: string }).access_token;

      // The protected /mcp via the OFFICIAL MCP SDK client with the bridge-minted token.
      const transport = new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), { requestInit: { headers: { authorization: `Bearer ${accessToken}` } } });
      const client = new Client({ name: "init-done-bar", version: "0.0.1" }, { capabilities: {} });
      try {
        await withTimeout(client.connect(transport), 10_000, "MCP client connect");
        const result = await withTimeout(client.callTool({ name: "ping", arguments: {} }), 10_000, "MCP client callTool");
        const text = (result.content as Array<{ type: string; text?: string }>).find((c) => c.type === "text")?.text;
        assert.equal(text, `pong: ${subject}`, "the pairing-resolved subject reached the protected tool — full round-trip");
      } finally {
        await client.close();
        await transport.close();
      }

      // Tokenless /mcp is still 401 + the RFC 9728 challenge (the resource-server leg).
      const mcp = await fetchBounded(`${origin}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", method: "initialize", id: 1 }) });
      assert.equal(mcp.status, 401);
      assert.match(mcp.headers.get("www-authenticate") ?? "", /^Bearer resource_metadata=/);
    } finally {
      if (child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL"); }
    }
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init (spawn): a blank HOST binds loopback (fail-closed on blank env — NOT 0.0.0.0)", async () => {
  // P1 regression: HOST="" must not fall through `??` to Node as "bind all interfaces",
  // which would expose the one-time pairing code to the network. The generated server
  // treats a blank env value as missing → the loopback default.
  await ensureDist();
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-blankhost-"));
  const proj = join(base, "proj");
  const stateDir = join(base, "state");
  const port = await freePort();
  try {
    await spawnScaffold(proj);
    await linkDeps(proj);
    const child = spawn("node", ["server.ts"], {
      cwd: proj,
      env: { ...process.env, MCP_SSO_DIR: stateDir, PORT: String(port), HOST: "" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    try {
      await waitFor(child, new RegExp(`mcp-sso listening on 127\\.0\\.0\\.1:${port}`), 15_000);
    } finally {
      if (child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL"); }
    }
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init (spawn): PORT=0 fails closed at boot (not an unusable ephemeral bind)", async () => {
  await ensureDist();
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-port0-"));
  const proj = join(base, "proj");
  const stateDir = join(base, "state");
  try {
    await spawnScaffold(proj);
    await linkDeps(proj);
    const child = spawn("node", ["server.ts"], {
      cwd: proj,
      env: { ...process.env, MCP_SSO_DIR: stateDir, PORT: "0", HOST: "127.0.0.1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr?.on("data", (c: Buffer) => { stderr += c.toString(); });
    const code = await new Promise<number | null>((resolveP) => child.on("close", (c) => resolveP(c)));
    assert.notEqual(code, 0, "PORT=0 fails closed (non-zero exit), not an ephemeral bind with port-0 URLs");
    assert.match(stderr, /PORT must be an integer in 1/);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init (spawn): HOST off-loopback without OAUTH_ISSUER warns about the issuer mismatch", async () => {
  await ensureDist();
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-hostwarn-"));
  const proj = join(base, "proj");
  const stateDir = join(base, "state");
  const port = await freePort();
  try {
    await spawnScaffold(proj);
    await linkDeps(proj);
    const child = spawn("node", ["server.ts"], {
      cwd: proj,
      // HOST off loopback, OAUTH_ISSUER intentionally UNSET → the advertised issuer
      // (127.0.0.1) won't match the host clients reach (RFC 9728 resource validation).
      env: { ...process.env, MCP_SSO_DIR: stateDir, PORT: String(port), HOST: "0.0.0.0" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    try {
      const stderr = await waitFor(child, /OAUTH_ISSUER is unset/, 15_000);
      assert.match(stderr, /HOST=0\.0\.0\.0 but OAUTH_ISSUER is unset/, "off-loopback HOST without OAUTH_ISSUER warns about the mismatch");
    } finally {
      if (child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL"); }
    }
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init: refuses a symlinked ancestor in a group/other-writable dir (write-redirection risk)", { skip: process.platform === "win32" }, async () => {
  // The attacker-controllable class: a symlinked ANCESTOR whose parent is group/other-
  // writable (an attacker could swap it). mkdir -p would follow it → write outside the
  // lexical target. (A system symlink under a root-owned parent — e.g. macOS /tmp — is
  // ALLOWED, not a false positive.)
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-anceslink-"));
  const writable = join(base, "writable"); // → 0777
  const link = join(writable, "link"); // symlink → elsewhere
  const target = join(link, "proj"); // scaffold THROUGH the symlinked ancestor
  try {
    await mkdir(writable, { mode: 0o777 });
    await chmod(writable, 0o777);
    await symlink(join(base, "elsewhere"), link);
    await assert.rejects(run(["node", "init.ts", "init", target]), /write-redirection risk/, "a symlinked ancestor in a writable dir is refused");
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init (spawn): a trailing slash on OAUTH_ISSUER is trimmed (resource is /mcp, not //mcp)", async () => {
  await ensureDist();
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-slash-"));
  const proj = join(base, "proj");
  const stateDir = join(base, "state");
  const port = await freePort();
  try {
    await spawnScaffold(proj);
    await linkDeps(proj);
    const child = spawn("node", ["server.ts"], {
      cwd: proj,
      env: { ...process.env, MCP_SSO_DIR: stateDir, PORT: String(port), HOST: "127.0.0.1", OAUTH_ISSUER: `http://127.0.0.1:${port}/` }, // trailing slash
      stdio: ["ignore", "pipe", "pipe"],
    });
    try {
      await waitFor(child, new RegExp(`mcp-sso listening on 127\\.0\\.0\\.1:${port}`), 15_000);
      // Assert on the ADVERTISED PRM resource (what clients see), not the boot log line
      // (which prints a tick after "listening" and races under suite load).
      const prm = await fetchBounded(`http://127.0.0.1:${port}/.well-known/oauth-protected-resource`);
      assert.equal(prm.status, 200);
      assert.equal((await prm.json() as { resource: string }).resource, `http://127.0.0.1:${port}/mcp`, "the advertised PRM resource is /mcp (the trailing slash on OAUTH_ISSUER was trimmed, not //mcp)");
    } finally {
      if (child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL"); }
    }
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init: refuses a MISSING segment under a group/other-writable parent (closes the create-race TOCTOU)", { skip: process.platform === "win32" }, async () => {
  // The path walk returns at the first missing segment; if that segment's parent is
  // group/other-writable, an attacker could race-create it as a symlink before mkdir.
  // Refuse outright (the pre-check can't otherwise close that window).
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-missing-"));
  const writable = join(base, "writable"); // → 0777
  const target = join(writable, "new", "proj"); // 'new' is missing under the writable parent
  try {
    await mkdir(writable, { mode: 0o777 });
    await chmod(writable, 0o777);
    await assert.rejects(run(["node", "init.ts", "init", target]), /group\/other-writable parent/, "a missing segment under a writable parent is refused (closes the create-race)");
    assert.equal(existsSync(join(writable, "new")), false, "nothing created under the writable parent");
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init: refuses an existing real dir under a writable NON-STICKY parent (swap race)", { skip: process.platform === "win32" }, async () => {
  // The P1 race: an existing real dir under a group/other-writable + non-sticky parent can
  // be deleted+swapped for a symlink after the check. Sticky parents (e.g. /tmp) protect
  // owned entries, so this targets the non-sticky case specifically.
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-nonsticky-"));
  const writable = join(base, "writable"); // → 0777 (non-sticky)
  const existing = join(writable, "existing"); // a real dir under the non-sticky writable parent
  const target = join(existing, "proj");
  try {
    await mkdir(writable, { mode: 0o777 });
    await chmod(writable, 0o777); // non-sticky
    await mkdir(existing); // a real dir under the writable parent
    await assert.rejects(run(["node", "init.ts", "init", target]), /could be swapped for a symlink/, "an existing real dir under a writable non-sticky parent is refused (swap race)");
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init (spawn): a malformed OAUTH_ISSUER fails BEFORE the state dir is created", async () => {
  // Validate-before-side-effects: a malformed issuer rejects at URL validation, not after
  // loadOrCreateQuickstartSecrets writes the state dir + signing secrets.
  await ensureDist();
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-badissuer-"));
  const proj = join(base, "proj");
  const stateDir = join(base, "state");
  try {
    await spawnScaffold(proj);
    await linkDeps(proj);
    const child = spawn("node", ["server.ts"], {
      cwd: proj,
      env: { ...process.env, MCP_SSO_DIR: stateDir, PORT: "3000", HOST: "127.0.0.1", OAUTH_ISSUER: "not-a-url" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr?.on("data", (c: Buffer) => { stderr += c.toString(); });
    const code = await new Promise<number | null>((resolveP) => child.on("close", (c) => resolveP(c)));
    assert.notEqual(code, 0, "a malformed OAUTH_ISSUER fails closed");
    assert.match(stderr, /OAUTH_ISSUER is not a valid URL/);
    assert.equal(existsSync(stateDir), false, "the state dir was NOT created (validation ran before the state-creating helper)");
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init: refuses a missing descendant through a symlink into a writable destination (macOS /tmp→/private/tmp shape)", { skip: process.platform === "win32" }, async () => {
  // A trusted symlink ancestor (under a non-writable parent) that points into a writable
  // destination: the walk must check the DESTINATION's writability (stat follows the
  // symlink), or a missing descendant could be raced in at the writable destination.
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-destlink-"));
  const dest = join(base, "dest"); // → 0777 (the writable destination)
  const link = join(base, "link"); // symlink → dest (trusted: under the owner-only base)
  const target = join(link, "newproj"); // missing descendant through the symlink
  try {
    await mkdir(dest, { mode: 0o777 });
    await chmod(dest, 0o777);
    await symlink(dest, link);
    await assert.rejects(run(["node", "init.ts", "init", target]), /group\/other-writable parent/, "a missing descendant through a symlink into a writable destination is refused");
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init: refuses a pre-existing group/other-writable target dir (file-swap risk)", { skip: process.platform === "win32" }, async () => {
  // The target dir's OWN mode (the ancestor walk checks parents): a group/other-writable
  // target lets another user unlink+swap the scaffolded files. A just-created target is
  // 0700 (passes); a pre-existing 0777 target is refused.
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-writabletarget-"));
  const target = join(base, "target"); // → 0777
  try {
    await mkdir(target, { mode: 0o777 });
    await chmod(target, 0o777);
    await assert.rejects(run(["node", "init.ts", "init", target]), /group\/other-writable.*another user could swap the files/, "a group/other-writable target dir is refused");
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

function extractField(html: string, name: string): string {
  const m = new RegExp(`name="${name}" value="([^"]+)"`).exec(html);
  assert.ok(m?.[1], `hidden field ${name} not found`);
  return m![1];
}

function extractCode(stderr: string): string | undefined {
  const m = /\[mcp-sso\] Console pairing code: ([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})/.exec(stderr);
  return m?.[1];
}

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolveP, rejectP) => {
    const t = setTimeout(() => rejectP(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then((v) => { clearTimeout(t); resolveP(v); }, (e) => { clearTimeout(t); rejectP(e); });
  });
}

async function fetchBounded(url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(10_000) });
}

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
    await assert.rejects(scaffold(target), /refusing to overwrite.*server\.ts/, "a symlink at a scaffold path is refused up front (lstat no-follow), not followed");
    assert.equal(existsSync(join(target, "package.json")), false, "no partial scaffold — nothing written before the refusal");
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("bin init: refuses a symlinked target directory (writes must not follow it)", { skip: process.platform === "win32" }, async () => {
  // O_NOFOLLOW protects only the final file component, not the target dir itself — so a
  // symlinked target would let writes follow it into the real dir. lstat the target.
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-init-symlinktargetdir-"));
  const real = join(base, "real");
  const link = join(base, "link"); // symlink → an empty real dir
  try {
    await mkdir(real);
    await symlink(real, link);
    await assert.rejects(run(["node", "init.ts", "init", link]), /symlink; point mcp-sso init at a real directory/);
    assert.equal(existsSync(join(real, "package.json")), false, "nothing written through the symlinked target");
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
