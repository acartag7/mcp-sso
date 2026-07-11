#!/usr/bin/env node
// `mcp-sso init [target]` — scaffold a zero-setup MCP server (contracts §15 "Init CLI").
// Dep-free (node builtins only). Fail closed: refuse to overwrite an existing file.
//
// The shebang above MUST be the first line: npm exposes this as the package `bin`, so
// `npx mcp-sso init` executes dist/bin/init.js directly (npm chmods it executable on
// install); without the shebang the OS cannot launch it under node. tsc preserves it.

import { lstat, mkdir, open } from "node:fs/promises";
import { constants as fsc, readFileSync, realpathSync } from "node:fs";
import { basename, join, parse, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { templateFiles } from "./templates.ts";

// O_NOFOLLOW refuses a symlink (dangling or not — no write outside the target via a
// symlink); O_EXCL fails if the path already exists; O_CREAT creates. Atomic + no-follow
// + no-clobber — the HARD enforcement behind "refuses to overwrite" (the lstat pre-check
// lists all conflicts up front; this closes the check-then-write race). POSIX-only (0 on
// Windows, where the lstat pre-check still catches symlinks).
const O_NOFOLLOW = (fsc as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0;
const EXCLUSIVE_CREATE = O_NOFOLLOW | fsc.O_CREAT | fsc.O_EXCL | fsc.O_WRONLY;

const HELP = `mcp-sso init [target]

Scaffold a zero-setup MCP server (console pairing) into <target> (default: the current
directory). Then: \`npm install && npm start\`, and pair with the printed one-time code.

The generated server is the starting point. For a real identity provider, see the
README it generates + https://github.com/acartag7/mcp-sso/tree/main/examples/fastify-sqlite.`;

/** Read the mcp-sso version this binary is running as (dist/bin/init.js → the package
 *  root package.json), so the generated package.json pins mcp-sso at that exact version. */
function ownVersion(): string {
  const pkgUrl = new URL("../../package.json", import.meta.url);
  const pkg = JSON.parse(readFileSync(fileURLToPath(pkgUrl), "utf8")) as { version?: string };
  if (typeof pkg.version !== "string" || !pkg.version) throw new Error("mcp-sso init: cannot determine the mcp-sso version");
  return pkg.version;
}

function parseArgs(argv: string[]): { target: string; help: boolean } {
  const args = argv.slice(2); // drop node + script
  // `mcp-sso init [target]` — the literal subcommand is "init" (so `npx mcp-sso init`
  // works; the bin is named "mcp-sso"). Bare `npx mcp-sso` or -h/--help → help.
  if (args.length === 0 || args.includes("-h") || args.includes("--help")) return { target: ".", help: true };
  if (args[0] !== "init") throw new Error(`unknown subcommand "${args[0]}" — try "mcp-sso init [target]"`);
  return { target: args[1] ?? ".", help: false };
}

async function exists(path: string): Promise<boolean> {
  // lstat (NO-follow): a symlink (dangling or not) counts as existing, so the pre-check
  // refuses it up front — no partial scaffold before writeExclusive's O_NOFOLLOW kicks in.
  try { await lstat(path); return true; } catch { return false; }
}

/** Refuse a symlinked ANCESTOR of the target whose parent is group/other-writable (the
 *  attacker-swappable class): `mkdir -p` would follow it, writing outside the lexical
 *  target. System symlinks under a root/owner-owned parent (e.g. macOS /tmp→/private/tmp,
 *  /var→/private/var) are ALLOWED — an attacker can't replace them, so refusing them would
 *  be a false positive on a normal temp-dir scaffold. POSIX-only. */
async function assertNoAttackerSymlinkAncestor(dir: string): Promise<void> {
  if (process.platform === "win32") return;
  const { root } = parse(dir);
  let current = root;
  for (const seg of dir.slice(root.length).split(sep).filter(Boolean)) {
    const parent = current;
    current = join(current, seg);
    let st;
    try { st = await lstat(current); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return; throw error; } // rest doesn't exist yet
    if (st.isSymbolicLink() && ((await lstat(parent)).mode & 0o022)) {
      throw new Error(`${current} is a symlink inside a group/other-writable directory (${parent}); mcp-sso init refuses to scaffold through it (write-redirection risk). Point it at a real directory.`);
    }
  }
}

/** POSIX shell-escape a path for safe copy-paste in a printed command: single-quote +
 *  escape embedded single quotes. Survives spaces, `"`, `$()`, backticks, and `'`. */
function shellQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

/** Atomically create `path` with `content`, refusing to overwrite or follow a symlink. */
async function writeExclusive(path: string, content: string): Promise<void> {
  let fh;
  try {
    fh = await open(path, EXCLUSIVE_CREATE, 0o644);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "EEXIST") throw new Error(`refusing to overwrite existing file: ${path}`);
    if (code === "ELOOP") throw new Error(`refusing to follow a symlink at ${path} (scaffold target must be a real directory)`);
    throw error;
  }
  try { await fh.writeFile(content, "utf8"); }
  finally { await fh.close(); }
}

/** The scaffolder, factored out so tests call it directly (no process.exit). Writes the
 *  template files into `target`, refusing to clobber any pre-existing file. Throws on
 *  conflict or version-resolution failure. */
export async function run(argv: string[]): Promise<string[]> {
  const { target, help } = parseArgs(argv);
  if (help) { console.log(HELP); return []; }
  const dir = resolve(target);
  // Refuse a symlinked TARGET dir: O_NOFOLLOW protects only the final file component,
  // not the target dir itself, so writes would follow a symlinked target out of it.
  try {
    if ((await lstat(dir)).isSymbolicLink()) {
      throw new Error(`${dir} is a symlink; point mcp-sso init at a real directory (writes must not follow the target).`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; // ENOENT is fine — mkdir creates it
  }
  await assertNoAttackerSymlinkAncestor(dir);
  const name = basename(dir) || "mcp-sso-server";
  const files = templateFiles({ mcpSsoVersion: ownVersion(), name });

  // Best-effort UX: list ALL conflicts up front so the operator sees every clash, not
  // just the first. (writeExclusive is the hard, atomic enforcement that closes the race.)
  const conflicts = (await Promise.all(files.map(async (f) => ({ path: f.path, exists: await exists(resolve(dir, f.path)) }))))
    .filter((x) => x.exists).map((x) => x.path);
  if (conflicts.length > 0) {
    throw new Error(`refusing to overwrite existing file(s) in ${dir}: ${conflicts.join(", ")} — move them aside or pick an empty target.`);
  }

  await mkdir(dir, { recursive: true });
  const written: string[] = [];
  for (const f of files) {
    await writeExclusive(resolve(dir, f.path), f.content);
    written.push(f.path);
  }

  console.log(`mcp-sso init: wrote ${files.length} files to ${dir}:`);
  for (const f of files) console.log(`  ${f.path}`);
  console.log(`\nNext:\n  cd ${shellQuote(dir)}\n  npm install\n  npm start        # terminal 1 — the server (stays foreground)\n  # in ANOTHER terminal (server running) — it prints a one-time code when a client connects:\n  claude mcp add --transport http my-bridge http://127.0.0.1:3000/mcp\n  # the server prints the code to terminal 1; a browser opens — paste the code, approve.`);
  return written;
}

/** Entry detection that survives npm's bin symlink: resolve BOTH sides to their real
 *  path (import.meta.url is the real module; process.argv[1] is the symlink npm exec'd). */
function isMain(): boolean {
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1] ?? "");
  } catch {
    return false; // don't auto-run when imported (e.g. by a test) or on an odd invocation
  }
}

if (isMain()) {
  run(process.argv).catch((error) => { console.error((error as Error)?.message ?? String(error)); process.exit(1); });
}
