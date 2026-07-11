// `mcp-sso init [target]` — scaffold a zero-setup MCP server (contracts §15 "Init CLI").
// Dep-free (node builtins only). Fail closed: refuse to overwrite an existing file.

import { access, mkdir, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { templateFiles } from "./templates.ts";

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
  try { await access(path); return true; } catch { return false; }
}

/** The scaffolder, factored out so tests call it directly (no process.exit). Writes the
 *  template files into `target`, refusing to clobber any pre-existing file. Throws on
 *  conflict or version-resolution failure. */
export async function run(argv: string[]): Promise<string[]> {
  const { target, help } = parseArgs(argv);
  if (help) { console.log(HELP); return []; }
  const dir = resolve(target);
  const name = basename(dir) || "mcp-sso-server";
  const files = templateFiles({ mcpSsoVersion: ownVersion(), name });

  // Fail closed: refuse to overwrite ANY existing file (never clobber a consumer's work).
  const conflicts = (await Promise.all(files.map(async (f) => ({ path: f.path, exists: await exists(resolve(dir, f.path)) }))))
    .filter((x) => x.exists).map((x) => x.path);
  if (conflicts.length > 0) {
    throw new Error(`refusing to overwrite existing file(s) in ${dir}: ${conflicts.join(", ")} — move them aside or pick an empty target.`);
  }

  await mkdir(dir, { recursive: true });
  const written: string[] = [];
  for (const f of files) {
    await writeFile(resolve(dir, f.path), f.content, "utf8");
    written.push(f.path);
  }

  console.log(`mcp-sso init: wrote ${files.length} files to ${dir}:`);
  for (const f of files) console.log(`  ${f.path}`);
  console.log(`\nNext:\n  cd ${dir}\n  npm install\n  npm start  # paste the printed one-time code, then:\n  claude mcp add --transport http my-bridge http://localhost:3000/mcp`);
  return written;
}

// Entry: run only when invoked as the bin (not when imported by a test).
const invokedDirectly = import.meta.url === pathToFileURL(process.argv[1] ?? "").href;
if (invokedDirectly) {
  run(process.argv).catch((error) => { console.error((error as Error)?.message ?? String(error)); process.exit(1); });
}
