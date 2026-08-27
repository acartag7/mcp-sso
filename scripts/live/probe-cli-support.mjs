// Pure support for scripts/live/probe-cli.mjs: which CLI, how it starts an
// authorization, how its output is read, and what the served leg's audit must
// show afterwards. Nothing here spawns a process.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

/** How a CLI may identify itself. A client chooses between the spec's two
 *  paths at run time, so a row states which paths are that CLI's and binds the
 *  one it used to the audit event that path must produce: a CIMD `client_id`
 *  with no document fetch, or a dynamic id with no registration, is a client
 *  identifying as something it did not do. */
export const CLIS = Object.freeze({
  claude: {
    binary: "claude",
    /** Claude Code identifies through its published CIMD document. */
    identities: [{ path: "cimd", clientIdShape: /^https:\/\/claude\.ai\/oauth\/claude-code-client-metadata$/ }],
    versionArgs: ["--version"],
  },
  codex: {
    binary: "codex",
    /** Codex CLI does both and decides at run time: a per-instance CIMD
     *  document under its vendor's host (observed live 2026-08-26 on three
     *  legs), or a dynamic registration whose stored id starts with `mcpdc_`
     *  (what a signed-out CLI does, which is every CI run). The shipped
     *  `0.147.0` binary carries both paths, so this is not a version to pin
     *  away from. */
    identities: [
      { path: "cimd", clientIdShape: /^https:\/\/chatgpt\.com\/oauth\/codex\/[A-Za-z0-9_-]{1,64}\/client\.json$/ },
      { path: "dcr", clientIdShape: /^mcpdc_[a-f0-9]{32}$/ },
    ],
    versionArgs: ["--version"],
  },
});

/** The identity a client id claims for this CLI, or undefined when it claims
 *  none of them. An unknown shape is never admitted. */
export function identityOf(cli, clientId) {
  return CLIS[cli]?.identities.find((identity) => typeof clientId === "string" && identity.clientIdShape.test(clientId));
}
const ROLE = /^[a-z]+$/;

/** Every browser launcher a CLI or its libraries reach through PATH on Linux
 *  or macOS; each gets a shim in the private bin directory. */
export const BROWSER_LAUNCHERS = Object.freeze([
  "open", "xdg-open", "gio", "gnome-open", "kde-open", "sensible-browser", "x-www-browser", "wslview",
]);

export function parseCliArgs(argv) {
  const options = { cli: undefined, user: "member" };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--cli" && Object.hasOwn(CLIS, argv[i + 1] ?? "")) options.cli = argv[++i];
    else if (argv[i] === "--user" && argv[i + 1] && ROLE.test(argv[i + 1])) options.user = argv[++i];
    else throw new Error("usage: probe-cli.mjs --cli <claude|codex> [--user <role>]");
  }
  if (options.cli === undefined) throw new Error("--cli is required");
  return options;
}

/** Strip terminal control sequences from CLI output: CSI sequences, and every
 *  OSC sequence (a hyperlink's hidden target among them) whether the CLI ends
 *  it with BEL or with ESC-backslash. A carriage return becomes a line break,
 *  so a line the CLI redraws in place stays a separate line. What remains is
 *  what a person sees. */
export function plainText(output) {
  return output.replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "").replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").replace(/\r\n?/g, "\n");
}

/** The first line of a CLI's --version output that is a version, or "unknown":
 *  the one thing a row prints about the CLI, so it is never the CLI's text. */
export function versionOf(output) {
  const match = plainText(typeof output === "string" ? output : "").match(/\d+\.\d+\.\d+/);
  return match === null ? "unknown" : match[0];
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/** Whether the driver's browser runs on this host: the machine's own Chrome,
 *  or a CDP endpoint on a loopback address. A hosted browser elsewhere would
 *  deliver the CLI's loopback callback to its own host, never to the CLI. */
export function browserIsLocal(cdpUrl) {
  if (cdpUrl === undefined || cdpUrl === "") return true;
  try {
    return LOOPBACK_HOSTS.has(new URL(cdpUrl).hostname);
  } catch {
    return false;
  }
}

/** The authorization URL a CLI printed, parsed, or undefined until it appears.
 *  Only an https URL whose path is /oauth/authorize on the expected origin
 *  counts; anything else the CLI prints is ignored. A control character ends
 *  a candidate, so a hyperlink's hidden target can never be glued to its
 *  text, and a candidate counts only once whitespace follows it, so a URL cut
 *  at a read boundary is not taken for the whole. */
export function extractAuthorizeUrl(output, origin) {
  const text = plainText(output);
  const match = text.match(/https:\/\/[^\s"'<>\x00-\x1f\x7f]+\/oauth\/authorize\?[^\s"'<>\x00-\x1f\x7f]+(?=\s)/g);
  if (!match) return undefined;
  for (const candidate of match) {
    let url;
    try {
      url = new URL(candidate);
    } catch {
      continue;
    }
    if (url.origin !== origin || url.pathname !== "/oauth/authorize") continue;
    const redirect = url.searchParams.get("redirect_uri");
    if (redirect === null || url.searchParams.get("state") === null || url.searchParams.get("code_challenge") === null) continue;
    return { href: url.href, clientId: url.searchParams.get("client_id") ?? "", redirectUri: redirect, state: url.searchParams.get("state") };
  }
  return undefined;
}

const PTY_RUNNER = fileURLToPath(new URL("./pty-run.py", import.meta.url));

/** Run a command on a wide pseudo-terminal through pty-run.py (Python's pty
 *  module, which both macOS and the Ubuntu runner ship), so a CLI that refuses
 *  a non-terminal stdin still runs headless and a CLI that wraps its output to
 *  the terminal's width keeps a long URL on one line. Output accumulates;
 *  `write` feeds its stdin. */
export function spawnPty(command, args, { cwd, env }) {
  const child = spawn("python3", [PTY_RUNNER, command, ...args], {
    cwd, env, stdio: ["pipe", "pipe", "pipe"],
  });
  const state = { child, output: "", exited: undefined };
  const collect = (chunk) => { state.output += chunk.toString(); };
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  // A write after the command exited is an EPIPE the caller has already
  // handled by checking `exited`; it must never become an uncaught error.
  child.stdin.on("error", () => {});
  state.exit = new Promise((resolve) => {
    child.once("error", () => { state.exited = { code: 1 }; resolve(state.exited); });
    child.once("exit", (code, signal) => { state.exited = { code, signal }; resolve(state.exited); });
  });
  state.write = (text) => { child.stdin.write(text); };
  return state;
}

/** Stop a pty-run.py command and the process group it started: SIGTERM lets
 *  the runner kill its child's group, and SIGKILL follows if it does not. */
export async function stopPty(state, graceMs = 2_000) {
  if (state.exited !== undefined) return;
  try { state.child.kill("SIGTERM"); } catch { return; }
  await waitForOutput(state, () => state.exited !== undefined, graceMs);
  if (state.exited === undefined) {
    try { state.child.kill("SIGKILL"); } catch { /* already gone */ }
    await state.exit;
  }
}

/** Wait until `predicate(output)` holds or the deadline passes. */
export function waitForOutput(state, predicate, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    const tick = () => {
      if (predicate(state.output)) return resolve(true);
      if (state.exited !== undefined || Date.now() - started > timeoutMs) return resolve(predicate(state.output));
      setTimeout(tick, 250);
    };
    tick();
  });
}

const kinds = (events) => events.map((event) => `${event.event}:${event.status}`);
const CODE = /^[a-z0-9_.-]{1,64}$/;

/** The audit events as `event:status(reason)` for the row's NOTE line. Every
 *  part is a fixed code from the library's vocabulary; anything else prints
 *  as `?` so the line never carries a value from the outside. */
export function auditKinds(events) {
  return events.map((event) => {
    const name = [event.event, event.status].map((part) => (typeof part === "string" && CODE.test(part) ? part : "?")).join(":");
    const reason = typeof event.reason === "string" && CODE.test(event.reason) ? `(${event.reason})` : "";
    return name + reason;
  });
}

/** What the served leg must have recorded for a CLI's completed login: the
 *  identity path the client id claimed, the identity, the code exchange, and,
 *  when the CLI then reached /mcp, a successful protected request. `path` is
 *  the one `identityOf` matched, so the audit has to agree with the client id
 *  the row already checked; a path this CLI does not declare holds nothing. */
export function cliLoginHolds(events, cli, { path, expectProtectedRequest }) {
  const seen = kinds(events);
  if (!CLIS[cli]?.identities.some((identity) => identity.path === path)) return false;
  const registration = path === "cimd" ? "oauth.cimd.fetch:success" : "oauth.register:success";
  const required = [registration, "identity.verify:success", "oauth.authorize.approve:success", "oauth.token.authorization_code:success"];
  if (expectProtectedRequest) required.push("auth.request:success");
  return required.every((name) => seen.includes(name));
}
