// A real third-party MCP client (Claude Code or Codex CLI) against a SERVED
// leg on its public hostname, driven headless: the CLI's own login command
// prints its authorization URL under a pseudo-terminal, the identity driver
// completes that URL through the real provider pages as a provisioned test
// user, the browser lands on the CLI's loopback callback, and the served leg's
// audit shows the registration, the identity, and the code exchange. Claude
// Code's connection check then proves a protected /mcp request; a tool call
// runs when the client-keys file supplies the vendor key.
//
//   run.sh scripts/live/probe-cli.mjs entra --cli claude [--user member]
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { driveAuthorize, openBrowser } from "./drive-identity-browser.mjs";
import { ARMABLE_OUTCOMES, ProbeRefusal } from "./drive-identity-support.mjs";
import {
  BROWSER_LAUNCHERS, CLIS, auditKinds, browserIsLocal, cliLoginHolds, extractAuthorizeUrl, identityOf, parseCliArgs, plainText, spawnPty, stopPty,
  versionOf, waitForOutput,
} from "./probe-cli-support.mjs";
import { eventsSince } from "./probe-client-support.mjs";
import { LEGS, readClientKeysFile } from "./run-support.mjs";

const out = [];
const ok = (label, condition, detail = "") => {
  out.push(`${condition ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return condition;
};
const requireEnv = (name) => {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required`);
  return value;
};
const LOGIN_TIMEOUT_MS = 90_000;
const FAKE_KEYCHAIN = fileURLToPath(new URL("./fake-keychain.py", import.meta.url));
const KEYCHAIN_STORE = ".mcp-sso-keychain.json";
const OPEN_MARKER = "browser-open-requested";
// On macOS a CLI opens a URL through /usr/bin/open by absolute path, which no
// PATH shim reaches, so the login command runs under a process sandbox that
// denies exactly that executable; the CLI still prints the URL.
const DARWIN_SANDBOX = '(version 1)(allow default)(deny process-exec (literal "/usr/bin/open"))';
const loginCommand = (command, args) => process.platform === "darwin"
  ? ["sandbox-exec", ["-p", DARWIN_SANDBOX, command, ...args]] : [command, args];

const options = parseCliArgs(process.argv.slice(2));
const cli = CLIS[options.cli];
const leg = requireEnv("MCP_SSO_LEG");
if (!LEGS.includes(leg)) throw new Error("MCP_SSO_LEG is not a known leg");
const origin = requireEnv("OAUTH_ISSUER");
const auditFile = requireEnv("MCP_SSO_AUDIT_FILE");
const users = JSON.parse(requireEnv("IDP_TEST_USERS_JSON"));
const password = requireEnv("IDP_TEST_USER_PASSWORD");
const user = users[options.user];
if (typeof user !== "string" || user.length === 0) throw new Error("the requested test user is not provisioned");
const idpName = leg === "cloudflare_access" ? requireEnv("CF_ACCESS_IDP_NAME") : undefined;
const keys = process.env.MCP_SSO_CLIENT_KEYS_FILE ? readClientKeysFile(process.env.MCP_SSO_CLIENT_KEYS_FILE) : {};
const readAudit = () => { try { return readFileSync(auditFile, "utf8"); } catch { return ""; } };
const countLines = (text) => text.split("\n").filter((line) => line.trim() !== "").length;

// The CLI runs in a private HOME and cwd of its own, created before anything
// else, so its configuration and credential store never touch the operator's,
// and disappear with the run on every exit path. Its PATH starts with a bin
// directory of shims: every browser launcher a CLI reaches through PATH
// (`open`, `xdg-open`, and the others in BROWSER_LAUNCHERS) records that it
// was asked and does nothing, so a CLI that opens the authorization URL itself
// (Codex does, through xdg-open on Linux) reaches the driver's browser only,
// never the operator's desktop browser (on macOS the process sandbox above
// does that job); on macOS, `security` is fake-keychain.py, so Claude Code's
// OAuth state lives in the private HOME instead of the operator's login
// keychain (the Linux runner has no keychain and the CLI uses a file there on
// its own). The shims leave a file behind when used, which is how the row
// proves they were reached.
const home = mkdtempSync(join(process.env.TMPDIR ?? "/tmp", `mcp-sso-${options.cli}-`));
const cwd = join(home, "project");
const bin = join(home, "bin");
const cliEnv = {
  PATH: `${bin}:${process.env.PATH}`, BROWSER: join(bin, "open"), HOME: home, TMPDIR: process.env.TMPDIR ?? "/tmp",
  LANG: process.env.LANG ?? "C.UTF-8", TERM: "xterm", NO_COLOR: "1", CI: "1",
};
let opened;
let login;
let refusal;
let failures = 0;
const trace = [];
// A runner-level refusal: nothing on stdout, one fixed line on stderr, before
// the CLI has touched the served leg, so the rehearsal records BLOCKED with
// the reason and not a failed check (the same shape as probe-client.mjs).
const refuse = (message) => {
  process.stderr.write(`probe-cli: ${message}\n`);
  failures++;
};
try {
  mkdirSync(bin, { mode: 0o700 });
  mkdirSync(cwd, { mode: 0o700 });
  for (const name of BROWSER_LAUNCHERS) writeFileSync(join(bin, name), `#!/bin/sh\n: > ${JSON.stringify(join(home, OPEN_MARKER))}\nexit 0\n`, { mode: 0o700 });
  if (process.platform === "darwin") {
    writeFileSync(join(bin, "security"), `#!/bin/sh\nexec python3 ${JSON.stringify(FAKE_KEYCHAIN)} "$@"\n`, { mode: 0o700 });
  }
  const python = spawnSync("python3", ["--version"], { cwd, env: cliEnv, encoding: "utf8" });
  const version = python.status === 0 ? spawnSync(cli.binary, cli.versionArgs, { cwd, env: cliEnv, encoding: "utf8" }) : undefined;
  // The CLI listens for its callback on this host's loopback, so the browser
  // that lands on it must run here: a hosted browser would deliver the code
  // to its own host's loopback instead.
  const local = browserIsLocal(process.env.MCP_SSO_BROWSER_CDP_URL);
  opened = python.status === 0 && version?.status === 0 && local ? await openBrowser() : undefined;
  if (python.status !== 0) {
    refuse("python3 is unavailable on PATH");
  } else if (version?.status !== 0) {
    refuse(`${options.cli} is unavailable on PATH`);
  } else if (!local) {
    refuse("the CLI rows need a browser on this host; unset MCP_SSO_BROWSER_CDP_URL");
  } else if (opened === undefined) {
    refuse("browser is unavailable; install Chrome or set MCP_SSO_BROWSER_CDP_URL");
  } else {
    const serverName = `live-${leg}`;
    const before = countLines(readAudit());
    out.push(`NOTE  ${options.cli} ${versionOf(version.stdout)}`);
    if (options.cli === "claude") {
      const added = spawnSync("claude", ["mcp", "add", "--transport", "http", serverName, `${origin}/mcp`, "-s", "local"], { cwd, env: cliEnv, encoding: "utf8" });
      if (!ok("the client records the server", added.status === 0)) failures++;
      login = spawnPty(...loginCommand("claude", ["mcp", "login", "--no-browser", serverName]), { cwd, env: cliEnv });
    } else {
      // codex mcp add detects OAuth on the server and starts the login itself.
      login = spawnPty(...loginCommand("codex", ["mcp", "add", serverName, "--url", `${origin}/mcp`]), { cwd, env: cliEnv });
    }
    await waitForOutput(login, (text) => extractAuthorizeUrl(text, origin) !== undefined, LOGIN_TIMEOUT_MS);
    const authorize = extractAuthorizeUrl(login.output, origin);
    if (!ok("the client prints an authorization URL on the served origin", authorize !== undefined)) throw new Error("no authorization url");
    const identity = identityOf(options.cli, authorize.clientId);
    if (!ok(`the client identifies itself a way this CLI declares (${cli.identities.map((i) => i.path).join(" or ")})`, identity !== undefined)) failures++;
    if (options.cli !== "codex") {
      if (!ok("the client opened no browser of its own (--no-browser)", !existsSync(join(home, OPEN_MARKER)))) failures++;
    } else if (process.platform === "darwin") {
      out.push("NOTE  the client's own browser launch is denied by the process sandbox on macOS");
    } else if (!ok("the client's browser launch reached the shim, not the desktop", existsSync(join(home, OPEN_MARKER)))) failures++;
    const result = await driveAuthorize({
      context: opened.context, origin, authorizeUrl: authorize.href, callback: authorize.redirectUri, user, password, idpName, trace,
      loopbackCallback: authorize.redirectUri,
    });
    // An outcome the operator must arm (the tenant asking this test user to
    // register MFA) is a runner-level refusal, not a failed check, exactly as
    // in probe-client.mjs: the flow was never attempted.
    if (ARMABLE_OUTCOMES.has(result.outcome)) throw new ProbeRefusal(result.outcome);
    out.push(`NOTE  trace ${trace.join(" > ")}`);
    if (!ok("the provider sign-in reaches consent and the browser lands on the client's loopback callback", result.outcome === "approved", result.outcome)) failures++;
    // The CLI's listener took the code; it may also accept the same redirect
    // pasted, which is what --no-browser documents, so offer it once.
    const finished = await waitForOutput(login, () => login.exited !== undefined, 20_000);
    if (!finished && result.redirectUrl !== undefined && options.cli === "claude") {
      login.write(`${result.redirectUrl}\r`);
      await waitForOutput(login, () => login.exited !== undefined, 30_000);
    }
    const loginText = plainText(login.output);
    if (!ok("the client's login command exits successfully", login.exited?.code === 0 && !/Couldn't complete/.test(loginText), `exit ${login.exited?.code ?? "none"}`)) failures++;
    if (options.cli === "claude" && process.platform === "darwin") {
      if (!ok("the client's keychain writes reached the private store, not the login keychain", existsSync(join(home, KEYCHAIN_STORE)))) failures++;
    }
    let protectedRequest = false;
    if (options.cli === "claude") {
      // The connection check runs on every Claude Code row, key or no key.
      const listed = spawnSync("claude", ["mcp", "list"], { cwd, env: cliEnv, encoding: "utf8" });
      protectedRequest = listed.status === 0 && new RegExp(`^${serverName}:[^\n]*Connected`, "m").test(plainText(listed.stdout));
      if (!ok("the client's connection check reaches the protected /mcp with its token", protectedRequest)) failures++;
      if (keys.ANTHROPIC_API_KEY) {
        const call = spawnSync("claude", ["-p", `Call the ping tool of the ${serverName} MCP server and reply with exactly its text.`,
          "--allowedTools", `mcp__${serverName}__ping`, "--output-format", "text"], { cwd, env: { ...cliEnv, ANTHROPIC_API_KEY: keys.ANTHROPIC_API_KEY }, encoding: "utf8", timeout: 120_000 });
        if (!ok("the client completes a tool call through the served leg", call.status === 0 && /pong/i.test(plainText(call.stdout)))) failures++;
      } else {
        out.push("NOTE  tool call skipped: the client-keys file supplies no ANTHROPIC_API_KEY");
      }
    } else if (keys.OPENAI_API_KEY) {
      const call = spawnSync("codex", ["exec", "--skip-git-repo-check", `Call the ping tool of the ${serverName} MCP server and reply with exactly its text.`],
        { cwd, env: { ...cliEnv, OPENAI_API_KEY: keys.OPENAI_API_KEY }, encoding: "utf8", timeout: 120_000 });
      protectedRequest = call.status === 0 && /pong/i.test(plainText(call.stdout));
      if (!ok("the client completes a tool call through the served leg", protectedRequest)) failures++;
    } else {
      out.push("NOTE  tool call skipped: the client-keys file supplies no OPENAI_API_KEY; the row proves the login and the code exchange only");
    }
    const events = eventsSince(readAudit(), before);
    out.push(`NOTE  audit ${auditKinds(events).join(" > ") || "(no events)"}`);
    if (!ok("the served leg's audit records the client's registration, identity, and code exchange",
      cliLoginHolds(events, options.cli, { path: identity?.path, expectProtectedRequest: protectedRequest }), `${events.length} events added`)) failures++;
  }
} catch (error) {
  failures++;
  if (error instanceof ProbeRefusal) refusal = error.outcome;
  else if (out.length > 0) out.push("FAIL  probe aborted before completion");
  else process.stderr.write("probe-cli: the private HOME or the CLI could not be prepared\n");
} finally {
  if (login !== undefined) await stopPty(login);
  try { await opened?.browser.close(); } catch { /* nothing left to release */ }
  rmSync(home, { recursive: true, force: true });
  if (refusal !== undefined) {
    process.stderr.write(`probe-cli: ${refusal}\n`);
  } else if (out.length > 0) {
    console.log(out.join("\n"));
    console.log(`\n${out.filter((line) => line.startsWith("PASS")).length}/${out.filter((line) => !line.startsWith("NOTE")).length} checks passed`);
  }
  process.exitCode = failures > 0 ? 1 : 0;
}
