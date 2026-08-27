// Behavioural coverage for the third-party CLI probe: how a CLI's printed
// authorization URL is recognised, what the served audit must show, the
// loopback-callback exception in the driver's host policy, the pseudo-terminal
// runner, and the probe's refusal when the CLI is absent.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { hostPolicy } from "../scripts/live/drive-identity-support.mjs";
import {
  BROWSER_LAUNCHERS, CLIS, auditKinds, browserIsLocal, cliLoginHolds, extractAuthorizeUrl, identityOf, parseCliArgs, plainText, spawnPty, stopPty, versionOf,
  waitForOutput,
} from "../scripts/live/probe-cli-support.mjs";
import { readClientKeysFile } from "../scripts/live/run-support.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const ORIGIN = "https://entra.example";
const CIMD = "https://claude.ai/oauth/claude-code-client-metadata";

function authorizeUrl(overrides = {}) {
  const url = new URL(`${ORIGIN}/oauth/authorize`);
  const params = {
    response_type: "code", client_id: CIMD, redirect_uri: "http://localhost:1455/callback", state: "st4te",
    code_challenge: "ch4llenge", code_challenge_method: "S256", scope: "mcp:read", ...overrides,
  };
  for (const [key, value] of Object.entries(params)) if (value !== undefined) url.searchParams.set(key, value);
  return url.href;
}

test("BEHAVIOUR parseCliArgs: only a known CLI and a plain role are accepted", () => {
  assert.deepEqual(parseCliArgs(["--cli", "claude"]), { cli: "claude", user: "member" });
  assert.deepEqual(parseCliArgs(["--cli", "codex", "--user", "nogroups"]), { cli: "codex", user: "nogroups" });
  assert.throws(() => parseCliArgs([]), /--cli is required/);
  assert.throws(() => parseCliArgs(["--cli", "cursor"]), /usage/);
  assert.throws(() => parseCliArgs(["--cli", "claude", "--user", "mem ber"]), /usage/);
  assert.throws(() => parseCliArgs(["--cli", "claude", "--expect", "x"]), /usage/);
});

test("BEHAVIOUR extractAuthorizeUrl: only a complete authorize URL on the served origin counts", () => {
  const found = extractAuthorizeUrl(`Open this URL:\n\x1b[1m${authorizeUrl()}\x1b[0m\r\nthen paste the redirect\n`, ORIGIN);
  assert.equal(found.href, authorizeUrl());
  assert.equal(found.clientId, CIMD);
  assert.equal(found.redirectUri, "http://localhost:1455/callback");
  assert.equal(found.state, "st4te");
  assert.equal(identityOf("claude", found.clientId)?.path, "cimd");
  const linked = `\x1b]8;;${authorizeUrl()}\x1b\\Open\x1b]8;;\x1b\\ ${authorizeUrl()}\n`;
  assert.equal(extractAuthorizeUrl(linked, ORIGIN)?.href, authorizeUrl(), "an OSC 8 hyperlink does not hide the URL");
  // Claude Code ends its hyperlink sequences with BEL. Two independent
  // defences keep the hidden target and the visible text from reading as one
  // URL with every parameter twice (which the gateway refuses as duplicate
  // request parameters): plainText drops the whole sequence, and a control
  // character ends a candidate. Each is asserted on its own.
  const bell = `\x1b]8;;${authorizeUrl()}\x07${authorizeUrl()}\x1b]8;;\x07\n`;
  assert.equal(plainText(bell), `${authorizeUrl()}\n`, "plainText drops a BEL-terminated hyperlink's hidden target");
  const fromBell = extractAuthorizeUrl(bell, ORIGIN);
  assert.equal(fromBell?.href, authorizeUrl(), "a BEL-terminated hyperlink yields the URL once");
  assert.equal(new URL(fromBell.href).searchParams.getAll("client_id").length, 1);
  assert.equal(extractAuthorizeUrl(`${authorizeUrl()}\x07${authorizeUrl()}\n`, ORIGIN)?.href, authorizeUrl(), "a control character ends a candidate");
  // A CLI that redraws a status line with a bare carriage return must not
  // glue the redrawn text onto the URL either.
  const redrawn = `Opening browser...\r${authorizeUrl()}\rPress enter to continue\n`;
  assert.equal(extractAuthorizeUrl(redrawn, ORIGIN)?.href, authorizeUrl(), "a carriage return ends a candidate");
  assert.equal(extractAuthorizeUrl(authorizeUrl(), ORIGIN), undefined, "a candidate with nothing after it may be cut at a read boundary");
  assert.equal(extractAuthorizeUrl(`${authorizeUrl().replace(ORIGIN, "https://entra.example.evil")}\n`, ORIGIN), undefined, "another origin");
  assert.equal(extractAuthorizeUrl(`${authorizeUrl().replace("https://", "http://")}\n`, "http://entra.example"), undefined, "never plain http");
  assert.equal(extractAuthorizeUrl(`${ORIGIN}/x/oauth/authorize?redirect_uri=a&state=b&code_challenge=c\n`, ORIGIN), undefined, "another path");
  assert.equal(extractAuthorizeUrl(`${authorizeUrl({ state: undefined })}\n`, ORIGIN), undefined, "no state");
  assert.equal(extractAuthorizeUrl(`${authorizeUrl({ code_challenge: undefined })}\n`, ORIGIN), undefined, "no PKCE challenge");
  const wrapped = `${authorizeUrl().replace("&code_challenge=", "\n&code_challenge=")}\n`;
  assert.equal(extractAuthorizeUrl(wrapped, ORIGIN), undefined, "a URL wrapped by a narrow terminal is not a URL");
  const twice = `${authorizeUrl().replace(ORIGIN, "https://other.example")}\n${authorizeUrl()}\n`;
  assert.equal(extractAuthorizeUrl(twice, ORIGIN)?.href, authorizeUrl(), "a foreign candidate does not shadow the real one");
  assert.equal(extractAuthorizeUrl("", ORIGIN), undefined);
  assert.equal(identityOf("codex", "mcpdc_" + "0123456789abcdef".repeat(2))?.path, "dcr");
  assert.equal(identityOf("codex", CIMD), undefined, "Claude Code's document is not a Codex identity");
});

test("BEHAVIOUR plainText, versionOf, browserIsLocal, and auditKinds print or admit only fixed vocabulary", () => {
  assert.equal(plainText("\x1b[32mok\x1b[0m\r\n\x1b]8;;https://x.example\x1b\\link\x1b]8;;\x1b\\"), "ok\nlink");
  assert.equal(plainText("spinner\rdone\r\n"), "spinner\ndone\n", "a bare carriage return is a line break, never deleted");
  assert.equal(versionOf("\x1b[1m2.1.246 (Claude Code)\x1b[0m\n"), "2.1.246");
  assert.equal(versionOf("codex-cli 0.147.0\n"), "0.147.0");
  assert.equal(versionOf("see https://example.com/user@example.com\n"), "unknown", "a line with no version prints nothing of its own");
  assert.equal(versionOf(undefined), "unknown");
  assert.equal(browserIsLocal(undefined), true, "the machine's own Chrome");
  assert.equal(browserIsLocal(""), true);
  assert.equal(browserIsLocal("ws://127.0.0.1:9222/devtools/browser/x"), true);
  assert.equal(browserIsLocal("ws://localhost:9222/"), true);
  assert.equal(browserIsLocal("wss://connect.browserbase.com?apiKey=x&sessionId=y"), false, "a hosted browser cannot reach this host's loopback");
  assert.equal(browserIsLocal("ws://localhost.example:9222/"), false);
  assert.equal(browserIsLocal("not a url"), false);
  assert.deepEqual(auditKinds([
    { event: "oauth.cimd.fetch", status: "success" },
    { event: "identity.verify", status: "failure", reason: "entra_no_groups" },
    { event: "auth.request", status: "failure", reason: "Bearer token for user@example.com" },
    { event: 42, status: null },
  ]), ["oauth.cimd.fetch:success", "identity.verify:failure(entra_no_groups)", "auth.request:failure", "?:?"]);
});

test("BEHAVIOUR cliLoginHolds: the identity path the client id claimed, the identity, the approval, and the exchange", () => {
  const CODEX_CIMD = "https://chatgpt.com/oauth/codex/c50ro4oho5AB/client.json";
  const DCR_ID = "mcpdc_" + "0123456789abcdef".repeat(2);
  // `oauth.register` and `identity.verify` are emitted before the client is
  // known and carry no id; everything after names the client.
  const events = (clientId, ...names) => names.map((name) => {
    const [event, status] = name.split(":");
    return event === "oauth.register" || event === "identity.verify" ? { event, status } : { event, status, clientId };
  });
  const flow = (clientId, registration) => events(clientId, registration, "identity.verify:success", "oauth.authorize.approve:success", "oauth.token.authorization_code:success");
  const claude = [...events(CIMD, "auth.request:failure"), ...flow(CIMD, "oauth.cimd.fetch:success")];
  const codex = flow(DCR_ID, "oauth.register:success");

  assert.equal(cliLoginHolds(claude, "claude", { path: "cimd", clientId: CIMD, expectProtectedRequest: false }), true);
  assert.equal(cliLoginHolds(codex, "codex", { path: "dcr", clientId: DCR_ID, expectProtectedRequest: false }), true);
  assert.equal(cliLoginHolds(claude, "codex", { path: "dcr", clientId: CIMD, expectProtectedRequest: false }), false, "a CIMD fetch is not a dynamic registration");
  assert.equal(cliLoginHolds(codex, "claude", { path: "cimd", clientId: DCR_ID, expectProtectedRequest: false }), false, "a dynamic registration is not a CIMD fetch");
  assert.equal(cliLoginHolds(claude, "claude", { path: "cimd", clientId: CIMD, expectProtectedRequest: true }), false, "a connection check must show as a protected request");
  assert.equal(cliLoginHolds([...claude, ...events(CIMD, "auth.request:success")], "claude", { path: "cimd", clientId: CIMD, expectProtectedRequest: true }), true);
  assert.equal(cliLoginHolds(claude.filter((e) => e.event !== "oauth.token.authorization_code"), "claude", { path: "cimd", clientId: CIMD, expectProtectedRequest: false }), false);
  assert.equal(cliLoginHolds([], "claude", { path: "cimd", clientId: CIMD, expectProtectedRequest: false }), false);
  assert.equal(cliLoginHolds(claude, "claude", { path: undefined, clientId: CIMD, expectProtectedRequest: false }), false, "a client id that claimed no declared identity holds nothing");
  assert.equal(cliLoginHolds(claude, "claude", { path: "dcr", clientId: CIMD, expectProtectedRequest: false }), false, "Claude Code declares no dynamic-registration identity");
  assert.equal(cliLoginHolds(claude, "claude", { path: "cimd", clientId: undefined, expectProtectedRequest: false }), false, "no observed client id, nothing to bind to");
  assert.equal(cliLoginHolds(claude, "claude", { path: "cimd", clientId: "", expectProtectedRequest: false }), false);
});

test("BEHAVIOUR cliLoginHolds: a stranger's flow on the same served leg is not this row's evidence", () => {
  // The served leg is public while the row runs, so another client can be
  // signing in at the same time: tonight's own session had four clients
  // against one leg. Counting event kinds alone would let that flow's
  // document fetch stand in for this row's.
  const MINE = "https://chatgpt.com/oauth/codex/c50ro4oho5AB/client.json";
  const THEIRS = "https://claude.ai/oauth/claude-code-client-metadata";
  const named = (clientId, ...names) => names.map((name) => { const [event, status] = name.split(":"); return { event, status, clientId }; });
  const unnamed = (...names) => names.map((name) => { const [event, status] = name.split(":"); return { event, status }; });
  const interleaved = [
    ...named(THEIRS, "oauth.cimd.fetch:success"),
    ...unnamed("identity.verify:success"),
    ...named(MINE, "oauth.authorize.approve:success", "oauth.token.authorization_code:success"),
  ];
  assert.equal(cliLoginHolds(interleaved, "codex", { path: "cimd", clientId: MINE, expectProtectedRequest: false }), false,
    "another client's document fetch does not prove this client fetched one");
  assert.equal(cliLoginHolds([...interleaved, ...named(MINE, "oauth.cimd.fetch:success")], "codex", { path: "cimd", clientId: MINE, expectProtectedRequest: false }), true,
    "this client's own fetch does");
  const foreignExchange = [
    ...named(MINE, "oauth.cimd.fetch:success"),
    ...unnamed("identity.verify:success"),
    ...named(THEIRS, "oauth.authorize.approve:success", "oauth.token.authorization_code:success"),
  ];
  assert.equal(cliLoginHolds(foreignExchange, "codex", { path: "cimd", clientId: MINE, expectProtectedRequest: false }), false,
    "another client's code exchange is not this row's token");
});

test("BEHAVIOUR hostPolicy: the loopback callback the CLI named is the only plain-http page the driver accepts", () => {
  const plain = hostPolicy(ORIGIN);
  assert.equal(plain.classify("http://localhost:1455/callback?code=x"), "other");
  assert.equal(plain.allowed("http://localhost:1455/callback?code=x"), false);
  const policy = hostPolicy(ORIGIN, { loopbackCallback: "http://localhost:1455/callback" });
  assert.equal(policy.classify("http://localhost:1455/callback?code=x&state=y"), "callback");
  assert.equal(policy.allowed("http://localhost:1455/callback?code=x"), true);
  assert.equal(policy.classify("http://localhost:1456/callback?code=x"), "other", "another port is not the named callback");
  assert.equal(policy.classify("http://127.0.0.1:1455/callback?code=x"), "other", "another loopback host is not the named callback");
  assert.equal(policy.classify("http://localhost.example:1455/callback"), "other");
  assert.equal(policy.classify(`${ORIGIN}/oauth/authorize`), "leg", "the leg is unchanged");
  assert.equal(policy.mayTypeCredential("http://localhost:1455/callback"), false);
  assert.equal(policy.mayTypeCredential("https://login.microsoftonline.com/x"), true);
  assert.throws(() => hostPolicy(ORIGIN, { loopbackCallback: "http://cli.example/callback" }), /loopback/);
  assert.throws(() => hostPolicy(ORIGIN, { loopbackCallback: "https://localhost:1455/callback" }), /plain http/);
  assert.throws(() => hostPolicy(ORIGIN, { loopbackCallback: "not a url" }));
});

test("BEHAVIOUR pty-run.py: a wide terminal, relayed stdin, and the command's own exit status", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-pty-"));
  try {
    const env = { PATH: process.env.PATH, HOME: dir, TERM: "xterm" };
    const wide = spawnPty("sh", ["-c", "stty size; cat"], { cwd: dir, env });
    assert.equal(await waitForOutput(wide, (text) => /50 400/.test(text), 10_000), true, `the terminal is 50 by 400: ${wide.output}`);
    wide.write("hello from stdin\n");
    assert.equal(await waitForOutput(wide, (text) => /hello from stdin/.test(text), 10_000), true, "stdin reaches the command");
    wide.child.stdin.end();
    assert.deepEqual(await wide.exit, { code: 0, signal: null });
    const failing = spawnPty("sh", ["-c", "exit 3"], { cwd: dir, env });
    assert.equal((await failing.exit).code, 3, "the exit status is the command's");
    const noOutput = spawnPty("sh", ["-c", "exit 0"], { cwd: dir, env });
    assert.equal(await waitForOutput(noOutput, (text) => text.includes("never"), 10_000), false, "waiting ends when the command exits");
    // Stopping the relay stops the command's whole process group, not just
    // the relay: the command's pid must be gone afterwards.
    const lingering = spawnPty("sh", ["-c", "echo PID=$$; sleep 60"], { cwd: dir, env });
    assert.equal(await waitForOutput(lingering, (text) => /PID=\d+/.test(text), 10_000), true);
    const pid = Number(lingering.output.match(/PID=(\d+)/)[1]);
    await stopPty(lingering);
    assert.notEqual(lingering.exited, undefined, "the relay exited");
    const gone = await new Promise((resolve) => {
      const started = Date.now();
      const tick = () => {
        try { process.kill(pid, 0); } catch { return resolve(true); }
        if (Date.now() - started > 5_000) return resolve(false);
        setTimeout(tick, 100);
      };
      tick();
    });
    assert.equal(gone, true, "the command started under the pty is gone with the relay");
    // A group signal, which is how the orchestrator stops a timed-out row,
    // reaches the command under the relay as well as the relay itself.
    const grouped = spawnPty("sh", ["-c", "echo PID=$$; sleep 60"], { cwd: dir, env });
    assert.equal(await waitForOutput(grouped, (text) => /PID=\d+/.test(text), 10_000), true);
    const groupedPid = Number(grouped.output.match(/PID=(\d+)/)[1]);
    process.kill(grouped.child.pid, "SIGTERM");
    await grouped.exit;
    const groupGone = await new Promise((resolve) => {
      const started = Date.now();
      const tick = () => {
        try { process.kill(groupedPid, 0); } catch { return resolve(true); }
        if (Date.now() - started > 5_000) return resolve(false);
        setTimeout(tick, 100);
      };
      tick();
    });
    assert.equal(groupGone, true, "SIGTERM to the relay ends the command it started");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("BEHAVIOUR fake-keychain.py: the three security forms Claude Code uses, on an owner-only file in the private HOME", () => {
  const home = mkdtempSync(join(tmpdir(), "mcp-sso-keychain-"));
  try {
    const keychain = (args, input) => spawnSync("python3", [join(ROOT, "scripts/live/fake-keychain.py"), ...args], { encoding: "utf8", env: { HOME: home, PATH: process.env.PATH }, input });
    const find = ["find-generic-password", "-a", "unknown", "-w", "-s", "Claude Code-credentials"];
    const missing = keychain(find);
    assert.equal(missing.status, 44, "a missing item exits 44 like the real tool");
    assert.equal(missing.stdout, "");
    const hex = Buffer.from('{"mcpOAuth":{"live-entra|x":{"clientInfo":{"client_id":"https://claude.ai/oauth/claude-code-client-metadata"}}}}').toString("hex");
    const added = keychain(["-i"], `add-generic-password -U -a "unknown" -s "Claude Code-credentials" -X "${hex}"\n`);
    assert.equal(added.status, 0, added.stderr);
    const found = keychain(find);
    assert.equal(found.status, 0);
    assert.match(found.stdout, /^\{"mcpOAuth":.*\}\n$/, "the stored value is read back as text");
    assert.equal(keychain(["find-generic-password", "-a", "other", "-w", "-s", "Claude Code-credentials"]).status, 44, "items are keyed by account and service");
    assert.equal(keychain(["find-generic-password", "-a", "unknown", "-w", "-s", "Claude Code"]).status, 44);
    assert.equal(statSync(join(home, ".mcp-sso-keychain.json")).mode & 0o777, 0o600, "the store is owner-only");
    const updated = keychain(["-i"], `add-generic-password -U -a "unknown" -s "Claude Code-credentials" -X "${Buffer.from("{}").toString("hex")}"\n`);
    assert.equal(updated.status, 0);
    assert.equal(keychain(find).stdout, "{}\n", "-U replaces the item");
    assert.equal(keychain(["delete-generic-password", "-a", "unknown", "-s", "Claude Code-credentials"]).status, 0);
    assert.equal(keychain(find).status, 44);
    assert.equal(keychain(["dump-keychain"]).status, 1, "any other form is refused");
    assert.equal(keychain(["-i"], "list-keychains\n").status, 1);
    assert.equal(keychain(["find-generic-password", "-w"]).status, 1, "no account or service is a refusal, not a match");
    const blank = keychain(["-i"], `\nadd-generic-password -U -a "unknown" -s "Claude Code-credentials" -X "${hex}"\n\n`);
    assert.equal(blank.status, 0, "blank lines in interactive mode are ignored, as the real tool ignores them");
    assert.equal(keychain(find).status, 0);
    const noHome = spawnSync("python3", [join(ROOT, "scripts/live/fake-keychain.py"), ...find], { encoding: "utf8", env: { PATH: process.env.PATH } });
    assert.equal(noHome.status, 1, "no HOME is a refusal");
    assert.doesNotMatch(noHome.stderr, /Traceback/);
    const badHex = keychain(["-i"], 'add-generic-password -U -a "unknown" -s "Claude Code-credentials" -X "not-hex"\n');
    assert.equal(badHex.status, 1, "a malformed value is a refusal");
    assert.doesNotMatch(badHex.stderr, /Traceback/);
    assert.deepEqual(BROWSER_LAUNCHERS.slice(0, 2), ["open", "xdg-open"]);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("BEHAVIOUR readClientKeysFile: an owner-only KEY=VALUE file with the two vendor keys only", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-keys-"));
  const file = (name, text, mode = 0o600) => { const path = join(dir, name); writeFileSync(path, text, { mode }); chmodSync(path, mode); return path; };
  try {
    assert.deepEqual(readClientKeysFile(file("both.env", "ANTHROPIC_API_KEY=fixture-anthropic-key\nOPENAI_API_KEY=fixture-openai-key\n")),
      { ANTHROPIC_API_KEY: "fixture-anthropic-key", OPENAI_API_KEY: "fixture-openai-key" });
    assert.deepEqual(readClientKeysFile(file("one.env", "# only one\nOPENAI_API_KEY=fixture-openai-key\n")), { OPENAI_API_KEY: "fixture-openai-key" });
    assert.deepEqual(readClientKeysFile(file("empty.env", "# nothing yet\n")), {}, "an empty file is no keys, which the probe reports as a skipped tool call");
    assert.throws(() => readClientKeysFile(file("other.env", "AWS_SECRET_ACCESS_KEY=fixture-aws-secret\n")), /key/i, "a key outside the allowlist is refused");
    assert.throws(() => readClientKeysFile(file("export.env", "export OPENAI_API_KEY=fixture-openai-key\n")), /key|line/i, "shell syntax is refused");
    assert.throws(() => readClientKeysFile(file("group.env", "OPENAI_API_KEY=fixture-openai-key\n", 0o640)), /permission|owner|mode/i, "a group-readable file is refused");
    const target = file("target.env", "OPENAI_API_KEY=fixture-openai-key\n");
    symlinkSync(target, join(dir, "link.env"));
    assert.throws(() => readClientKeysFile(join(dir, "link.env")), /symlink|regular|ELOOP/i, "a symlink is refused");
    assert.throws(() => readClientKeysFile(join(dir, "missing.env")), /cannot be opened/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("BEHAVIOUR probe-cli.mjs: a missing prerequisite is a runner-level refusal before any CLI or provider I/O, leaving nothing behind", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-cli-"));
  try {
    const emptyBin = join(dir, "empty-bin");
    mkdirSync(emptyBin);
    const pythonBin = join(dir, "python-bin");
    mkdirSync(pythonBin);
    const python = spawnSync("sh", ["-c", "command -v python3"], { encoding: "utf8" }).stdout.trim();
    symlinkSync(python, join(pythonBin, "python3"));
    const env = {
      TMPDIR: dir, MCP_SSO_LEG: "entra", OAUTH_ISSUER: ORIGIN, MCP_SSO_AUDIT_FILE: join(dir, "audit.jsonl"),
      IDP_TEST_USERS_JSON: JSON.stringify({ member: "member@fixture.example" }), IDP_TEST_USER_PASSWORD: "fixture-password-value",
    };
    const probe = (extra) => spawnSync(process.execPath, [join(ROOT, "scripts/live/probe-cli.mjs"), "--cli", "codex"], { encoding: "utf8", env: { ...env, ...extra } });
    const noPython = probe({ PATH: emptyBin });
    assert.equal(noPython.status, 1);
    assert.match(noPython.stderr, /^probe-cli: python3 is unavailable on PATH$/m);
    const noCli = probe({ PATH: pythonBin });
    assert.equal(noCli.status, 1);
    assert.match(noCli.stderr, /^probe-cli: codex is unavailable on PATH$/m);
    const badLeg = probe({ PATH: pythonBin, MCP_SSO_LEG: "entra:[^\\n]*Connected|" });
    assert.equal(badLeg.status, 1);
    assert.match(badLeg.stderr, /MCP_SSO_LEG is not a known leg/);
    for (const run of [noPython, noCli]) {
      assert.equal(run.stdout, "", "a refusal prints no check line");
      assert.doesNotMatch(run.stderr, /fixture-password-value/);
    }
    assert.deepEqual(readdirSync(dir).sort(), ["empty-bin", "python-bin"], "no private HOME outlives a refusal");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
