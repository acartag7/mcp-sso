import assert from "node:assert/strict";
import {
  chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync,
  readFileSync, readdirSync, rmSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SERVE = readFileSync(join(ROOT, "scripts/live/serve.sh"), "utf8");
const PROBE = readFileSync(join(ROOT, "scripts/live/probe-e2e.mjs"), "utf8");
const README = readFileSync(join(ROOT, "scripts/live/README.md"), "utf8");

function executable(path, source) {
  writeFileSync(path, source, { mode: 0o700 });
  chmodSync(path, 0o700);
}

function waitForExit(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("serve.sh did not exit after tunnel completion")), 5_000);
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

function waitForFile(path) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 5_000;
    const poll = () => {
      if (existsSync(path)) return resolve();
      if (Date.now() >= deadline) return reject(new Error(`timed out waiting for ${path}`));
      setTimeout(poll, 10);
    };
    poll();
  });
}

async function runServeScenario(mode) {
  const fixture = mkdtempSync(join(tmpdir(), "mcp-sso-live-serve-"));
  const repo = join(fixture, "repo");
  const infra = join(fixture, "infra");
  const bin = join(fixture, "bin");
  const marker = join(fixture, "server-terminated");
  const ready = join(fixture, "server-ready");
  const bystanderPid = join(fixture, "bystander-pid");
  const bystanderSignaled = join(fixture, "bystander-signaled");
  const tunnelReady = join(fixture, "tunnel-ready");
  const releaseTunnel = join(fixture, "release-tunnel");
  const serverJs = join(fixture, "server.mjs");
  const bystanderJs = join(fixture, "bystander.mjs");
  mkdirSync(join(repo, "scripts/live"), { recursive: true });
  mkdirSync(join(repo, "examples/fastify-sqlite"), { recursive: true });
  mkdirSync(join(infra, "scripts"), { recursive: true });
  mkdirSync(bin, { recursive: true });
  copyFileSync(join(ROOT, "scripts/live/serve.sh"), join(repo, "scripts/live/serve.sh"));
  chmodSync(join(repo, "scripts/live/serve.sh"), 0o700);
  writeFileSync(bystanderJs, `import { appendFileSync, writeFileSync } from "node:fs";\nconst note = (signal) => appendFileSync(process.env.BYSTANDER_SIGNALED, signal + "\\n");\nprocess.on("SIGINT", () => note("SIGINT"));\nprocess.on("SIGTERM", () => note("SIGTERM"));\nwriteFileSync(process.env.BYSTANDER_PID, String(process.pid));\nsetInterval(() => {}, 1_000);\n`);
  writeFileSync(serverJs, `import { spawn } from "node:child_process";\nimport { existsSync, writeFileSync } from "node:fs";\nconst bystander = spawn(process.execPath, [process.env.FAKE_BYSTANDER_JS], { env: process.env, stdio: "ignore" });\nbystander.unref();\nconst stop = () => { writeFileSync(process.env.MARKER, "terminated"); process.exit(0); };\nprocess.on("SIGINT", stop);\nprocess.on("SIGTERM", stop);\nconst ready = setInterval(() => {\n  if (existsSync(process.env.BYSTANDER_PID)) { clearInterval(ready); writeFileSync(process.env.READY, "ready"); }\n}, 10);\nsetInterval(() => {}, 1_000);\n`);
  executable(join(repo, "scripts/live/run.sh"), `#!/usr/bin/env bash\nexec node "$FAKE_SERVER_JS"\n`);
  executable(join(infra, "scripts/tofu-run.sh"), `#!/usr/bin/env bash\ncase "${'$'}{*: -1}" in\n  issuer_origins) printf '%s\\n' '{"entra":"https://entra.test"}' ;;\n  tunnel_ingress_ports) printf '%s\\n' '{"entra":{"gateway":43123}}' ;;\nesac\n`);
  executable(join(bin, "cloudflared"), `#!/usr/bin/env bash\nif [[ "${'$'}1 ${'$'}2" == "tunnel info" ]]; then\n  printf 'ID 00000000-0000-0000-0000-000000000000\\n'\n  exit 0\nfi\nwhile [[ ! -f "$READY" ]]; do /bin/sleep 0.01; done\nprintf ready > "$TUNNEL_READY"\ncase "$TUNNEL_MODE" in\n  normal) exit 0 ;;\n  failure) exit 7 ;;\n  signal) while [[ ! -f "$RELEASE_TUNNEL" ]]; do /bin/sleep 0.01; done ;;\nesac\n`);
  executable(join(bin, "mktemp"), `#!/usr/bin/env bash\npath="$FAKE_TMPDIR/mcp-sso-tunnel-fixed"\n( set -o noclobber; : > "$path" ) || exit 1\nprintf '%s\\n' "$path"\n`);
  executable(join(bin, "sleep"), "#!/usr/bin/env bash\nexit 0\n");

  const child = spawn(join(repo, "scripts/live/serve.sh"), ["entra"], {
    detached: true,
    env: {
      ...process.env, MCP_SSO_INFRA_DIR: infra, MARKER: marker, READY: ready,
      BYSTANDER_PID: bystanderPid, BYSTANDER_SIGNALED: bystanderSignaled,
      FAKE_SERVER_JS: serverJs, FAKE_BYSTANDER_JS: bystanderJs,
      TUNNEL_MODE: mode === "normal" || mode === "failure" ? mode : "signal",
      TUNNEL_READY: tunnelReady, RELEASE_TUNNEL: releaseTunnel,
      FAKE_TMPDIR: fixture,
      PATH: `${bin}:${process.env.PATH}`, TMPDIR: fixture,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  try {
    if (mode === "sigint" || mode === "sigterm") {
      await waitForFile(tunnelReady);
      process.kill(child.pid, mode === "sigint" ? "SIGINT" : "SIGTERM");
      writeFileSync(releaseTunnel, "release");
    }
    const result = await waitForExit(child);
    const expected = { normal: 0, failure: 7, sigint: 130, sigterm: 143 }[mode];
    assert.deepEqual(result, { code: expected, signal: null });
    assert.equal(readFileSync(marker, "utf8"), "terminated", "cleanup terminated the captured server PID");
    const config = /^tunnel config: (.+)$/m.exec(stdout)?.[1];
    assert.ok(config, `serve.sh printed its generated config path: ${stdout}`);
    assert.equal(existsSync(config), false, "cleanup removed the generated tunnel config");
    assert.deepEqual(
      readdirSync(fixture).filter((name) => name.startsWith("mcp-sso-tunnel-")), [],
      "cleanup left no precursor or configured tunnel tempfile",
    );
    const unrelatedPid = Number(readFileSync(bystanderPid, "utf8"));
    assert.doesNotThrow(() => process.kill(unrelatedPid, 0), "an unrelated process in the group survived cleanup");
    assert.equal(existsSync(bystanderSignaled), false, "cleanup never signaled an unrelated process in the group");
  } finally {
    if (child.pid) try { process.kill(-child.pid, "SIGKILL"); } catch {}
    rmSync(fixture, { recursive: true, force: true });
  }
}

test("live serve cleanup owns only its child and generated config on every exit", async (t) => {
  for (const mode of ["normal", "failure", "sigint", "sigterm"]) {
    await t.test(mode, () => runServeScenario(mode));
  }
  assert.doesNotMatch(SERVE, /kill\s+0\b/, "cleanup must not signal the whole process group");
  assert.match(SERVE, /kill\s+"\$SERVER_PID"/, "cleanup targets the captured server PID");
  assert.ok(SERVE.indexOf("trap cleanup EXIT") < SERVE.indexOf('CONF="$(mktemp'), "cleanup is armed before tempfile creation");
  assert.doesNotMatch(SERVE, /mktemp[^\n]+\)\.yml/, "CONF is the exact exclusively created tempfile");
});

test("live probe labels its machine credential as process-local, not SQLite-persisted", () => {
  assert.match(PROBE, /const machineRows = new Map\(\)/, "the probe machine store is process-local");
  assert.match(PROBE, /process-local MachineClientStore/);
  assert.match(README, /process-local `MachineClientStore`/);
  assert.match(README, /SQLite store proves filesystem admission only/);
  for (const artifact of [PROBE, README]) {
    assert.doesNotMatch(artifact, /provisioned into persistent SQLite/i);
    assert.doesNotMatch(artifact, /SQLite-persisted machine credential/i);
  }
});
