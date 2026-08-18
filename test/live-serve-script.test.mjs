// Behavioural coverage for scripts/live/serve.sh: the shipped script is spawned
// with fixture tools (cloudflared, curl, lsof, sleep), a fixture run.sh that
// becomes a fixture server, and a bystander process in the same process group.
// Every scenario asserts on process outcomes and files, never on serve.sh text.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync,
  symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const TUNNEL = "0f0f0f0f-1111-2222-3333-444444444444";
const ORIGINS = { cloudflare_access: "https://cf.example", entra: "https://entra.example", google: "https://google.example" };
const PORTS = { cloudflare_access: { gateway: 43101, backend: 43102 }, entra: { gateway: 43111, backend: 43112 }, google: { gateway: 43121, backend: 43122 } };
const executable = (path, source) => { writeFileSync(path, source); chmodSync(path, 0o700); };

function waitForExit(child, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label}: serve.sh did not exit`)), 30_000);
    child.once("error", reject);
    child.once("exit", (code, signal) => { clearTimeout(timer); resolve({ code, signal }); });
  });
}
function waitForFile(path) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 8_000;
    const poll = () => {
      if (existsSync(path)) return resolve();
      if (Date.now() >= deadline) return reject(new Error(`timed out waiting for ${path}`));
      setTimeout(poll, 10);
    };
    poll();
  });
}

async function runServeScenario(mode, legs = ["entra"]) {
  const fixture = mkdtempSync(join(tmpdir(), "mcp-sso-live-serve-"));
  const repo = join(fixture, "repo");
  const infra = join(fixture, "infra");
  const bin = join(fixture, "bin");
  const home = join(fixture, "home");
  const state = join(fixture, "state"); // per-port files: pid.<port>, ready.<port>, terminated.<port>
  mkdirSync(join(repo, "scripts/live"), { recursive: true });
  mkdirSync(join(repo, "examples/fastify-sqlite"), { recursive: true });
  mkdirSync(join(infra, "scripts"), { recursive: true });
  mkdirSync(join(home, ".cloudflared"), { recursive: true });
  mkdirSync(bin);
  mkdirSync(state);
  symlinkSync(join(ROOT, "src"), join(repo, "src"));
  for (const file of ["app.ts", "registration-rate-limit.ts", "trusted-proxy.ts"]) {
    symlinkSync(join(ROOT, "examples/fastify-sqlite", file), join(repo, "examples/fastify-sqlite", file));
  }
  copyFileSync(join(ROOT, "scripts/live/serve.sh"), join(repo, "scripts/live/serve.sh"));
  chmodSync(join(repo, "scripts/live/serve.sh"), 0o700);
  copyFileSync(join(ROOT, "scripts/live/run-support.mjs"), join(repo, "scripts/live/run-support.mjs"));
  writeFileSync(join(home, ".cloudflared", `${TUNNEL}.json`), "{}");
  const bystanderJs = join(fixture, "bystander.mjs");
  const serverJs = join(fixture, "server.mjs");
  const bystanderPid = join(fixture, "bystander-pid");
  const bystanderSignaled = join(fixture, "bystander-signaled");
  const tunnelStarted = join(fixture, "tunnel-started");
  const tunnelStopped = join(fixture, "tunnel-stopped");
  const tunnelConfig = join(fixture, "tunnel-config.yml");
  const releaseTunnel = join(fixture, "release-tunnel");
  const runShLog = join(fixture, "run-sh.log");
  writeFileSync(bystanderJs, `import { appendFileSync, writeFileSync } from "node:fs";
const note = (signal) => appendFileSync(process.env.BYSTANDER_SIGNALED, signal + "\\n");
process.on("SIGINT", () => note("SIGINT"));
process.on("SIGTERM", () => note("SIGTERM"));
writeFileSync(process.env.BYSTANDER_PID, String(process.pid));
setInterval(() => {}, 1_000);
`);
  writeFileSync(serverJs, `import { spawn } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
const port = process.env.PORT;
writeFileSync(process.env.STATE + "/pid." + port, String(process.pid));
if (!existsSync(process.env.BYSTANDER_PID)) {
  const bystander = spawn(process.execPath, [process.env.FAKE_BYSTANDER_JS], { env: process.env, stdio: "ignore" });
  bystander.unref();
}
const stop = () => { writeFileSync(process.env.STATE + "/terminated." + port, "terminated"); process.exit(0); };
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
const ready = setInterval(() => {
  if (existsSync(process.env.BYSTANDER_PID)) { clearInterval(ready); writeFileSync(process.env.STATE + "/ready." + port, "ready"); }
}, 10);
setInterval(() => {}, 1_000);
`);
  executable(join(repo, "scripts/live/run.sh"), `#!/usr/bin/env bash
printf '%s\\n' "$* PORT=$PORT" >> "$RUN_SH_LOG"
if [[ -n "\${STARTUP_EXIT-}" ]]; then exit "$STARTUP_EXIT"; fi
exec node "$FAKE_SERVER_JS"
`);
  executable(join(infra, "scripts/tofu-run.sh"), `#!/usr/bin/env bash
case "$4" in
  issuer_origins) printf '%s' '${JSON.stringify(ORIGINS)}' ;;
  tunnel_ingress_ports) printf '%s' '${JSON.stringify(PORTS)}' ;;
  *) exit 1 ;;
esac
`);
  executable(join(bin, "cloudflared"), `#!/usr/bin/env bash
[[ "$1 $2" == "tunnel --config" ]] || exit 9
cp -- "$3" "$TUNNEL_CONFIG_COPY"
printf started > "$TUNNEL_STARTED"
trap 'printf stopped > "$TUNNEL_STOPPED"; exit 143' TERM INT
case "$TUNNEL_MODE" in
  normal) exit 0 ;;
  failure) exit 7 ;;
  *) while [[ ! -f "$RELEASE_TUNNEL" ]]; do /bin/sleep 0.01; done; exit 0 ;;
esac
`);
  executable(join(bin, "curl"), `#!/usr/bin/env bash
url="\${@: -1}"; port="\${url##*:}"; port="\${port%%/*}"
[[ "$TUNNEL_MODE" != "startup-timeout" && -f "$STATE/ready.$port" ]]
`);
  executable(join(bin, "lsof"), `#!/usr/bin/env bash
port=""
for arg in "$@"; do case "$arg" in -iTCP:*) port="\${arg#-iTCP:}" ;; esac; done
case "$LSOF_MODE" in
  busy) echo 424242 ;;
  foreign) [[ -f "$STATE/ready.$port" ]] && echo 424242 ;;
  *) [[ -f "$STATE/ready.$port" ]] && cat "$STATE/pid.$port" ;;
esac
exit 0
`);
  executable(join(bin, "sleep"), "#!/usr/bin/env bash\n/bin/sleep 0.02\n");

  const child = spawn(join(repo, "scripts/live/serve.sh"), legs, {
    detached: true,
    env: {
      PATH: `${bin}:${process.env.PATH}`, HOME: home, TMPDIR: fixture, STATE: state,
      MCP_SSO_INFRA_DIR: infra, MCP_SSO_CLOUDFLARE_STACK: "cf", MCP_SSO_TUNNEL: TUNNEL,
      MCP_SSO_READINESS_POLLS: "60",
      BYSTANDER_PID: bystanderPid, BYSTANDER_SIGNALED: bystanderSignaled,
      FAKE_SERVER_JS: serverJs, FAKE_BYSTANDER_JS: bystanderJs, RUN_SH_LOG: runShLog,
      STARTUP_EXIT: mode === "startup-failure" ? "23" : "",
      TUNNEL_MODE: ["normal", "failure", "startup-timeout"].includes(mode) ? mode : "signal",
      LSOF_MODE: mode === "port-busy" ? "busy" : mode === "foreign-listener" ? "foreign" : "",
      TUNNEL_STARTED: tunnelStarted, TUNNEL_STOPPED: tunnelStopped, TUNNEL_CONFIG_COPY: tunnelConfig, RELEASE_TUNNEL: releaseTunnel,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  try {
    if (mode === "sigint" || mode === "sigterm") {
      // Signal serve.sh ALONE (by pid, not the process group) and never
      // release the tunnel: cleanup must terminate the tunnel it started.
      await waitForFile(tunnelStarted);
      process.kill(child.pid, mode === "sigint" ? "SIGINT" : "SIGTERM");
    }
    const result = await waitForExit(child, mode);
    const expected = {
      normal: 0, failure: 7, sigint: 130, sigterm: 143, "startup-failure": 23,
      "startup-timeout": 1, "foreign-listener": 1, "port-busy": 1,
    }[mode];
    assert.deepEqual(result, { code: expected, signal: null }, `${mode}: ${stderr}`);
    const gatewayPorts = legs.map((leg) => PORTS[leg].gateway);
    if (["startup-failure", "startup-timeout", "foreign-listener", "port-busy"].includes(mode)) {
      assert.equal(existsSync(tunnelStarted), false, `${mode}: a failed or unproven server never starts the public tunnel`);
    } else {
      assert.equal(existsSync(tunnelStarted), true, `${mode}: the tunnel starts once every leg is ready`);
      const config = readFileSync(tunnelConfig, "utf8");
      assert.match(config, new RegExp(`^tunnel: ${TUNNEL}$`, "m"));
      assert.match(config, new RegExp(`^credentials-file: ${join(home, ".cloudflared", `${TUNNEL}.json`)}$`, "m"));
      for (const leg of legs) {
        assert.match(config, new RegExp(`- hostname: ${ORIGINS[leg].slice("https://".length)}\\n    service: http://127.0.0.1:${PORTS[leg].gateway}$`, "m"),
          "the ingress targets the address readiness and lsof proved");
      }
      assert.match(config, /- service: http_status:404\n$/);
    }
    if (mode === "port-busy") {
      assert.equal(existsSync(runShLog), false, "a busy port stops serve.sh before any server starts");
    } else if (mode !== "startup-failure") {
      for (const port of gatewayPorts) {
        assert.equal(readFileSync(join(state, `terminated.${port}`), "utf8"), "terminated", `${mode}: cleanup terminated the server on ${port}`);
      }
      const started = readFileSync(runShLog, "utf8").trim().split("\n").sort();
      assert.deepEqual(started, legs.map((leg) => `examples/fastify-sqlite/index.ts ${leg} PORT=${PORTS[leg].gateway}`).sort());
    }
    const config = /^tunnel config: (.+)$/m.exec(stdout)?.[1];
    if (mode !== "port-busy") {
      assert.ok(config, `${mode}: serve.sh printed its generated config path: ${stdout}`);
      assert.equal(existsSync(config), false, `${mode}: cleanup removed the generated tunnel config`);
    }
    assert.deepEqual(readdirSync(fixture).filter((name) => name.startsWith("mcp-sso-tunnel-")), [], `${mode}: no tunnel tempfile survives`);
    if (!["startup-failure", "port-busy"].includes(mode)) {
      const unrelatedPid = Number(readFileSync(bystanderPid, "utf8"));
      assert.doesNotThrow(() => process.kill(unrelatedPid, 0), `${mode}: an unrelated process in the group survived cleanup`);
      assert.equal(existsSync(bystanderSignaled), false, `${mode}: cleanup never signaled an unrelated process in the group`);
    }
    if (mode === "sigint" || mode === "sigterm") {
      assert.equal(readFileSync(tunnelStopped, "utf8"), "stopped", `${mode}: cleanup terminated the tunnel it started`);
    }
    if (mode === "foreign-listener") assert.match(stderr, /is not the server just started/);
    if (mode === "port-busy") assert.match(stderr, /already has a listener/);
  } finally {
    if (child.pid) try { process.kill(-child.pid, "SIGKILL"); } catch { /* already gone */ }
    if (existsSync(bystanderPid)) try { process.kill(Number(readFileSync(bystanderPid, "utf8")), "SIGKILL"); } catch { /* already gone */ }
    rmSync(fixture, { recursive: true, force: true });
  }
}

test("serve.sh proves readiness of the server it started and cleans up only what it owns", async (t) => {
  for (const mode of ["normal", "failure", "sigint", "sigterm", "startup-failure", "startup-timeout", "foreign-listener", "port-busy"]) {
    await t.test(mode, () => runServeScenario(mode));
  }
  await t.test("two legs share one tunnel ingress and one cleanup", () => runServeScenario("normal", ["cloudflare_access", "google"]));
});
