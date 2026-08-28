#!/usr/bin/env node
// Small operator wrapper for a manual client session. It starts the existing
// live server, follows its audit trail, and removes only this helper's fixed MCP
// entries from Claude Code and Codex.
import { spawn, spawnSync } from "node:child_process";
import { unlinkSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  LEGS, buildFlows, clientEntries, flowKey, isFragment, outcomeOf, readAudit,
  readPrivateJson, resultFor, validateLegs, writePrivateJson, writeResults,
} from "./session-support.mjs";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const STATE_DIR = join(ROOT, ".live-state");
const SESSION_FILE = join(STATE_DIR, "session.json");
const RESULTS_FILE = join(STATE_DIR, "session-results.jsonl");
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

function command(cmd, args, options = {}) {
  return spawnSync(cmd, args, { encoding: "utf8", timeout: 15_000, maxBuffer: 64 * 1024, ...options });
}

function checkout() {
  const head = command("git", ["-C", ROOT, "rev-parse", "HEAD"]);
  if (head.status !== 0 || !/^[0-9a-f]{40,64}\n?$/.test(head.stdout ?? "")) {
    throw new Error("the live-session checkout commit is unavailable");
  }
  const status = command("git", ["-C", ROOT, "status", "--porcelain", "--untracked-files=all"]);
  if (status.status !== 0) throw new Error("the live-session checkout status is unavailable");
  return { commit: head.stdout.trim(), clean: status.stdout === "" };
}

function modeFromEnvironment() {
  const mode = process.env.MCP_SSO_DCR_MODE ?? "stored";
  if (!new Set(["stored", "stateless"]).has(mode)) throw new Error("MCP_SSO_DCR_MODE must be stored or stateless");
  return mode;
}

function isAbsent(result) {
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  return result.status === 1 && output.includes("No MCP server named");
}

function cleanupClients(legs = LEGS) {
  let failed = false;
  for (const { cli, name } of clientEntries(legs)) {
    const result = command(cli, ["mcp", "remove", name]);
    if (result.status === 0 || isAbsent(result)) process.stdout.write(`cleaned ${cli} MCP entry ${name}\n`);
    else {
      failed = true;
      process.stderr.write(`session.mjs: cleanup failed for ${cli} MCP entry ${name}\n`);
    }
  }
  return !failed;
}

function validSession(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const fields = ["clean", "commit", "legs", "mode", "startedAt", "status", "version"];
  if (Object.keys(value).sort().join("\0") !== fields.join("\0")) return undefined;
  let legs;
  try { legs = validateLegs(value.legs); } catch { return undefined; }
  const started = typeof value.startedAt === "string" ? Date.parse(value.startedAt) : Number.NaN;
  if (value.version !== 1 || value.status !== "ready" || !["stored", "stateless"].includes(value.mode)
    || !/^[0-9a-f]{40,64}$/.test(value.commit)
    || typeof value.clean !== "boolean" || Number.isNaN(started)
    || new Date(started).toISOString() !== value.startedAt) return undefined;
  return { legs, mode: value.mode, commit: value.commit, clean: value.clean, startedAt: value.startedAt };
}

function invalidateSession() {
  try { unlinkSync(SESSION_FILE); return true; } catch (error) {
    if (error?.code === "ENOENT") return true;
    process.stderr.write("session.mjs: failed to invalidate the session state\n");
    return false;
  }
}

async function serve(args) {
  const legs = validateLegs(args);
  const mode = modeFromEnvironment();
  const source = checkout();
  const state = { version: 1, status: "starting", legs, mode, ...source, startedAt: new Date().toISOString() };
  writePrivateJson(SESSION_FILE, state);
  const child = spawn(join(ROOT, "scripts/live/serve.sh"), legs, {
    detached: true, stdio: ["inherit", "inherit", "inherit", "pipe", "pipe"],
    env: { ...process.env, MCP_SSO_SESSION_READY_FD: "3", MCP_SSO_SESSION_PARENT_FD: "4" },
  });
  let ready = false;
  let readinessFailed = false;
  let stoppedForReadiness = false;
  let childExited = false;
  let emptyMarkerTimer;
  let marker = "";
  const readiness = child.stdio[3];
  const failReadiness = () => {
    readinessFailed = true;
    try { stoppedForReadiness = child.kill("SIGTERM") || stoppedForReadiness; } catch { /* the child already stopped */ }
  };
  child.once("exit", () => {
    childExited = true;
    if (emptyMarkerTimer !== undefined) clearTimeout(emptyMarkerTimer);
  });
  readiness.setEncoding("utf8");
  readiness.on("data", (chunk) => {
    marker += chunk;
    if (Buffer.byteLength(marker) > 16) failReadiness();
  });
  readiness.on("error", failReadiness);
  readiness.once("end", () => {
    if (!readinessFailed && marker === "ready\n") {
      try { writePrivateJson(SESSION_FILE, { ...state, status: "ready" }); ready = true; } catch {
        failReadiness();
      }
    } else if (!ready) {
      readinessFailed = true;
      if (marker !== "") failReadiness();
      else {
        emptyMarkerTimer = setTimeout(() => {
          if (!childExited && !ready) failReadiness();
        }, 100);
      }
    }
  });
  let forwarded;
  const forward = (signal) => {
    if (forwarded === undefined) {
      forwarded = signal;
      try { child.kill(signal); } catch { /* the child already stopped */ }
    }
  };
  const onInt = () => { forward("SIGINT"); };
  const onTerm = () => { forward("SIGTERM"); };
  process.on("SIGINT", onInt);
  process.on("SIGTERM", onTerm);
  const result = await new Promise((resolve) => {
    child.once("error", () => { readinessFailed = true; resolve({ code: 1, signal: null }); });
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  process.off("SIGINT", onInt);
  process.off("SIGTERM", onTerm);
  const stateClean = ready || invalidateSession();
  const clean = cleanupClients(legs);
  if (forwarded !== undefined) return forwarded === "SIGINT" ? 130 : 143;
  if (stoppedForReadiness || (readinessFailed && result.code === 0)) return 1;
  if (typeof result.code === "number" && result.code !== 0) return result.code;
  if (result.signal !== null) return result.signal === "SIGINT" ? 130 : 143;
  return clean && stateClean && !readinessFailed ? 0 : 1;
}

function clientVersions() {
  const versions = {};
  for (const [cli, kind] of [["claude", "claude-code"], ["codex", "codex"]]) {
    const result = command(cli, ["--version"]);
    const line = result.status === 0 ? (result.stdout ?? "").split("\n")[0]?.trim() : undefined;
    if (line && line.length <= 200 && /^[\x20-\x7e]+$/.test(line)) versions[kind] = line;
  }
  return versions;
}

function readFlows(session) {
  const startedAt = Date.parse(session.startedAt);
  return new Map(session.legs.map((leg) => [leg, buildFlows(readAudit(join(STATE_DIR, leg, "audit.jsonl"))
    .filter((event) => Date.parse(event.occurredAt) >= startedAt))]));
}

function printResult(result) {
  const row = result.row === undefined ? "extra" : result.row;
  const calls = result.toolCalls === 0 ? (result.ambiguousToolCalls > 0 ? `no attributable protected /mcp request (${result.ambiguousToolCalls} ambiguous)` : "no protected /mcp request") : `${result.toolCalls} protected /mcp request(s)`;
  process.stdout.write(`${result.verdict} ${row} ${result.leg} ${result.clientLabel}: ${calls}\n`);
}

async function watch(args) {
  const allowed = new Set(["--all", "--once", "--codex-dcr"]);
  if (args.some((arg) => !allowed.has(arg)) || new Set(args).size !== args.length) {
    throw new Error("usage: session.mjs watch [--all] [--once] [--codex-dcr]");
  }
  const once = args.includes("--once");
  const fromStart = once || args.includes("--all");
  const codexDcr = args.includes("--codex-dcr");
  const session = validSession(readPrivateJson(SESSION_FILE));
  if (session === undefined) throw new Error("run session.mjs serve before watch");
  const versions = clientVersions();
  const reported = new Set();
  if (!fromStart) {
    for (const [leg, flows] of readFlows(session)) {
      for (const flow of flows) {
        if (!isFragment(flow) && ["PASS", "DENIED"].includes(outcomeOf(flow).verdict)) {
          reported.add(flowKey(leg, flow));
        }
      }
    }
  }
  let stopped = false;
  let failed = false;
  const stop = () => { stopped = true; };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  const oneShot = [];
  const scan = (finalize) => {
    let byLeg;
    try { byLeg = readFlows(session); } catch {
      process.stderr.write("session.mjs: an audit trail is unreadable\n");
      failed = true;
      return;
    }
    for (const [leg, flows] of byLeg) {
      for (const flow of flows) {
        if (isFragment(flow)) continue;
        const key = flowKey(leg, flow);
        if (reported.has(key)) continue;
        const outcome = outcomeOf(flow);
        if (!finalize && ["INCOMPLETE", "TOKEN_ONLY"].includes(outcome.verdict)) continue;
        const result = resultFor({
          leg, flow, flows, mode: session.mode, commit: session.commit, clean: session.clean,
          clientVersions: versions, observedAt: new Date().toISOString(), codexDcr,
        });
        reported.add(key);
        printResult(result);
        if (once) oneShot.push(result);
        else writeResults(RESULTS_FILE, [result]);
      }
    }
  };
  if (once) scan(true);
  else {
    while (!stopped && !failed) { scan(false); if (!stopped && !failed) await sleep(1_000); }
    if (!failed) scan(true);
  }
  process.off("SIGINT", stop);
  process.off("SIGTERM", stop);
  if (once && !failed) writeResults(RESULTS_FILE, oneShot, { replace: true });
  if (!failed) process.stdout.write(`saved ${once ? oneShot.length : "new"} result(s) in .live-state/session-results.jsonl\n`);
  return failed ? 1 : 0;
}

async function main([name, ...args]) {
  if (name === "serve") return serve(args);
  if (name === "watch") return watch(args);
  if (name === "cleanup" && args.length === 0) return cleanupClients() ? 0 : 1;
  throw new Error("usage: session.mjs serve [cloudflare_access|entra|google ...] | watch [--all] [--once] [--codex-dcr] | cleanup");
}

try { process.exitCode = await main(process.argv.slice(2)); } catch (error) {
  process.stderr.write(`session.mjs: ${error instanceof Error ? error.message : "failed"}\n`);
  process.exitCode = 1;
}
