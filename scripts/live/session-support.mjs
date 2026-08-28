import { spawnSync } from "node:child_process";
import {
  chmodSync, closeSync, constants, fstatSync, ftruncateSync, lstatSync, mkdirSync, openSync, readFileSync, writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

export const LEGS = Object.freeze(["cloudflare_access", "entra", "google"]);
const MAX_AUDIT_BYTES = 10 * 1024 * 1024;
const MAX_AUDIT_ROWS = 10_000;
const MAX_FIELD_BYTES = 2_048;
const SHORT = Object.freeze({
  "oauth.cimd.fetch": "cimd", "oauth.register": "register", "identity.verify": "identity",
  "oauth.authorize.prepare": "prepare", "oauth.upstream.callback": "callback",
  "oauth.authorize.approve": "consent", "oauth.token.authorization_code": "token",
  "auth.request": "/mcp", "oauth.token.refresh": "refresh", "oauth.revoke": "revoke",
});
const SESSION_EVENTS = new Set(Object.keys(SHORT));
const EVENTS = new Set([
  ...SESSION_EVENTS, "oauth.pairing.attempt", "oauth.device.authorization", "oauth.device.approve",
  "oauth.token.device_code", "oauth.token.client_credentials", "oauth.client.provision",
  "oauth.client.rotate_secret", "oauth.client.disable",
]);
const ROWS = Object.freeze([
  { id: "A1", leg: "cloudflare_access", kind: "claude-code", mode: "any" },
  { id: "A2", leg: "entra", kind: "claude-code", mode: "any" },
  { id: "A3", leg: "google", kind: "claude-code", mode: "any" },
  { id: "B1", leg: "cloudflare_access", kind: "codex", mode: "any" },
  { id: "B2", leg: "entra", kind: "codex", mode: "any" },
  { id: "B3", leg: "google", kind: "codex", mode: "any" },
  { id: "C1", leg: "cloudflare_access", kind: "chatgpt", mode: "any" },
  { id: "C2", leg: "entra", kind: "chatgpt", mode: "stored" },
  { id: "F1", leg: "cloudflare_access", kind: "claudeai", mode: "any" },
  { id: "F2", leg: "entra", kind: "claudeai", mode: "stored" },
  { id: "F2s", leg: "entra", kind: "claudeai", mode: "stateless" },
  { id: "F3", leg: "google", kind: "claudeai", mode: "any" },
]);

const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype;
const optionalField = (row, name) => {
  const value = row[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || Buffer.byteLength(value) > MAX_FIELD_BYTES || /[\r\n\0]/.test(value)) {
    throw new Error(`audit row has an invalid ${name}`);
  }
  return value;
};

export function validateLegs(values) {
  const legs = values.length === 0 ? [...LEGS] : values;
  if (legs.some((leg) => !LEGS.includes(leg))) throw new Error("unknown live-session leg");
  if (new Set(legs).size !== legs.length) throw new Error("a live-session leg is named twice");
  return legs;
}

export const entryName = (leg) => `mcp-sso-live-${leg}`;
export function clientEntries(legs = LEGS) {
  return legs.flatMap((leg) => [
    { cli: "claude", name: entryName(leg) },
    { cli: "codex", name: entryName(leg) },
  ]);
}

function readBoundedFile(path) {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new Error("live-session file reads require O_NOFOLLOW");
  }
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw new Error("live-session file cannot be opened");
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_AUDIT_BYTES) throw new Error("live-session file is not a bounded regular file");
    const body = readFileSync(fd, "utf8");
    if (Buffer.byteLength(body) > MAX_AUDIT_BYTES) throw new Error("live-session file grew beyond its size limit");
    return body;
  } finally {
    closeSync(fd);
  }
}

function inspectPrivateDir(path, uid) {
  let stat;
  try { stat = lstatSync(path); } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw new Error("live-session state directory cannot be inspected");
  }
  if (!stat.isDirectory() || (uid !== undefined && stat.uid !== uid) || (stat.mode & 0o077) !== 0) {
    throw new Error("live-session state directory is not private");
  }
  return stat;
}

function readPrivateFile(path, uid) {
  const before = inspectPrivateDir(dirname(path), uid);
  if (before === undefined) return undefined;
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new Error("live-session file reads require O_NOFOLLOW");
  }
  let fd;
  try {
    try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch (error) {
      if (error?.code === "ENOENT") return undefined;
      throw new Error("live-session state cannot be opened");
    }
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || (uid !== undefined && stat.uid !== uid)
      || (stat.mode & 0o077) !== 0 || stat.size > MAX_AUDIT_BYTES) {
      throw new Error("live-session state is not a private bounded regular file");
    }
    const body = readFileSync(fd, "utf8");
    if (Buffer.byteLength(body) > MAX_AUDIT_BYTES) throw new Error("live-session state grew beyond its size limit");
    const after = inspectPrivateDir(dirname(path), uid);
    if (after === undefined || before.dev !== after.dev || before.ino !== after.ino) {
      throw new Error("live-session state directory changed while reading");
    }
    return body;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function readAudit(path) {
  const body = readBoundedFile(path);
  if (body === undefined || body === "") return [];
  const lines = body.split("\n").filter(Boolean);
  if (lines.length > MAX_AUDIT_ROWS) throw new Error("audit trail has too many rows");
  return lines.map((line) => {
    let row;
    try { row = JSON.parse(line); } catch { throw new Error("audit trail contains invalid JSON"); }
    if (!isPlainObject(row)) throw new Error("audit trail contains a non-object row");
    const event = optionalField(row, "event");
    const status = optionalField(row, "status");
    const reason = optionalField(row, "reason");
    const occurredAt = optionalField(row, "occurredAt");
    const timestamp = occurredAt === undefined ? Number.NaN : Date.parse(occurredAt);
    if (!event || !EVENTS.has(event) || !["success", "failure"].includes(status)
      || (reason !== undefined && !/^[a-z0-9_]+$/.test(reason))
      || !occurredAt || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(occurredAt)
      || Number.isNaN(timestamp) || new Date(timestamp).toISOString() !== occurredAt) {
      throw new Error("audit row has no valid event status");
    }
    return {
      event, status, reason, clientId: optionalField(row, "clientId"),
      redirectHost: optionalField(row, "redirectHost"), occurredAt,
    };
  });
}

const isChallenge = (event) => event.event === "auth.request" && event.status === "failure";
const STARTS = new Set(["oauth.cimd.fetch", "oauth.register"]);
export function buildFlows(events) {
  const flows = [];
  const active = new Map();
  const attempts = new Map();
  let held = [];
  for (const event of events) {
    if (isChallenge(event)) continue;
    if (!SESSION_EVENTS.has(event.event)) continue;
    if (event.clientId === undefined) {
      if (event.event === "identity.verify" && event.status === "failure") {
        flows.push({ clientId: "unattributed", events: [event], unbound: true });
      } else held.push(event);
      continue;
    }
    let flow = active.get(event.clientId);
    let clientAttempts = attempts.get(event.clientId);
    if (clientAttempts === undefined) { clientAttempts = []; attempts.set(event.clientId, clientAttempts); }
    const startsAnotherAttempt = event.event === "oauth.authorize.prepare"
      && flow?.events.some((candidate) => candidate.event === "oauth.authorize.prepare");
    if (flow === undefined || STARTS.has(event.event) || startsAnotherAttempt) {
      flow = { clientId: event.clientId, events: [] };
      flows.push(flow);
      clientAttempts.push(flow);
      active.set(event.clientId, flow);
    }
    if (event.event === "auth.request" && clientAttempts.length > 1) {
      for (const attempt of clientAttempts) attempt.ambiguousToolCalls = (attempt.ambiguousToolCalls ?? 0) + 1;
      continue;
    }
    if (held.length > 0) { flow.events.push(...held); held = []; }
    flow.events.push(event);
  }
  return flows;
}

export const isFragment = (flow) => !flow.events.some((event) => event.event === "oauth.authorize.prepare"
  || event.event === "oauth.token.authorization_code") && flow.unbound !== true;

export function classifyClient(flow, siblings = [], { codexDcr = false } = {}) {
  if (flow.unbound === true) return {
    kind: "unattributed", label: "unattributed identity denial", redirectHost: "",
  };
  const identifiedHost = (candidate) => candidate.events.find((event) => event.event === "oauth.authorize.prepare"
    && event.clientId === candidate.clientId && event.redirectHost)?.redirectHost
    ?? candidate.events.find((event) => event.clientId === candidate.clientId && event.redirectHost)?.redirectHost;
  const siblingHost = siblings.filter((candidate) => candidate.clientId === flow.clientId)
    .map(identifiedHost).find((redirectHost) => redirectHost !== undefined);
  const origin = identifiedHost(flow)
    ?? siblingHost
    ?? flow.events.find((event) => event.redirectHost)?.redirectHost
    ?? "";
  let redirectHost = origin;
  try { redirectHost = new URL(origin).hostname; } catch { redirectHost = origin.replace(/^[a-z]+:\/\//i, "").split(":")[0]; }
  if (redirectHost.startsWith("[") && redirectHost.endsWith("]")) redirectHost = redirectHost.slice(1, -1);
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(redirectHost);
  let document;
  try { document = new URL(flow.clientId); } catch { document = undefined; }
  if (document === undefined && codexDcr && loopback && /^mcpdc_[a-f0-9]{32}$/.test(flow.clientId)) return {
    kind: "codex", label: "Codex CLI (operator-annotated DCR)", redirectHost,
    attribution: "operator-annotated",
  };
  if (document === undefined) return {
    kind: loopback ? "cli-dcr" : "dcr-hosted",
    label: loopback ? "local CLI (dynamic registration)" : "hosted client (dynamic registration)", redirectHost,
  };
  if (/(^|\.)(chatgpt|openai)\.com$/.test(document.hostname)) return {
    kind: loopback ? "codex" : "chatgpt", label: loopback ? "Codex CLI" : "ChatGPT connector", redirectHost,
  };
  if (/(^|\.)(claude\.ai|anthropic\.com)$/.test(document.hostname)) return {
    kind: loopback ? "claude-code" : "claudeai", label: loopback ? "Claude Code" : "claude.ai connector", redirectHost,
  };
  return { kind: "cimd-other", label: `CIMD client on ${document.hostname}`, redirectHost };
}

export function outcomeOf(flow) {
  const denial = flow.events.find((event) => event.event === "identity.verify" && event.status === "failure");
  const tokenAt = flow.events.findIndex((event) => event.event === "oauth.token.authorization_code" && event.status === "success");
  const toolCalls = tokenAt < 0 ? 0 : flow.events.slice(tokenAt + 1)
    .filter((event) => event.event === "auth.request" && event.status === "success").length;
  const ambiguousToolCalls = flow.ambiguousToolCalls ?? 0;
  if (denial !== undefined) return { verdict: "DENIED", reason: denial.reason ?? "unspecified", toolCalls, ambiguousToolCalls };
  if (tokenAt >= 0 && toolCalls > 0) return { verdict: "PASS", toolCalls, ambiguousToolCalls };
  if (tokenAt >= 0) return { verdict: "TOKEN_ONLY", toolCalls, ambiguousToolCalls };
  return { verdict: "INCOMPLETE", toolCalls: 0, ambiguousToolCalls };
}

export function chainOf(flow) {
  const steps = [];
  for (const event of flow.events) {
    const name = `${SHORT[event.event] ?? event.event}${event.status === "failure" ? `:${event.reason ?? "failure"}` : ""}`;
    const last = steps.at(-1);
    if (last?.name === name) last.count += 1;
    else steps.push({ name, count: 1 });
  }
  return steps.map((step) => step.count > 1 ? `${step.name} x${step.count}` : step.name).join(" -> ");
}

export function resultFor({ leg, flow, flows, mode, commit, clean, clientVersions, observedAt, codexDcr = false }) {
  const client = classifyClient(flow, flows, { codexDcr });
  const outcome = outcomeOf(flow);
  const row = ROWS.find((candidate) => candidate.leg === leg && candidate.kind === client.kind
    && (candidate.mode === "any" || candidate.mode === mode));
  return {
    row: row?.id, leg, mode, client: client.kind, clientLabel: client.label,
    clientId: flow.clientId, redirectHost: client.redirectHost,
    clientVersion: clientVersions[client.kind], clientAttribution: client.attribution,
    ...outcome, chain: chainOf(flow), commit, clean, observedAt,
  };
}

export function flowKey(leg, flow) {
  const first = flow.events[0];
  return `${leg}\0${flow.clientId}\0${first?.occurredAt ?? ""}\0${first?.event ?? ""}`;
}

function ensurePrivateDir(path, uid = process.getuid?.()) {
  let stat;
  try { stat = lstatSync(path); } catch (error) {
    if (error?.code !== "ENOENT") throw new Error("live-session state directory cannot be inspected");
    mkdirSync(path, { mode: 0o700 });
    chmodSync(path, 0o700);
    stat = lstatSync(path);
  }
  if (!stat.isDirectory() || (uid !== undefined && stat.uid !== uid) || (stat.mode & 0o077) !== 0) {
    throw new Error("live-session state directory is not private");
  }
}

export function writeResults(path, results, { replace = false, beforeWrite } = {}) {
  if (!Array.isArray(results) || results.length > MAX_AUDIT_ROWS) throw new Error("live-session result set is invalid");
  if (beforeWrite !== undefined && typeof beforeWrite !== "function") throw new Error("live-session result guard is invalid");
  ensurePrivateDir(dirname(path));
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) throw new Error("result writes require O_NOFOLLOW");
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK
    | (replace ? 0 : constants.O_APPEND);
  let fd;
  try {
    try { fd = openSync(path, flags, 0o600); } catch { throw new Error("result path cannot be opened"); }
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0) throw new Error("result path is not a private regular file");
    beforeWrite?.();
    if (replace) ftruncateSync(fd, 0);
    const body = results.map((result) => JSON.stringify(result)).join("\n");
    if (body !== "") writeFileSync(fd, `${body}\n`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function readPrivateJson(path, uid = process.getuid?.()) {
  const body = readPrivateFile(path, uid);
  if (body === undefined) return undefined;
  try { return JSON.parse(body); } catch { throw new Error("live-session state contains invalid JSON"); }
}

export function writePrivateJson(path, value) {
  ensurePrivateDir(dirname(path));
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) throw new Error("state writes require O_NOFOLLOW");
  let fd;
  try {
    try {
      fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
    } catch { throw new Error("state path cannot be opened"); }
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0) throw new Error("state path is not a private regular file");
    ftruncateSync(fd, 0);
    writeFileSync(fd, `${JSON.stringify(value)}\n`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function acquireSessionLock(path) {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new Error("live-session lock requires O_NOFOLLOW");
  }
  ensurePrivateDir(dirname(path));
  let fd;
  try {
    fd = openSync(path, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0) throw new Error("live-session lock is not private");
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (error instanceof Error && error.message === "live-session lock is not private") throw error;
    throw new Error("live-session lock cannot be opened");
  }
  const utility = process.platform === "darwin" ? { path: "/usr/bin/lockf", args: ["-s", "-t", "0", "3"], busy: 75 }
    : process.platform === "linux" ? { path: "/usr/bin/flock", args: ["-n", "3"], busy: 1 } : undefined;
  if (utility === undefined) { closeSync(fd); throw new Error("live-session locking is unsupported on this platform"); }
  const result = spawnSync(utility.path, utility.args, {
    stdio: ["ignore", "ignore", "ignore", fd], timeout: 5_000,
  });
  if (result.status !== 0) {
    closeSync(fd);
    if (result.status === utility.busy) throw new Error("another live session is active");
    throw new Error("live-session lock acquisition failed");
  }
  let released = false;
  return () => {
    if (released) throw new Error("live-session lock was already released");
    released = true;
    closeSync(fd);
  };
}
