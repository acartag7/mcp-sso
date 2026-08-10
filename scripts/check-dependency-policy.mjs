import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  validateAdvisoryExceptionRecords,
  validateExceptionBindings,
  verifyAdvisoryExceptionEvidence,
  workspaceCooldownConfig,
} from "./dependency-policy-exceptions.mjs";

const START = "<!-- dependency-policy:start -->";
const END = "<!-- dependency-policy:end -->";
const DAY_MS = 86_400_000;
const FIRST_PARTY_EXCEPTION = "acartag7/engineering-os";

function fail(messages) {
  if (messages.length > 0) {
    throw new Error(`dependency policy violations:\n${messages.map((m) => `- ${m}`).join("\n")}`);
  }
}

function object(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function policyJson(markdown) {
  const start = markdown.indexOf(START);
  const end = markdown.indexOf(END);
  if (start < 0 || end <= start) throw new Error("dependency policy markers are missing or misordered");
  const block = markdown.slice(start + START.length, end);
  const match = /^\s*```json\s*\n([\s\S]*?)\n```\s*$/.exec(block);
  if (!match) throw new Error("dependency policy block must contain exactly one JSON fence");
  return JSON.parse(match[1]);
}

export async function loadDependencyPolicy(root = process.cwd()) {
  const markdown = await readFile(resolve(root, "docs/dependency-ledger.md"), "utf8");
  const policy = object(policyJson(markdown), "dependency policy");
  object(policy.packages, "dependency policy packages");
  object(policy.actions, "dependency policy actions");
  if (!Number.isInteger(policy.minimumAgeDays) || policy.minimumAgeDays < 1) {
    throw new Error("dependency policy minimumAgeDays must be a positive integer");
  }
  return policy;
}

function validDate(date) {
  return typeof date === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(date)
    && Number.isFinite(Date.parse(date));
}

function assertRecordShape(policy) {
  const errors = [];
  const exceptions = validateAdvisoryExceptionRecords(policy.advisoryExceptions);
  errors.push(...exceptions.errors);
  for (const [name, recordValue] of Object.entries(policy.packages)) {
    const record = object(recordValue, `package ${name}`);
    if (typeof record.version !== "string" || record.version === "") errors.push(`${name}: version is invalid`);
    if (!validDate(record.published)) errors.push(`${name}: published date is invalid`);
  }
  for (const [name, recordValue] of Object.entries(policy.actions)) {
    const record = object(recordValue, `action ${name}`);
    if (!/^[0-9a-f]{40}$/.test(record.sha)) errors.push(`${name}: sha must be 40 lowercase hex characters`);
    if (!validDate(record.published)) errors.push(`${name}: published date is invalid`);
    if (record.firstPartyException === true) {
      if (name !== FIRST_PARTY_EXCEPTION) errors.push(`${name}: is not eligible for the first-party exception`);
      if (record.tag !== undefined) errors.push(`${name}: a first-party exception must not claim a release tag`);
    } else if (typeof record.tag !== "string" || !/^v\d/.test(record.tag)) {
      errors.push(`${name}: third-party action tag is invalid`);
    }
    if (name === FIRST_PARTY_EXCEPTION && record.firstPartyException !== true) {
      errors.push(`${name}: the documented first-party exception must be explicit`);
    }
  }
  fail(errors);
  return exceptions.byPackage;
}

function expectedActionComment(record) {
  return record.firstPartyException === true
    ? `first-party exception (${record.published.slice(0, 10)})`
    : `${record.tag} (${record.published.slice(0, 10)})`;
}

async function packagePins(root) {
  const pkg = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
  const pins = {
    ...object(pkg.dependencies ?? {}, "dependencies"),
    ...object(pkg.devDependencies ?? {}, "devDependencies"),
    ...object(pkg.optionalDependencies ?? {}, "optionalDependencies"),
  };
  const manager = /^pnpm@(.+)$/.exec(pkg.packageManager ?? "");
  if (!manager) throw new Error("packageManager must be an exact pnpm@version pin");
  pins.pnpm = manager[1];
  return pins;
}

async function workflowPins(root) {
  const dir = resolve(root, ".github/workflows");
  const files = (await readdir(dir)).filter((name) => /\.ya?ml$/.test(name)).sort();
  const uses = [];
  const pattern = /^\s*(?:-\s+)?uses:\s*["']?([^@\s"']+)@([^#\s"']+)["']?\s*(?:#\s*(.*))?$/;
  for (const file of files) {
    const lines = (await readFile(resolve(dir, file), "utf8")).split(/\r?\n/);
    lines.forEach((line, index) => {
      if (!/^\s*(?:-\s+)?uses:/.test(line)) return;
      const match = pattern.exec(line);
      if (!match) throw new Error(`${file}:${index + 1}: uses entry is not a literal action pin`);
      if (match[1].startsWith("./")) return;
      const parts = match[1].split("/");
      if (parts.length < 2) throw new Error(`${file}:${index + 1}: action repository is malformed`);
      if (match[1] === "pnpm/action-setup") {
        const stepIndent = line.search(/\S/);
        for (let next = index + 1; next < lines.length; next++) {
          const candidate = lines[next];
          if (/^\s*(?:#.*)?$/.test(candidate)) continue;
          if (candidate.search(/\S/) <= stepIndent) break;
          if (/^\s*version\s*:/.test(candidate) || /^\s*with:\s*\{[^}]*\bversion\s*:/.test(candidate)) {
            throw new Error(`${file}:${next + 1}: pnpm/action-setup must read packageManager without a version override`);
          }
        }
      }
      uses.push({ file, line: index + 1, repo: parts.slice(0, 2).join("/"), ref: match[2], comment: match[3] ?? "" });
    });
  }
  return uses;
}

function assertAge(name, published, minimumAgeDays, now, errors) {
  const age = now.getTime() - Date.parse(published);
  if (age < minimumAgeDays * DAY_MS) errors.push(`${name}: ${published} is younger than ${minimumAgeDays} days`);
}

export async function verifyLocalDependencyPolicy(root = process.cwd(), now = new Date()) {
  const policy = await loadDependencyPolicy(root);
  const exceptions = assertRecordShape(policy);
  const errors = [];
  const workspace = await workspaceCooldownConfig(root);
  const expectedWorkspaceAge = policy.minimumAgeDays * 1440;
  if (workspace.minimumAgeMinutes !== expectedWorkspaceAge) {
    errors.push(`pnpm-workspace.yaml minimumReleaseAge ${workspace.minimumAgeMinutes} != ledger ${expectedWorkspaceAge}`);
  }
  const pins = await packagePins(root);
  errors.push(...validateExceptionBindings({
    byPackage: exceptions,
    excludedPackages: workspace.excludedPackages,
    pins,
    packages: policy.packages,
    now,
  }));
  const packageNames = new Set([...Object.keys(pins), ...Object.keys(policy.packages)]);
  for (const name of [...packageNames].sort()) {
    if (!(name in pins)) errors.push(`${name}: ledger package is not directly pinned`);
    else if (!(name in policy.packages)) errors.push(`${name}: direct package pin is missing from the ledger`);
    else if (pins[name] !== policy.packages[name].version) errors.push(`${name}: package pin ${pins[name]} != ledger ${policy.packages[name].version}`);
    else if (!exceptions.has(name)) assertAge(name, policy.packages[name].published, policy.minimumAgeDays, now, errors);
  }

  const used = new Set();
  for (const action of await workflowPins(root)) {
    const record = policy.actions[action.repo];
    if (!record) {
      errors.push(`${action.file}:${action.line}: ${action.repo} is missing from the ledger`);
      continue;
    }
    used.add(action.repo);
    if (action.ref !== record.sha) errors.push(`${action.file}:${action.line}: ${action.repo} pin does not match the ledger`);
    if (action.comment !== expectedActionComment(record)) errors.push(`${action.file}:${action.line}: ${action.repo} version/date comment does not match the ledger`);
    if (record.firstPartyException !== true) {
      assertAge(action.repo, record.published, policy.minimumAgeDays, now, errors);
    }
  }
  for (const name of Object.keys(policy.actions).sort()) {
    if (!used.has(name)) errors.push(`${name}: ledger action is unused`);
  }
  fail(errors);
  return policy;
}

async function fetchJson(url, fetchImpl, token) {
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "mcp-sso-dependency-policy" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetchImpl(url, { headers });
  if (!response.ok) throw new Error(`${url}: upstream returned ${response.status}`);
  return await response.json();
}

export async function verifyRemoteDependencyPolicy(policy, options = {}) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const token = options.token ?? process.env.GITHUB_TOKEN;
  const errors = [];
  await Promise.all(Object.entries(policy.actions).map(async ([repo, record]) => {
    try {
      if (record.firstPartyException === true) {
        const commit = await fetchJson(`https://api.github.com/repos/${repo}/commits/${record.sha}`, fetchImpl, token);
        if (commit.sha !== record.sha) errors.push(`${repo}: upstream commit SHA mismatch`);
        if (commit.commit?.committer?.date !== record.published) errors.push(`${repo}: upstream commit date mismatch`);
        return;
      }
      const commit = await fetchJson(`https://api.github.com/repos/${repo}/commits/${record.tag}`, fetchImpl, token);
      const release = await fetchJson(`https://api.github.com/repos/${repo}/releases/tags/${record.tag}`, fetchImpl, token);
      if (commit.sha !== record.sha) errors.push(`${repo}: ${record.tag} does not resolve to the ledger SHA`);
      if (release.published_at !== record.published) errors.push(`${repo}: release date does not match the ledger`);
    } catch (error) {
      errors.push(`${repo}: ${error instanceof Error ? error.message : "remote verification failed"}`);
    }
  }));
  await Promise.all(Object.entries(policy.packages).map(async ([name, record]) => {
    try {
      const packument = await fetchJson(`https://registry.npmjs.org/${encodeURIComponent(name)}`, fetchImpl);
      if (packument.time?.[record.version] !== record.published) {
        errors.push(`${name}: npm publication date does not match the ledger`);
      }
    } catch (error) {
      errors.push(`${name}: ${error instanceof Error ? error.message : "remote verification failed"}`);
    }
  }));
  await verifyAdvisoryExceptionEvidence(
    policy.advisoryExceptions,
    fetchJson,
    fetchImpl,
    token,
    errors,
  );
  fail(errors);
}

export async function checkDependencyPolicy(options = {}) {
  const policy = await verifyLocalDependencyPolicy(options.root, options.now);
  if (options.verifyRemote === true) await verifyRemoteDependencyPolicy(policy, options);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  if (args.some((arg) => arg !== "--verify-remote")) throw new Error("usage: check-dependency-policy.mjs [--verify-remote]");
  await checkDependencyPolicy({ verifyRemote: args.includes("--verify-remote") });
  console.log("✓ dependency pins match the ledger and age policy");
}
