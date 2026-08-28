import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const NON_RUNTIME_PACKAGE_FIELDS = new Set([
  "author", "bugs", "contributors", "description", "funding", "homepage", "keywords", "license", "repository",
  // The version reaches a user through `src/bin/init.ts`, which pins it in the
  // package.json `mcp-sso init` generates, and through the name of the packed
  // tarball. Nothing a client observes over the OAuth and MCP endpoints changes
  // when it changes, while the bump is a step of every release. Ageing evidence
  // on it would mean re-running a campaign to prove a number changed, and it is
  // what forced the bump and its evidence into two pull requests.
  "version",
]);
/** What ages a receipt: the library, the example a leg serves, how either is
 *  built or published, the composition of the leg a client is driven against,
 *  and the code that produced the evidence. `run.sh`, `serve.sh`, and
 *  `run-support.mjs` choose the entry point, map configuration onto the
 *  example's identity selector, DCR mode, redirect allowlist, and proxy trust,
 *  and expose the hostname. The probes and the rehearsal are here because a
 *  receipt produced by a probe that has since been corrected should not stand
 *  as current, and re-running is a local command. */
const EVIDENCE_PATHS = [
  "src", "examples", "test", "scripts/live", "scripts/run-release-matrix.mjs", "scripts/check-release-matrix.mjs",
  "scripts/lib/release-matrix-outcome.mjs", "docs/verification.md", "tsconfig.json", "tsconfig.build.json",
  ".github/workflows/publish.yml", "pnpm-lock.yaml", "pnpm-workspace.yaml",
];

function gitOutput(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

export function resolveCommit(cwd, value) {
  try {
    return gitOutput(cwd, ["rev-parse", "--verify", `${value}^{commit}`]);
  } catch {
    return undefined;
  }
}

export function isAncestor(cwd, ancestor, descendant) {
  try {
    execFileSync("git", ["merge-base", "--is-ancestor", ancestor, descendant], { cwd, stdio: "ignore" });
    return true;
  } catch (error) {
    if (error && typeof error === "object" && "status" in error && error.status === 1) return false;
    throw error;
  }
}

function changedRuntimeInputs(cwd, ancestor, descendant) {
  const output = execFileSync(
    "git",
    [
      "diff", "--name-only", "-z", ancestor, descendant, "--",
      ...EVIDENCE_PATHS,
    ],
    { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  return output.split("\0").filter(Boolean);
}

function packageAtCommit(cwd, commit) {
  try {
    return JSON.parse(gitOutput(cwd, ["show", `${commit}:package.json`]));
  } catch {
    return undefined;
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalJson(value[key])]));
}

function changedRuntimePackageFields(cwd, ancestor, descendant) {
  const before = packageAtCommit(cwd, ancestor);
  const after = packageAtCommit(cwd, descendant);
  if (!before || !after || typeof before !== "object" || typeof after !== "object") return ["package.json (unreadable)"];
  const fields = new Set([...Object.keys(before), ...Object.keys(after)]);
  return [...fields]
    .filter((field) => !NON_RUNTIME_PACKAGE_FIELDS.has(field))
    .filter((field) => {
      const beforeValue = field === "scripts" ? withoutReleaseReadyScript(before[field]) : before[field];
      const afterValue = field === "scripts" ? withoutReleaseReadyScript(after[field]) : after[field];
      return JSON.stringify(canonicalJson(beforeValue)) !== JSON.stringify(canonicalJson(afterValue));
    })
    .sort()
    .map((field) => `package.json:${field}`);
}

function withoutReleaseReadyScript(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  return Object.fromEntries(Object.entries(value).filter(([name]) => name !== "check:release-ready"));
}

function runtimePackageProjection(value) {
  return Object.fromEntries(Object.entries(value)
    .filter(([field]) => !NON_RUNTIME_PACKAGE_FIELDS.has(field))
    .map(([field, fieldValue]) => [field, field === "scripts" ? withoutReleaseReadyScript(fieldValue) : fieldValue]));
}

export function evidenceInputDigest(cwd, commit) {
  const entries = execFileSync(
    "git", ["ls-tree", "-r", "-z", commit, "--", ...EVIDENCE_PATHS],
    { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ).split("\0").filter(Boolean).map((entry) => {
    const match = entry.match(/^([0-9]{6}) ([a-z]+) [0-9a-f]+\t([\s\S]+)$/);
    if (!match) throw new Error(`unreadable evidence tree entry: ${entry}`);
    return { mode: match[1], type: match[2], file: match[3] };
  });
  const packageJson = packageAtCommit(cwd, commit);
  if (!packageJson || typeof packageJson !== "object") return undefined;
  const hash = createHash("sha256").update("mcp-sso-release-evidence-v1\0");
  for (const { mode, type, file } of entries) {
    const blob = execFileSync("git", ["show", `${commit}:${file}`], { cwd, stdio: ["ignore", "pipe", "pipe"] });
    hash.update(`${mode}:${type}:${file.length}:${file}:${blob.length}:`).update(blob);
  }
  hash.update(JSON.stringify(canonicalJson(runtimePackageProjection(packageJson))));
  return hash.digest("hex");
}

/** The inputs that changed between the receipt's commit and the release commit. */
export function changedEvidenceInputs(cwd, ancestor, descendant) {
  return [
    ...changedRuntimeInputs(cwd, ancestor, descendant),
    ...changedRuntimePackageFields(cwd, ancestor, descendant),
  ];
}
