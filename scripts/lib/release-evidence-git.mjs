import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const NON_RUNTIME_PACKAGE_FIELDS = new Set([
  "author", "bugs", "contributors", "description", "funding", "homepage", "keywords", "license", "repository",
]);
/** What a recorded observation is ABOUT: the library, the example a leg
 *  serves, and how either is built or published. A change here can change what
 *  any client would observe, so it ages every recorded row. */
const RUNTIME_PATHS = [
  "src", "examples", "tsconfig.json", "tsconfig.build.json",
  ".github/workflows/publish.yml", "pnpm-lock.yaml", "pnpm-workspace.yaml",
];

/** What composes and exposes the leg a client is driven against: the runner
 *  that maps stack values onto the example's identity selector, DCR mode,
 *  redirect allowlist and proxy trust, and the script that starts the servers
 *  and the tunnel. A change here changes what ANY client observes without
 *  touching `src/`, so it ages every row, an operator's included. */
const DEPLOYMENT_PATHS = [
  "scripts/live/run.sh", "scripts/live/serve.sh", "scripts/live/run-support.mjs",
];

/** What PRODUCES harness-driven evidence: the probes, the drivers, the
 *  rehearsal, the renderer and the row definitions it writes from, the release
 *  matrix and its definition. A change here can change what such a row proves,
 *  so it ages those rows — and only those. A row an operator drove through a
 *  real client came from none of this, and the two have different lifecycles:
 *  the record run re-proves the harness rows on every dispatch, while an
 *  operator row keeps standing until the thing it observed changes. */
const HARNESS_PATHS = [
  "test", "scripts/live", "scripts/run-release-matrix.mjs", "scripts/check-release-matrix.mjs",
  "scripts/lib/release-matrix-outcome.mjs", "docs/verification.md",
];

/** The set `evidenceInputDigest` hashes, frozen as it was when the first digest
 *  was recorded. A digest already in the matrix was taken over exactly these
 *  paths; widening or narrowing the set now would stop it matching, which is a
 *  failure with no fix but re-running the campaign that produced it. */
const DIGEST_PATHS = [
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

function changedRuntimeInputs(cwd, ancestor, descendant, paths) {
  const output = execFileSync(
    "git",
    [
      "diff", "--name-only", "-z", ancestor, descendant, "--",
      ...paths,
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
    "git", ["ls-tree", "-r", "-z", commit, "--", ...DIGEST_PATHS],
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

/** The inputs that changed between the commit a row named and the release
 *  commit. `harnessDriven` says whether the row came out of the harness; a row
 *  that did not is aged by runtime changes alone. */
export function changedEvidenceInputs(cwd, ancestor, descendant, { harnessDriven = true } = {}) {
  const paths = harnessDriven
    ? [...RUNTIME_PATHS, ...DEPLOYMENT_PATHS, ...HARNESS_PATHS]
    : [...RUNTIME_PATHS, ...DEPLOYMENT_PATHS];
  return [
    ...changedRuntimeInputs(cwd, ancestor, descendant, paths),
    ...changedRuntimePackageFields(cwd, ancestor, descendant),
  ];
}
