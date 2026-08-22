import { execFileSync } from "node:child_process";

const NON_RUNTIME_PACKAGE_FIELDS = new Set([
  "author", "bugs", "contributors", "description", "funding", "homepage", "keywords", "license", "repository",
]);

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
      "src", "examples", "test", "scripts/live", "scripts/run-release-matrix.mjs", "tsconfig.json", "tsconfig.build.json",
      ".github/workflows/publish.yml", "pnpm-lock.yaml", "pnpm-workspace.yaml",
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

export function changedEvidenceInputs(cwd, ancestor, descendant) {
  return [
    ...changedRuntimeInputs(cwd, ancestor, descendant),
    ...changedRuntimePackageFields(cwd, ancestor, descendant),
  ];
}
