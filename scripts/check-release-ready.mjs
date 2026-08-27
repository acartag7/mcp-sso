import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluateReleaseReadiness } from "./lib/release-ready.mjs";
import { formatReleaseReadinessFailure, parseReleaseReadyArgs } from "./lib/release-ready-output.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
let verbose;
try {
  ({ verbose } = parseReleaseReadyArgs(process.argv.slice(2)));
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`release readiness failed:\n- ${message}`);
  process.exit(1);
}

function readJson(path, label) {
  try {
    const value = JSON.parse(readFileSync(path, "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected an object");
    return value;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`release readiness failed:\n- cannot read ${label}: ${message}`);
    process.exit(1);
  }
}

function readReceipts(directory) {
  let names;
  try {
    names = readdirSync(directory).filter((name) => name.endsWith(".json")).sort();
  } catch {
    console.error("release readiness failed:\n- cannot read docs/evidence/");
    process.exit(1);
  }
  return Object.fromEntries(names.map((name) => [name, readJson(resolve(directory, name), `docs/evidence/${name}`)]));
}

const result = evaluateReleaseReadiness({
  receipts: readReceipts(resolve(root, "docs/evidence")),
  packageJson: readJson(resolve(root, "package.json"), "package.json"),
  releaseMatrix: readJson(resolve(root, "test/release-matrix.json"), "test/release-matrix.json"),
  status: readFileSync(resolve(root, "docs/verification-status.md"), "utf8"),
  gitCwd: root,
  releaseCommit: process.env.RELEASE_COMMIT ?? "HEAD",
});

if (result.errors.length > 0 || result.staleEvidence.length > 0) {
  console.error(formatReleaseReadinessFailure({
    errors: result.errors,
    staleEvidence: result.staleEvidence,
    releaseTarget: process.env.RELEASE_COMMIT ?? "HEAD",
    verbose,
  }));
  process.exit(1);
}

console.log(`release ready: ${result.version} at ${result.releaseCommit}; ${result.exportCount} public exports have live evidence`);
