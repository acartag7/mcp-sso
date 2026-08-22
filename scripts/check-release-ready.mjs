import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluateReleaseReadiness } from "./lib/release-ready.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));

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

const result = evaluateReleaseReadiness({
  packageJson: readJson(resolve(root, "package.json"), "package.json"),
  releaseMatrix: readJson(resolve(root, "test/release-matrix.json"), "test/release-matrix.json"),
  compatibility: readFileSync(resolve(root, "docs/client-compatibility.md"), "utf8"),
  status: readFileSync(resolve(root, "docs/verification-status.md"), "utf8"),
  gitCwd: root,
  releaseCommit: process.env.RELEASE_COMMIT ?? "HEAD",
});

if (result.errors.length > 0) {
  console.error("release readiness failed:");
  for (const error of result.errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`release ready: ${result.version} at ${result.releaseCommit}; ${result.exportCount} public exports have live evidence`);
