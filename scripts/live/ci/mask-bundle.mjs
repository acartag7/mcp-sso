// Register every private value in the fetched bundles with the GitHub Actions
// log masker before anything else runs. The job log of a public repository is
// public; a hostname, a test user, or a credential that a child process prints
// must render as *** there. `::add-mask::` lines are consumed by the runner and
// are not themselves logged.
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import { privateValues, readPrivateJson } from "./bundle-support.mjs";
import { readGoogleCredentialFile } from "../run-support.mjs";

export function maskLines(dir) {
  const values = new Set();
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (name.endsWith(".json")) privateValues(readPrivateJson(path), values);
    else if (name === "google.env") privateValues(readGoogleCredentialFile(path), values);
  }
  return [...values].map((value) => `::add-mask::${value}`);
}

const invokedAsMain = () => {
  try {
    return realpathSync(process.argv[1] ?? "") === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
};

if (invokedAsMain()) {
  const dir = process.env.MCP_SSO_BUNDLE_DIR;
  if (typeof dir !== "string" || dir.length === 0) {
    process.stderr.write("mask-bundle: MCP_SSO_BUNDLE_DIR is not set\n");
    process.exitCode = 1;
  } else {
    try {
      const lines = maskLines(dir);
      process.stdout.write(lines.length > 0 ? `${lines.join("\n")}\n` : "");
      process.stderr.write(`mask-bundle: ${lines.length} values masked\n`);
    } catch {
      process.stderr.write("mask-bundle: bundle could not be read\n");
      process.exitCode = 1;
    }
  }
}
