// Fetch the /mcp-sso/live/* secrets into $MCP_SSO_BUNDLE_DIR with an AWS CLI
// that configure-aws-credentials has already authenticated. The two stack
// bundles are required; the rest are optional and their absence is recorded,
// never papered over: a row that needs one reports BLOCKED with that reason.
// Only what a row consumes is fetched: the hosted-browser key stays in its
// container until a row reads it. Every file is created exclusively with mode
// 0600 and validated before it is kept. No value is printed.
import { execFile } from "node:child_process";
import { appendFileSync, closeSync, constants, mkdirSync, openSync, rmSync, writeSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import { promisify } from "node:util";
import { BundleError, parseBundle, parseJsonObject } from "./bundle-support.mjs";
import { readGoogleCredentialFile } from "../run-support.mjs";

const execFileAsync = promisify(execFile);
const PREFIX = "/mcp-sso/live";

/** Each secret, how it is validated, and the file name it lands under. */
export const SECRETS = Object.freeze([
  { name: "entra", file: "entra.json", required: true, validate: parseBundle },
  { name: "cloudflare", file: "cloudflare.json", required: true, validate: parseBundle },
  { name: "google", file: "google.env", required: false, validate: undefined },
  { name: "tunnel-credentials", file: "tunnel-credentials.json", required: false, validate: validateTunnel },
]);

function validateTunnel(text) {
  const value = parseJsonObject(text);
  for (const key of ["AccountTag", "TunnelSecret", "TunnelID"]) {
    if (typeof value[key] !== "string" || value[key].length === 0) throw new BundleError("tunnel credentials are incomplete");
  }
  return value;
}

/** Read one secret's current value; `undefined` when it has no value yet. */
async function fetchSecret(name, awsBin) {
  try {
    const { stdout } = await execFileAsync(awsBin, [
      "secretsmanager", "get-secret-value", "--secret-id", `${PREFIX}/${name}`, "--query", "SecretString", "--output", "text",
    ], { maxBuffer: 1024 * 1024 });
    return stdout.endsWith("\n") ? stdout.slice(0, -1) : stdout;
  } catch (error) {
    const stderr = typeof error?.stderr === "string" ? error.stderr : "";
    if (/ResourceNotFoundException/.test(stderr)) return undefined;
    throw new BundleError(`secret ${name} could not be read`);
  }
}

/** Create the file exclusively at 0600 and write the text; refuse to reuse a
 *  file that already exists so a stale bundle from an earlier step never
 *  stands in for this fetch. */
function writePrivate(path, text) {
  let fd;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  } catch {
    throw new BundleError("bundle file already exists or cannot be created");
  }
  try {
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

export async function fetchBundles({ dir, awsBin = "aws", githubEnv }) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const manifest = {};
  for (const secret of SECRETS) {
    const text = await fetchSecret(secret.name, awsBin);
    if (text === undefined || text.length === 0) {
      if (secret.required) throw new BundleError(`required secret ${secret.name} has no value`);
      manifest[secret.name] = "absent";
      continue;
    }
    if (secret.validate !== undefined) secret.validate(text);
    const path = join(dir, secret.file);
    writePrivate(path, text.endsWith("\n") ? text : `${text}\n`);
    if (secret.name === "google") {
      try {
        readGoogleCredentialFile(path);
      } catch {
        rmSync(path, { force: true });
        throw new BundleError("google secret is not a valid credential file");
      }
      if (githubEnv) appendFileSync(githubEnv, `MCP_SSO_GOOGLE_ENV=${path}\n`);
    }
    manifest[secret.name] = "present";
  }
  return manifest;
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
    process.stderr.write("fetch-bundle: MCP_SSO_BUNDLE_DIR is not set\n");
    process.exitCode = 1;
  } else {
    try {
      const manifest = await fetchBundles({ dir, githubEnv: process.env.GITHUB_ENV });
      for (const [name, state] of Object.entries(manifest)) process.stdout.write(`${name}: ${state}\n`);
    } catch (error) {
      const reason = error instanceof BundleError ? error.message : "fetch failed";
      process.stderr.write(`fetch-bundle: ${reason}\n`);
      process.exitCode = 1;
    }
  }
}
