// Shared runner support for scripts/live/run.sh and serve.sh. Every decision
// the shell scripts must not make themselves lives here as an importable,
// executable function: parsing stack outputs, reading the private Google
// credential file through one descriptor, the per-leg provider preflight, and
// the guarded removal of prior live state. The CLI at the bottom is the only
// surface the shell scripts call. No value read here is ever printed; failures
// exit with a fixed reason.
import {
  chmodSync, closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, rmSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertSingleIdentityProviderSelector, assertUpstreamConfigBeforeState, configFromEnv,
  entraGroupAuthorizationFromEnv, fastifySqliteDcrFromEnv,
} from "../../examples/fastify-sqlite/app.ts";
import { createCloudflareAccessIdentity } from "../../src/identity/cloudflare-access.ts";
import { createEntraRedirectIdentity } from "../../src/identity/entra-redirect.ts";

export const LEGS = Object.freeze(["cloudflare_access", "entra", "google"]);
export const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
class RunSupportError extends Error {}
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
const MAX_VALUE_LENGTH = 4_096;
const MAX_CREDENTIAL_FILE_BYTES = 16 * 1024;
const CREDENTIAL_KEYS = new Set(["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "OIDC_CLIENT_SECRET"]);

const isPlainObject = (value) => value !== null && typeof value === "object"
  && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const parseObject = (raw, what) => {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new RunSupportError(`${what} output is not JSON`);
  }
  if (!isPlainObject(parsed)) throw new RunSupportError(`${what} output is not an object`);
  return parsed;
};
export const assertLeg = (leg) => {
  if (!LEGS.includes(leg)) throw new RunSupportError("unknown leg");
  return leg;
};
const isBareHttpsOrigin = (value) => {
  if (typeof value !== "string" || value.length === 0) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.username === "" && url.password === ""
      && url.origin === value;
  } catch {
    return false;
  }
};

/** The selected leg's public issuer origin from the `issuer_origins` output. */
export function issuerOriginForLeg(rawJson, leg) {
  const value = parseObject(rawJson, "issuer_origins")[assertLeg(leg)];
  if (!isBareHttpsOrigin(value)) throw new RunSupportError("issuer origin is missing or not a bare https origin");
  return value;
}

/** The selected leg's local gateway port from the `tunnel_ingress_ports` output. */
export function gatewayPortForLeg(rawJson, leg) {
  const entry = parseObject(rawJson, "tunnel_ingress_ports")[assertLeg(leg)];
  const port = isPlainObject(entry) ? entry.gateway : undefined;
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new RunSupportError("gateway port is missing or invalid");
  return port;
}

/** Wrap the `group_authorization_mapping` output as ENTRA_GROUP_AUTHORIZATION_JSON.
 *  No baseScopes: a user in zero mapped groups must be denied, not floored. */
export function groupAuthorizationJsonFromMapping(rawJson) {
  const mapping = parseObject(rawJson, "group_authorization_mapping");
  const entries = Object.entries(mapping);
  if (entries.length === 0) throw new RunSupportError("group mapping is empty");
  for (const [group, scopes] of entries) {
    if (!GUID.test(group) || !Array.isArray(scopes) || scopes.length === 0
      || !scopes.every((scope) => typeof scope === "string" && scope.length > 0)) {
      throw new RunSupportError("group mapping entry is invalid");
    }
  }
  return JSON.stringify({ mapping });
}

/** Read the private Google credential file through ONE descriptor: opened
 *  without following symlinks, checked (regular file, caller-owned, no group or
 *  other permission bits, bounded size) on that same descriptor, and parsed as
 *  KEY=VALUE data. It is never sourced. */
export function readGoogleCredentialFile(path, uid = process.getuid?.()) {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new RunSupportError("credential file reads require O_NOFOLLOW");
  }
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    throw new RunSupportError("credential file cannot be opened without following a symlink");
  }
  let text;
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new RunSupportError("credential file is not a regular file");
    if (uid !== undefined && st.uid !== uid) throw new RunSupportError("credential file is not owned by the caller");
    if ((st.mode & 0o077) !== 0) throw new RunSupportError("credential file must have no group or other permission bits");
    if (st.size > MAX_CREDENTIAL_FILE_BYTES) throw new RunSupportError("credential file is too large");
    text = readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
  const values = new Map();
  for (const rawLine of text.split("\n")) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (line.trim() === "" || line.startsWith("#")) continue;
    const at = line.indexOf("=");
    if (at <= 0) throw new RunSupportError("credential file line is not KEY=VALUE");
    const key = line.slice(0, at);
    const value = line.slice(at + 1);
    if (!CREDENTIAL_KEYS.has(key)) throw new RunSupportError("credential file contains an unsupported key");
    if (values.has(key)) throw new RunSupportError("credential file repeats a key");
    if (value.length === 0 || value.length > MAX_VALUE_LENGTH || CONTROL_CHARS.test(value)) {
      throw new RunSupportError("credential file value is empty, oversized, or contains control characters");
    }
    if (/["'\s]/.test(value)) {
      throw new RunSupportError("credential file value must be bare: no quotes or whitespace");
    }
    values.set(key, value);
  }
  const clientId = values.get("GOOGLE_CLIENT_ID");
  const secrets = [values.get("GOOGLE_CLIENT_SECRET"), values.get("OIDC_CLIENT_SECRET")].filter(Boolean);
  if (clientId === undefined || secrets.length !== 1) {
    throw new RunSupportError("credential file must provide GOOGLE_CLIENT_ID and exactly one client secret");
  }
  return { GOOGLE_CLIENT_ID: clientId, GOOGLE_CLIENT_SECRET: secrets[0] };
}

const requireEnv = (env, name) => {
  const value = env[name];
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_VALUE_LENGTH
    || CONTROL_CHARS.test(value)) throw new RunSupportError(`${name} is missing or malformed`);
  return value;
};

/** Provider preflight over the exact environment the runner assembled: exactly
 *  the selected leg's selector is present, the example's own config parser
 *  accepts it, and the leg's shipped identity constructor accepts its values.
 *  Nothing here performs network I/O or touches state. */
export function assertLegPreflight(leg, env) {
  assertLeg(leg);
  assertSingleIdentityProviderSelector(env);
  const selector = { cloudflare_access: "CF_ACCESS_AUDIENCE", entra: "ENTRA_TENANT_ID", google: "GOOGLE_CLIENT_ID" }[leg];
  if (env[selector] === undefined) throw new RunSupportError("selected leg has no identity selector");
  const issuer = requireEnv(env, "OAUTH_ISSUER");
  if (!isBareHttpsOrigin(issuer)) throw new RunSupportError("OAUTH_ISSUER is not a bare https origin");
  const config = configFromEnv(env, fastifySqliteDcrFromEnv(env).dcr);
  if (leg === "entra") {
    const tenantId = requireEnv(env, "ENTRA_TENANT_ID");
    const clientId = requireEnv(env, "ENTRA_CLIENT_ID");
    const unmapped = requireEnv(env, "ENTRA_UNMAPPED_GROUP");
    if (!GUID.test(tenantId) || !GUID.test(clientId) || !GUID.test(unmapped)) {
      throw new RunSupportError("Entra identifiers are not GUIDs");
    }
    const redirectUri = requireEnv(env, "ENTRA_REDIRECT_URI");
    if (redirectUri !== `${issuer}/oauth/callback`) throw new RunSupportError("ENTRA_REDIRECT_URI is not the issuer callback");
    const groupAuthorization = entraGroupAuthorizationFromEnv(env);
    if (groupAuthorization === undefined) throw new RunSupportError("ENTRA_GROUP_AUTHORIZATION_JSON is required");
    const mapped = Object.keys(groupAuthorization.mapping ?? {}).map((group) => group.toLowerCase());
    if (mapped.includes(unmapped.toLowerCase())) throw new RunSupportError("ENTRA_UNMAPPED_GROUP is present in the mapping");
    createEntraRedirectIdentity({
      tenantId, clientId, clientSecret: requireEnv(env, "ENTRA_CLIENT_SECRET"), redirectUri, groupAuthorization,
    }, { scopeCatalog: config.scopeCatalog });
    assertUpstreamConfigBeforeState(config, redirectUri, new URL(redirectUri).pathname);
    return;
  }
  if (leg === "cloudflare_access") {
    createCloudflareAccessIdentity({
      audience: requireEnv(env, "CF_ACCESS_AUDIENCE"),
      certsUrl: requireEnv(env, "CF_ACCESS_CERTS_URL"),
      issuer: requireEnv(env, "CF_ACCESS_ISSUER"),
    });
    return;
  }
  requireEnv(env, "GOOGLE_CLIENT_ID");
  requireEnv(env, "GOOGLE_CLIENT_SECRET");
  const redirectUri = requireEnv(env, "GOOGLE_REDIRECT_URI");
  if (redirectUri !== `${issuer}/oauth/callback`) throw new RunSupportError("GOOGLE_REDIRECT_URI is not the issuer callback");
  assertUpstreamConfigBeforeState(config, redirectUri, new URL(redirectUri).pathname);
}

/** Prepare `<root>/<leg>` for a fresh example server: the parent must be a real
 *  directory (never a symlink) that the caller owns with no group or other
 *  bits — created 0700 when absent — and a prior leaf is removed only after that
 *  check. A leaf that is itself a symlink or cannot be removed is an error;
 *  nothing is ever deleted through a link. */
export function prepareLiveStateDir(root, leg, uid = process.getuid?.()) {
  assertLeg(leg);
  let parent;
  try {
    parent = lstatSync(root);
  } catch (error) {
    if (error?.code !== "ENOENT") throw new RunSupportError("live state parent cannot be inspected");
  }
  if (parent === undefined) {
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o700);
  } else {
    if (!parent.isDirectory()) throw new RunSupportError("live state parent is not a real directory");
    if (uid !== undefined && parent.uid !== uid) throw new RunSupportError("live state parent is not owned by the caller");
    if ((parent.mode & 0o077) !== 0) throw new RunSupportError("live state parent must have no group or other permission bits");
  }
  const leaf = join(root, leg);
  let prior;
  try {
    prior = lstatSync(leaf);
  } catch (error) {
    if (error?.code !== "ENOENT") throw new RunSupportError("prior live state cannot be inspected");
  }
  if (prior !== undefined) {
    if (!prior.isDirectory()) throw new RunSupportError("prior live state is not a real directory");
    try {
      rmSync(leaf, { recursive: true });
    } catch {
      throw new RunSupportError("prior live state cannot be removed");
    }
  }
  return leaf;
}

const readStdin = () => readFileSync(0, "utf8");
const COMMANDS = {
  "issuer-origin": ([leg]) => issuerOriginForLeg(readStdin(), leg),
  "gateway-port": ([leg]) => String(gatewayPortForLeg(readStdin(), leg)),
  "group-authorization": () => groupAuthorizationJsonFromMapping(readStdin()),
  "google-credential-file": ([path]) => {
    const values = readGoogleCredentialFile(path);
    return `${values.GOOGLE_CLIENT_ID}\n${values.GOOGLE_CLIENT_SECRET}`;
  },
  preflight: ([leg]) => { assertLegPreflight(leg, process.env); return ""; },
  "state-dir": ([root, leg]) => prepareLiveStateDir(root, leg),
};

const invokedAsMain = () => {
  try {
    return realpathSync(process.argv[1] ?? "") === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
};

if (invokedAsMain()) {
  const [command, ...args] = process.argv.slice(2);
  const run = COMMANDS[command];
  if (run === undefined) {
    process.stderr.write("run-support: unknown command\n");
    process.exitCode = 2;
  } else {
    try {
      process.stdout.write(run(args));
    } catch (error) {
      // Only this module's fixed reasons reach output; a shipped constructor's
      // message may quote the value it rejected, so it is reduced to its class.
      const reason = error instanceof RunSupportError ? error.message : "provider preflight failed";
      process.stderr.write(`run-support: ${reason}\n`);
      process.exitCode = 1;
    }
  }
}
