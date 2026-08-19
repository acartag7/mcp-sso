// Shared runner support for scripts/live/run.sh and serve.sh. Every decision
// the shell scripts must not make themselves lives here as an importable,
// executable function: parsing stack outputs, reading the private Google
// credential file through one descriptor, the per-leg provider preflight, and
// the guarded removal of prior live state. The CLI at the bottom is the only
// surface the shell scripts call. No value read here is ever printed; failures
// exit with a fixed reason.
import {
  chmodSync, closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertSingleIdentityProviderSelector, assertUpstreamConfigBeforeState, configFromEnv,
  entraGroupAuthorizationFromEnv, fastifySqliteDcrFromEnv,
} from "../../examples/fastify-sqlite/app.ts";
import { trustedProxiesFromEnv } from "../../examples/fastify-sqlite/trusted-proxy.ts";
import { assertSafeDeploymentCombination } from "../../src/deployment-guard.ts";
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
 *  without following symlinks and without blocking (so a FIFO at the path fails
 *  the regular-file check instead of hanging the open), checked (regular file,
 *  caller-owned, no group or other permission bits, bounded size) on that same
 *  descriptor, and parsed as KEY=VALUE data. It is never sourced. */
export function readGoogleCredentialFile(path, uid = process.getuid?.()) {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new RunSupportError("credential file reads require O_NOFOLLOW");
  }
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
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

/** The pre-state gates buildExample runs before ensureStateDir, in its order:
 *  selector cardinality, DCR mode, proxy trust, config parse, deployment
 *  combination. Running the same set here means every configuration the
 *  example would refuse at boot is refused BEFORE prior state is cleared. */
function assertExamplePreStateGates(env) {
  assertSingleIdentityProviderSelector(env);
  const productionDcr = fastifySqliteDcrFromEnv(env);
  trustedProxiesFromEnv(env);
  const config = configFromEnv(env, productionDcr.dcr);
  assertSafeDeploymentCombination({ config, rateLimit: productionDcr.rateLimit }, { emitAcknowledgementWarning: false });
  return config;
}

/** Base preflight for the end-to-end probe, which composes its own app and
 *  needs no provider leg: a bare https issuer and a config the example's own
 *  parser and deployment guard accept. */
export function assertBasePreflight(env) {
  const issuer = requireEnv(env, "OAUTH_ISSUER");
  if (!isBareHttpsOrigin(issuer)) throw new RunSupportError("OAUTH_ISSUER is not a bare https origin");
  requireEnv(env, "OAUTH_CONSENT_SIGNING_SECRET");
  requireEnv(env, "REDIS_URL");
  return assertExamplePreStateGates(env);
}

/** Provider preflight over the exact environment the runner assembled: exactly
 *  the selected leg's selector is present, every pre-state gate the example
 *  itself runs accepts it, and the leg's shipped identity constructor accepts
 *  its values (Google's constructor performs discovery, so its values are
 *  shape-checked here and the probe performs the discovery). Nothing here
 *  performs network I/O or touches state. */
export function assertLegPreflight(leg, env) {
  assertLeg(leg);
  const selector = { cloudflare_access: "CF_ACCESS_AUDIENCE", entra: "ENTRA_TENANT_ID", google: "GOOGLE_CLIENT_ID" }[leg];
  if (env[selector] === undefined) throw new RunSupportError("selected leg has no identity selector");
  const issuer = requireEnv(env, "OAUTH_ISSUER");
  if (!isBareHttpsOrigin(issuer)) throw new RunSupportError("OAUTH_ISSUER is not a bare https origin");
  const config = assertExamplePreStateGates(env);
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
 *  bits — created 0700 when absent — and only after that check is the prior
 *  state touched. The last generation that holds evidence is retained: a leaf
 *  with an `audit.jsonl` is rotated to `<leg>.previous` (replacing the
 *  generation before it), while a leaf without one — a start that failed after
 *  the preflight, a server that never took a request — is removed and leaves
 *  `<leg>.previous` untouched, so a routine retry never costs the last
 *  successful run's audit trail. Every path is inspected before anything is
 *  removed or renamed; a symlink anywhere in that set is an error, and nothing
 *  is ever deleted or moved through a link. */
export function prepareLiveStateDir(root, leg, uid = process.getuid?.()) {
  assertLeg(leg);
  let parent;
  try {
    parent = lstatSync(root);
  } catch (error) {
    if (error?.code !== "ENOENT") throw new RunSupportError("live state parent cannot be inspected");
  }
  if (parent === undefined) {
    try {
      mkdirSync(root, { mode: 0o700 });
      chmodSync(root, 0o700);
    } catch (error) {
      // Legs started together (serve.sh) race on the first-ever create; the
      // loser re-inspects what won and holds it to the same bar below.
      if (error?.code !== "EEXIST") throw new RunSupportError("live state parent cannot be created");
      try {
        parent = lstatSync(root);
      } catch {
        throw new RunSupportError("live state parent cannot be inspected");
      }
    }
  }
  if (parent !== undefined) {
    if (!parent.isDirectory()) throw new RunSupportError("live state parent is not a real directory");
    if (uid !== undefined && parent.uid !== uid) throw new RunSupportError("live state parent is not owned by the caller");
    if ((parent.mode & 0o077) !== 0) throw new RunSupportError("live state parent must have no group or other permission bits");
  }
  const leaf = join(root, leg);
  const previous = join(root, `${leg}.previous`);
  const inspect = (path) => {
    try {
      return lstatSync(path);
    } catch (error) {
      if (error?.code === "ENOENT") return undefined;
      throw new RunSupportError("prior live state cannot be inspected");
    }
  };
  // Inspect every path before touching any: a rejected leaf must not have cost
  // the retained generation first.
  const priorPrevious = inspect(previous);
  const prior = inspect(leaf);
  if (priorPrevious !== undefined && !priorPrevious.isDirectory()) throw new RunSupportError("prior live state is not a real directory");
  if (prior !== undefined && !prior.isDirectory()) throw new RunSupportError("prior live state is not a real directory");
  const evidence = prior === undefined ? undefined : inspect(join(leaf, "audit.jsonl"));
  if (evidence !== undefined && !evidence.isFile()) throw new RunSupportError("prior live state evidence is not a regular file");
  const remove = (path) => {
    try {
      rmSync(path, { recursive: true });
    } catch {
      throw new RunSupportError("prior live state cannot be removed");
    }
  };
  if (prior === undefined) return leaf;
  if (evidence === undefined || evidence.size === 0) {
    // A start that produced no evidence is discarded; the retained generation
    // stays exactly as it was.
    remove(leaf);
    return leaf;
  }
  if (priorPrevious !== undefined) remove(previous);
  try {
    renameSync(leaf, previous);
  } catch {
    throw new RunSupportError("prior live state cannot be rotated aside");
  }
  return leaf;
}

const readStdin = () => readFileSync(0, "utf8");

/** Normalize a deny-channel value with EXACTLY the example's listEnv semantics
 *  (split on ",", String.prototype.trim — Unicode whitespace included — filter
 *  Boolean). Rejects the empty-normalizing channel (it would run the positive
 *  leg) and, when the real value is supplied as argv[0], a list containing it
 *  (a member login would pass while the run records the deny leg). Returns the
 *  normalized list for the runner to pass on — one parser, no shell re-parse. */
function denyListNormalized(raw, real) {
  const entries = raw.split(",").map((entry) => entry.trim()).filter(Boolean);
  if (entries.length === 0) {
    throw new RunSupportError("deny channel normalizes to an empty list; listEnv would treat it as unset and the positive leg would run");
  }
  if (real !== undefined && entries.includes(real.trim())) {
    throw new RunSupportError("deny channel contains the real value; the deny leg must exclude it or every member login passes");
  }
  return entries.join(",");
}

const COMMANDS = {
  "issuer-origin": ([leg]) => issuerOriginForLeg(readStdin(), leg),
  "gateway-port": ([leg]) => String(gatewayPortForLeg(readStdin(), leg)),
  "group-authorization": () => groupAuthorizationJsonFromMapping(readStdin()),
  "deny-list": ([real]) => denyListNormalized(readStdin(), real),
  "google-credential-file": ([path]) => {
    const values = readGoogleCredentialFile(path);
    return `${values.GOOGLE_CLIENT_ID}\n${values.GOOGLE_CLIENT_SECRET}`;
  },
  preflight: ([leg]) => { assertLegPreflight(leg, process.env); return ""; },
  "preflight-base": () => { assertBasePreflight(process.env); return ""; },
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
      const reason = error instanceof RunSupportError ? error.message : `${command} failed`;
      process.stderr.write(`run-support: ${reason}\n`);
      process.exitCode = 1;
    }
  }
}
