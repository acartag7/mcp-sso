// Support for the CI output adapter. In CI, MCP_SSO_INFRA_DIR points at
// scripts/live/ci/infra, whose scripts/tofu-run.sh answers run.sh's
// `<stack> output -raw|-json <name>` calls from a JSON bundle on disk (one per
// source stack, fetched from Secrets Manager by fetch-bundle.mjs) instead of
// from OpenTofu state. The bundle is read through one descriptor with the same
// checks the Google credential file gets, and every value is data.
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";

export class BundleError extends Error {}
export const STACK_HANDLE = /^[a-z][a-z-]{0,31}$/;
export const OUTPUT_NAME = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_BUNDLE_BYTES = 64 * 1024;
const MAX_SCALAR_LENGTH = 4_096;
const MIN_PRIVATE_LENGTH = 12;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

const isPlainObject = (value) => value !== null && typeof value === "object"
  && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;

/** Read one private JSON file through ONE descriptor: opened without following
 *  symlinks and without blocking, checked (regular file, caller-owned, no group
 *  or other permission bits, bounded size) on that same descriptor, and parsed
 *  as a JSON object. Anything else is a fixed-reason failure. */
export function readPrivateJson(path, uid = process.getuid?.()) {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new BundleError("bundle reads require O_NOFOLLOW");
  }
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch {
    throw new BundleError("bundle file cannot be opened without following a symlink");
  }
  let text;
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new BundleError("bundle file is not a regular file");
    if (uid !== undefined && st.uid !== uid) throw new BundleError("bundle file is not owned by the caller");
    if ((st.mode & 0o077) !== 0) throw new BundleError("bundle file must have no group or other permission bits");
    if (st.size > MAX_BUNDLE_BYTES) throw new BundleError("bundle file is too large");
    text = readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
  return parseJsonObject(text);
}

/** A stack bundle: a private JSON file whose keys are stack output names. */
export function readBundleFile(path, uid = process.getuid?.()) {
  return assertOutputNames(readPrivateJson(path, uid));
}

/** Parse text as a JSON object; nothing else is a bundle. */
export function parseJsonObject(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new BundleError("bundle is not JSON");
  }
  if (!isPlainObject(parsed)) throw new BundleError("bundle is not a JSON object");
  return parsed;
}

function assertOutputNames(bundle) {
  for (const key of Object.keys(bundle)) {
    if (!OUTPUT_NAME.test(key)) throw new BundleError("bundle contains an invalid output name");
  }
  return bundle;
}

/** Parse stack bundle text: a JSON object whose keys are output names. */
export function parseBundle(text) {
  return assertOutputNames(parseJsonObject(text));
}

/** What `tofu output -raw <name>` or `tofu output -json <name>` would print
 *  for this bundle. `-raw` accepts only a scalar, exactly as tofu does. */
export function bundleOutput(bundle, name, format) {
  if (typeof name !== "string" || !OUTPUT_NAME.test(name)) throw new BundleError("output name is invalid");
  if (!Object.hasOwn(bundle, name)) throw new BundleError("required stack output unavailable");
  const value = bundle[name];
  if (format === "-json") return JSON.stringify(value);
  if (format !== "-raw") throw new BundleError("unsupported output format");
  if (typeof value === "string") {
    if (value.length === 0 || value.length > MAX_SCALAR_LENGTH || CONTROL_CHARS.test(value)) {
      throw new BundleError("scalar output is empty, oversized, or contains control characters");
    }
    return value;
  }
  if ((typeof value === "number" && Number.isFinite(value)) || typeof value === "boolean") return String(value);
  throw new BundleError("output is not a scalar; -raw needs a string, number, or boolean");
}

/** Keys whose values are private at any length: credentials, identities, and
 *  the names an operator would recognise. Every other string leaf counts only
 *  from MIN_PRIVATE_LENGTH characters, so ports and scope names are not
 *  masked and ordinary output stays readable. */
export const ALWAYS_PRIVATE_KEYS = Object.freeze(new Set([
  "entra_client_secret", "test_user_password", "cf_access_idp_name", "cf_access_audience", "entra_tenant_id", "entra_client_id",
  "unmapped_group_object_id_do_not_map", "TunnelSecret", "TunnelID", "AccountTag", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
  "apiKey", "projectId", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "test_users",
]));

/** A value nested under a credential key is a credential too: `test_users` is
 *  a map of role to sign-in name, and a short name (`a@b.co`) would otherwise
 *  fall through both the key check, which sees the role, and the length floor. */
const effectiveKey = (parentKey, childKey) => (ALWAYS_PRIVATE_KEYS.has(parentKey) ? parentKey : childKey);

/** Every private string of a bundle: the values under ALWAYS_PRIVATE_KEYS at
 *  any length, every other string leaf of MIN_PRIVATE_LENGTH characters or
 *  more, each line of a multi-line value, and the bare hostname of any value
 *  that is a URL, so a log that prints `host=<name>` is masked as well as one
 *  that prints the origin. */
export function privateValues(value, out = new Set(), key = undefined) {
  if (typeof value === "string") {
    for (const line of value.split(/\r?\n/)) {
      if (line.length === 0) continue;
      if (line.length >= MIN_PRIVATE_LENGTH || ALWAYS_PRIVATE_KEYS.has(key)) out.add(line);
      try {
        const host = new URL(line).hostname;
        if (host.length > 0 && (host.length >= MIN_PRIVATE_LENGTH || ALWAYS_PRIVATE_KEYS.has(key))) out.add(host);
      } catch { /* not a URL */ }
    }
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) privateValues(item, out, key);
  } else if (isPlainObject(value)) {
    for (const [childKey, item] of Object.entries(value)) privateValues(item, out, effectiveKey(key, childKey));
  }
  return out;
}

/** The credential subset: the values under ALWAYS_PRIVATE_KEYS only. Used
 *  where the text being scanned is expected to name the deployment it serves
 *  (serve.sh prints the public origins it brings up, which are private values
 *  but not credentials) and the question is only whether a credential escaped
 *  into it. */
export function credentialValues(value, out = new Set(), key = undefined) {
  if (typeof value === "string") {
    if (ALWAYS_PRIVATE_KEYS.has(key)) for (const line of value.split(/\r?\n/)) if (line.length > 0) out.add(line);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) credentialValues(item, out, key);
  } else if (isPlainObject(value)) {
    for (const [childKey, item] of Object.entries(value)) credentialValues(item, out, effectiveKey(key, childKey));
  }
  return out;
}

/** True when any private value appears verbatim in the text. */
export function leaksPrivateValue(text, values) {
  for (const value of values) if (text.includes(value)) return true;
  return false;
}

/** One `::add-mask::` workflow command, encoded the way the Actions runner
 *  decodes it (`%`, CR, and LF), so the registered mask is the value itself. */
export function maskCommand(value) {
  return `::add-mask::${value.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A")}`;
}
