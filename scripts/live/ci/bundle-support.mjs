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

/** Every string leaf of a bundle long enough to be a private value (a
 *  credential, an identifier, a hostname), plus the bare hostname of any leaf
 *  that is a URL, so a log that prints `host=<name>` is masked as well as one
 *  that prints the origin. Short leaves such as ports and scope names are
 *  left alone; they are not private and would over-mask ordinary output. */
export function privateValues(value, out = new Set()) {
  if (typeof value === "string") {
    if (value.length >= MIN_PRIVATE_LENGTH && !/[\r\n]/.test(value)) {
      out.add(value);
      try {
        const host = new URL(value).hostname;
        if (host.length >= MIN_PRIVATE_LENGTH) out.add(host);
      } catch { /* not a URL */ }
    }
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) privateValues(item, out);
  } else if (isPlainObject(value)) {
    for (const item of Object.values(value)) privateValues(item, out);
  }
  return out;
}

/** True when any private value appears verbatim in the text. */
export function leaksPrivateValue(text, values) {
  for (const value of values) if (text.includes(value)) return true;
  return false;
}
