// One redirect-entry grammar shared by every §10.0 boundary. This module parses
// the raw bytes once, rejects any spelling WHATWG would rewrite, and returns the
// parsed URL only after the raw form has been accepted.

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const MAX_ENTRY_BYTES = 2048;

export type RedirectEntryForm = "origin" | "exact-uri";

export interface RedirectEntry {
  readonly raw: string;
  readonly url: URL;
  readonly form: RedirectEntryForm;
  readonly hasExplicitPort: boolean;
}

export interface RedirectEntryOptions {
  /** Only §10.1 allowlist entries may omit WHATWG's appended root slash. */
  readonly allowOmittedRootSlash?: boolean;
}

export class RedirectEntryError extends Error {
  readonly reason: string;
  readonly entry: unknown;
  readonly canonical?: string;

  constructor(entry: unknown, reason: string, canonical?: string) {
    super(messageFor(entry, reason, canonical));
    this.name = "RedirectEntryError";
    this.entry = entry;
    this.reason = reason;
    this.canonical = canonical;
  }
}

export function parseRedirectEntry(value: unknown, options: RedirectEntryOptions = {}): RedirectEntry {
  if (typeof value !== "string") throw new RedirectEntryError(value, "must be a primitive string");
  if (Buffer.byteLength(value, "utf8") > MAX_ENTRY_BYTES) {
    throw new RedirectEntryError(value, `must not exceed ${MAX_ENTRY_BYTES} UTF-8 bytes`);
  }
  if (value.length === 0) throw new RedirectEntryError(value, "must not be empty");
  if (/\s/u.test(value)) throw new RedirectEntryError(value, "must not contain whitespace");
  if (/[\u0000-\u001f\u007f]/u.test(value)) throw new RedirectEntryError(value, "must not contain control characters");
  if (value.includes("*")) throw new RedirectEntryError(value, "must not contain '*'");
  if (value.includes("\\")) throw new RedirectEntryError(value, "must not contain backslashes");
  if (value.includes("?")) throw new RedirectEntryError(value, "must not contain a query delimiter");
  if (value.includes("#")) throw new RedirectEntryError(value, "must not contain a fragment delimiter");
  if (/%(?![0-9a-f]{2})/iu.test(value)) throw new RedirectEntryError(value, "must not contain a malformed percent escape");
  if (/%(?:0[0-9a-f]|1[0-9a-f]|7f)/iu.test(value)) {
    throw new RedirectEntryError(value, "must not percent-encode a C0 control or DEL byte");
  }

  const schemeEnd = value.indexOf("://");
  const authorityEnd = schemeEnd < 0 ? -1 : authorityBoundary(value, schemeEnd + 3);
  if (schemeEnd < 1 || authorityEnd < 0) throw new RedirectEntryError(value, "must be an absolute http(s) URL");
  if (value.slice(schemeEnd + 3, authorityEnd).includes("@")) {
    throw new RedirectEntryError(value, "must not contain userinfo");
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RedirectEntryError(value, "must be a parseable absolute URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new RedirectEntryError(value, "scheme must be https or loopback http");
  }
  if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname)) {
    throw new RedirectEntryError(value, "http is allowed only on localhost, 127.0.0.1, or [::1]");
  }
  if (url.hostname.endsWith(".")) throw new RedirectEntryError(value, "host must not have a trailing dot");

  const form = classifyPath(value, url);
  const canonical = url.href;
  const omittedRootSlash = options.allowOmittedRootSlash === true
    && form === "origin" && `${value}/` === canonical;
  if (value !== canonical && !omittedRootSlash) {
    throw new RedirectEntryError(value, "must use canonical WHATWG spelling", canonical);
  }
  return Object.freeze({ raw: value, url, form, hasExplicitPort: hasExplicitPort(value) });
}

export function redirectEntryProblem(value: unknown, options: RedirectEntryOptions = {}): RedirectEntryError | null {
  try {
    parseRedirectEntry(value, options);
    return null;
  } catch (error) {
    return error instanceof RedirectEntryError
      ? error : new RedirectEntryError(value, "is invalid");
  }
}

export function isLoopbackRedirect(entry: RedirectEntry): boolean {
  return LOOPBACK_HOSTS.has(entry.url.hostname);
}

function classifyPath(raw: string, url: URL): RedirectEntryForm {
  if (url.pathname === "/") return "origin";
  if (!url.pathname.split("/").some((segment) => segment.length > 0)) {
    throw new RedirectEntryError(raw, "path must contain a non-empty segment or be the root path");
  }
  return "exact-uri";
}

function authorityBoundary(value: string, start: number): number {
  const slash = value.indexOf("/", start);
  return slash < 0 ? value.length : slash;
}

function hasExplicitPort(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\/(?:\[[^\]]*\]|[^\s:/?#]+):\d+(?=\/|$)/iu.test(value);
}

function messageFor(entry: unknown, reason: string, canonical?: string): string {
  // Bound the named entry so a hard-capped rejection cannot re-amplify the raw
  // input into an unbounded error_description / allocation (the cap is on work
  // and output as well as acceptance).
  const named = typeof entry === "string"
    ? JSON.stringify(entry.length <= 128 ? entry : `${entry.slice(0, 128)}…(${Buffer.byteLength(entry, "utf8")} bytes)`)
    : `<${entry === null ? "null" : typeof entry}>`;
  return `redirect entry ${named} ${reason}${canonical === undefined ? "" : `; use ${JSON.stringify(canonical)}`}`;
}
