// Exact browser-Origin grammar for BridgeConfig.allowedOrigins (contracts §5).
// The parser decides on the raw string as well as WHATWG's canonical form so
// normalization cannot turn a non-origin URL spelling into trusted config.

import { AuthConfigError } from "./config-error.ts";
import { snapshotStringArray } from "./config-snapshot.ts";

const MAX_ALLOWED_ORIGIN_BYTES = 2048;

/** Snapshot and validate the complete `allowedOrigins` boot value. */
export function validateAllowedOrigins(value: unknown): string[] {
  const entries = snapshotStringArray(
    "allowedOrigins", value, (message) => new AuthConfigError(message),
  );
  for (const entry of entries) assertAllowedOrigin(entry);
  return entries;
}

/** Validate one exact canonical HTTP(S) browser origin. */
export function assertAllowedOrigin(value: string): void {
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes > MAX_ALLOWED_ORIGIN_BYTES) {
    throw invalid(value, `must not exceed ${MAX_ALLOWED_ORIGIN_BYTES} UTF-8 bytes`);
  }
  if (value === "null") throw invalid(value, "must not be the opaque browser origin");
  if (value.length === 0) throw invalid(value, "must not be empty");
  if (/[\u0000-\u001f\u007f]/u.test(value)) throw invalid(value, "must not contain control characters");
  if (/\s/u.test(value)) throw invalid(value, "must not contain whitespace");
  if (value.includes("*")) throw invalid(value, "must not contain '*'");
  if (value.includes("\\")) throw invalid(value, "must not contain backslashes");
  if (value.includes("?")) throw invalid(value, "must not contain a query delimiter");
  if (value.includes("#")) throw invalid(value, "must not contain a fragment delimiter");

  const schemeEnd = value.indexOf("://");
  const authorityEnd = schemeEnd < 0 ? -1 : authorityBoundary(value, schemeEnd + 3);
  if (schemeEnd < 1 || authorityEnd < 0) throw invalid(value, "must be an absolute http(s) origin");
  if (value.slice(schemeEnd + 3, authorityEnd).includes("@")) {
    throw invalid(value, "must not contain userinfo");
  }

  let url: URL;
  try { url = new URL(value); }
  catch { throw invalid(value, "must be a parseable absolute origin"); }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw invalid(value, "scheme must be http or https");
  }
  if (url.pathname !== "/") throw invalid(value, "must not contain a path");
  if (value.endsWith("/")) throw invalid(value, "must not contain a trailing slash");
  if (url.origin !== value) {
    throw invalid(value, `must use canonical WHATWG origin spelling; use ${JSON.stringify(url.origin)}`);
  }
}

function authorityBoundary(value: string, start: number): number {
  const slash = value.indexOf("/", start);
  return slash < 0 ? value.length : slash;
}

function invalid(value: string, reason: string): AuthConfigError {
  const named = value.length <= 128
    ? value : `${value.slice(0, 128)}…(${Buffer.byteLength(value, "utf8")} bytes)`;
  return new AuthConfigError(`allowedOrigins entry ${JSON.stringify(named)} ${reason}`);
}
