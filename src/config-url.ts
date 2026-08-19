// Absolute-URL grammar for BridgeConfig issuer/resource (contracts §5). The
// decision runs on the raw string as well as WHATWG's canonical serialization,
// so a spelling the serializer would rewrite can never reach the frozen config
// (the raw value is emitted verbatim into iss claims, AS metadata, and the
// Basic realm — owner decision 2026-08-19: reject, never silently normalize).

import { AuthConfigError } from "./config-error.ts";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function validateUrl(allowInsecureLocalhost: boolean, label: string, value: unknown): void {
  if (typeof value !== "string") throw new AuthConfigError(`${label} must be an absolute URL`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuthConfigError(`${label} must be an absolute URL`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new AuthConfigError(`${label} must be https:// or http://`);
  }
  if (allowInsecureLocalhost) {
    if (!LOOPBACK_HOSTS.has(url.hostname)) {
      throw new AuthConfigError(`dev.allowInsecureLocalhost requires a loopback origin for ${label}`);
    }
    // loopback: http or https both permitted
  } else if (url.protocol !== "https:") {
    throw new AuthConfigError(`${label} must be https:// (use dev.allowInsecureLocalhost for local http)`);
  }
  // Byte-equality with the WHATWG serialization (§5, owner decision
  // 2026-08-19): the raw spelling is stored verbatim and byte-copied into JWT
  // `iss` claims, AS metadata, and the Basic realm, so anything `new URL()`
  // would rewrite (CR/LF/TAB it strips, an uppercase or percent-encoded host,
  // a query it moves behind the root path) is a boot failure naming the
  // canonical form — never silently normalized. The one permitted deviation is
  // the root slash WHATWG appends to an origin-form value (§10.0's
  // `allowOmittedRootSlash`).
  if (value !== url.href && `${value}/` !== url.href) {
    throw new AuthConfigError(`${label} must use canonical WHATWG spelling; use ${JSON.stringify(url.href)}`);
  }
}
