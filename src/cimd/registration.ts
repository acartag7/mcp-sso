// CimdRegistration — the named projection carried through the S6b flow
// (contracts §17.1.6 decision 1c). It is deliberately NOT the committed
// `CimdDocument` (which still exposes `raw`): signing or caching a raw document
// would carry attacker-controlled members into the flow cookie / consent page.
// Everything here is pure: shape classification, the SHARED redirect matcher
// (decision 1, used at authorize + callback + prepare's re-check), and the
// strict parse of the signed `cimd` flow-cookie claim.

import { assertCimdRedirectUri, type CimdDocument } from "./document.ts";
import { isLoopbackRedirect, parseRedirectEntry } from "../redirect-entry.ts";

export interface CimdRegistration {
  readonly client_id: string;
  readonly client_name: string;
  readonly redirect_uris: readonly string[];
}

/** RFC 3986 scheme syntax followed by "://" (§17.1.5 rule 22). */
const SCHEME_SHAPED = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const MAX_REDIRECT_URIS = 16;
const MAX_CLIENT_NAME = 256;

/** Any scheme-shaped client_id — NEVER eligible for the stateless-DCR
 *  ephemeral-client fallback (rule 22). */
export function isSchemeShaped(clientId: unknown): boolean {
  return typeof clientId === "string" && SCHEME_SHAPED.test(clientId);
}

/** Only a LITERAL lowercase `https://` prefix enters CIMD admission (rule 22);
 *  `HTTPS://`, `http://`, `ftp://`, `web+foo://` are scheme-shaped but not CIMD. */
export function isCimdClientId(clientId: unknown): boolean {
  return typeof clientId === "string" && clientId.startsWith("https://");
}

/** Explicit named-field projection at the fetch boundary (decision 1c). */
export function projectCimdRegistration(document: CimdDocument): CimdRegistration {
  const redirectUris = [...document.redirect_uris];
  for (const uri of redirectUris) assertCimdRedirectUri(uri);
  return Object.freeze({
    client_id: document.client_id,
    client_name: document.client_name,
    redirect_uris: Object.freeze(redirectUris),
  });
}

/** Strict parse of the signed `cimd` flow-cookie claim (decision 1d(i)). A
 *  present-but-malformed claim THROWS, which fails cookie verification ⇒
 *  callback row 3 (`invalid_request`, audit `flow_cookie_invalid`). Never
 *  `Object.assign`, never the lenient string-only `params` loop. */
export function parseCimdRegistrationClaim(value: unknown, expectedClientId: unknown): CimdRegistration {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("cimd claim must be an object");
  }
  const raw = value as Record<string, unknown>;
  const clientId = raw.client_id;
  const clientName = raw.client_name;
  const redirectUris = raw.redirect_uris;
  if (typeof clientId !== "string" || typeof expectedClientId !== "string" || clientId !== expectedClientId) {
    throw new Error("cimd claim client_id does not match the flow params");
  }
  if (typeof clientName !== "string" || clientName.length === 0 || clientName.length > MAX_CLIENT_NAME) {
    throw new Error("cimd claim client_name is invalid");
  }
  if (!Array.isArray(redirectUris) || redirectUris.length < 1 || redirectUris.length > MAX_REDIRECT_URIS) {
    throw new Error("cimd claim redirect_uris is invalid");
  }
  const uris: string[] = [];
  for (const uri of redirectUris) {
    if (typeof uri !== "string" || uri.length === 0) throw new Error("cimd claim redirect_uris entry is invalid");
    uris.push(uri);
  }
  return Object.freeze({ client_id: clientId, client_name: clientName, redirect_uris: Object.freeze(uris) });
}

/** THE shared CIMD redirect matcher (§17.1.6 decision 1, rule 20). An https
 *  entry matches by EXACT raw-string equality (no normalization, port
 *  included); a loopback `http` entry matches RFC 8252 any-port using the
 *  runtime semantics of src/redirect.ts:95-103 (scheme, host, path, and search
 *  equal; port ignored). Called at authorize, at the callback row-5a gate, and
 *  at prepare's defensive re-check — never array `includes`. */
export function cimdRedirectMatches(presented: unknown, registered: readonly string[]): boolean {
  if (!Array.isArray(registered)) return false;
  try {
    const candidate = parseRedirectEntry(presented);
    const entries = registered.map((entry) => parseRedirectEntry(entry));
    return entries.some((entry) => entry.raw === candidate.raw || (
      entry.url.protocol === "http:" && isLoopbackRedirect(entry)
      && candidate.url.protocol === entry.url.protocol
      && candidate.url.hostname === entry.url.hostname
      && candidate.url.pathname === entry.url.pathname
    ));
  } catch {
    return false;
  }
}

/** §17.1.4 consent obligation: SHOULD warn when EVERY registered redirect is
 *  loopback (the MCP localhost-impersonation consideration). */
export function everyRedirectIsLoopback(uris: readonly string[]): boolean {
  if (!Array.isArray(uris) || uris.length === 0) return false;
  return uris.every((uri) => {
    try {
      const url = new URL(uri);
      return url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
    } catch {
      return false;
    }
  });
}

/** Host of a validated absolute URL, for display only; falls back to the raw
 *  string so the renderer never throws on an unexpected value. */
export function displayHost(value: string): string {
  try {
    return new URL(value).host;
  } catch {
    return value;
  }
}
