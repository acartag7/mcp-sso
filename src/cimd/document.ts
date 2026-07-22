import { CimdError } from "./errors.ts";

export interface CimdDocument {
  readonly client_id: string;
  readonly client_name: string;
  readonly redirect_uris: readonly string[];
  readonly raw: Record<string, unknown>;
}

const PRIVATE_JWK_MEMBERS = new Set(["d", "p", "q", "dp", "dq", "qi", "oth", "k"]);
const GRANT_TYPES = new Set(["authorization_code", "refresh_token"]);
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function validateCimdDocument(rawBody: string, rawClientId: string): CimdDocument {
  if (typeof rawBody !== "string" || typeof rawClientId !== "string") throw invalid();
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    throw invalid();
  }
  if (!isObject(parsed)) throw invalid();

  const clientId = parsed.client_id;
  const clientName = parsed.client_name;
  const redirectUris = parsed.redirect_uris;
  if (typeof clientId !== "string" || clientId !== rawClientId) throw invalid();
  if (typeof clientName !== "string" || clientName.length === 0 || clientName.length > 256) throw invalid();
  if (!Array.isArray(redirectUris) || redirectUris.length < 1 || redirectUris.length > 16) throw invalid();
  for (const redirectUri of redirectUris) assertCimdRedirectUri(redirectUri);

  if (Object.hasOwn(parsed, "token_endpoint_auth_method")
    && parsed.token_endpoint_auth_method !== "none") throw invalid();
  if (Object.hasOwn(parsed, "client_secret") || Object.hasOwn(parsed, "client_secret_expires_at")) {
    throw invalid();
  }
  if (Object.hasOwn(parsed, "jwks")) assertPublicJwks(parsed.jwks);
  if (Object.hasOwn(parsed, "response_types")) assertResponseTypes(parsed.response_types);
  if (Object.hasOwn(parsed, "grant_types")) assertGrantTypes(parsed.grant_types);

  return {
    client_id: clientId,
    client_name: clientName,
    redirect_uris: [...redirectUris] as string[],
    raw: parsed,
  };
}

export function assertCimdRedirectUri(raw: string): void {
  if (typeof raw !== "string" || raw === "" || raw.trim() !== raw) throw invalid();
  if (raw.includes("\\") || raw.includes("#") || /[\x00-\x1f\x7f]/.test(raw)) throw invalid();
  if (/%(?![0-9a-f]{2})/i.test(raw)) throw invalid();

  const schemeEnd = raw.indexOf("://");
  if (schemeEnd < 1) throw invalid();
  const authorityStart = schemeEnd + 3;
  const authorityEnd = findAuthorityEnd(raw, authorityStart);
  const authority = raw.slice(authorityStart, authorityEnd);
  if (authority.includes("@")) throw invalid();

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw invalid();
  }
  if (url.hostname === "" || url.username || url.password || url.hash || url.hostname.includes("*")) {
    throw invalid();
  }
  if (url.protocol === "https:") return;
  if (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)
    && rawAuthorityHost(authority).toLowerCase() === url.hostname.toLowerCase()) return;
  throw invalid();
}

function assertPublicJwks(value: unknown): void {
  if (!isObject(value) || !Array.isArray(value.keys)) throw invalid();
  for (const key of value.keys) {
    if (!isObject(key)) throw invalid();
    for (const member of PRIVATE_JWK_MEMBERS) {
      if (Object.hasOwn(key, member)) throw invalid();
    }
  }
}

function assertResponseTypes(value: unknown): void {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string")
    || !value.includes("code")) throw invalid();
}

function assertGrantTypes(value: unknown): void {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string" && GRANT_TYPES.has(entry))) {
    throw invalid();
  }
}

function findAuthorityEnd(raw: string, start: number): number {
  const indexes = [raw.indexOf("/", start), raw.indexOf("?", start)].filter((index) => index >= 0);
  return indexes.length === 0 ? raw.length : Math.min(...indexes);
}

function rawAuthorityHost(authority: string): string {
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    return close < 0 ? "" : authority.slice(0, close + 1);
  }
  const colon = authority.lastIndexOf(":");
  return colon < 0 ? authority : authority.slice(0, colon);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function invalid(): CimdError {
  return new CimdError("document_invalid");
}
