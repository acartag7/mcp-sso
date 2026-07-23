import { OAuthError } from "../errors.ts";
import { headerString, parseNormRequest, type NormRequest } from "./http.ts";

export const CONSENT_HEADERS = Object.freeze({
  "content-type": "text/html; charset=utf-8",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'",
});

export function asOAuth(error: unknown): OAuthError {
  return error instanceof OAuthError
    ? error : new OAuthError("internal_error", "OAuth request failed", 500);
}

export function asDirectOAuth(error: unknown): OAuthError {
  const mapped = asOAuth(error);
  return new OAuthError(mapped.code, mapped.message, mapped.status);
}

export function parseApproved(raw: unknown): boolean {
  return raw === true || raw === "true";
}

export function consentCookie(req: NormRequest): string | undefined {
  const raw = headerString(req.headers, "cookie");
  if (!raw) return undefined;
  const found = raw.split(";").map((part) => part.trim())
    .find((part) => part.startsWith("mcp_idp_consent="));
  return found ? decodeURIComponent(found.slice("mcp_idp_consent=".length)) : undefined;
}

export function requiredRequest(value: unknown): Readonly<NormRequest> {
  const request = parseNormRequest(value);
  if (request === null) throw new OAuthError("invalid_request", "Request is malformed");
  return request;
}
