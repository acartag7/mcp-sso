import type { JWTPayload } from "jose";
import { snapshotOwnDataArray } from "./own-property.ts";
import type { ConsentRequestClaims, VerifiedAccessToken } from "./crypto.ts";

export const CONSENT_TYP = "mcp-sso-consent";

export function consentClaims(payload: JWTPayload): ConsentRequestClaims {
  if (payload.typ !== CONSENT_TYP) throw new Error("wrong token type");
  const scopes = scopeClaim(payload.scope);
  const allowedScopes = typeof payload.allowed_scopes === "string" && payload.allowed_scopes.trim()
    ? payload.allowed_scopes.split(/\s+/) : undefined;
  return {
    clientId: requiredString(payload.client_id, "client_id"),
    redirectUri: requiredString(payload.redirect_uri, "redirect_uri"),
    resource: requiredString(payload.resource, "resource"),
    scopes,
    codeChallenge: requiredString(payload.code_challenge, "code_challenge"),
    codeChallengeMethod: "S256",
    state: stringClaim(payload.state),
    subject: requiredString(payload.sub, "sub"),
    allowedScopes,
  };
}

export function accessClaims(payload: JWTPayload): VerifiedAccessToken {
  return {
    subject: requiredString(payload.sub, "sub"),
    clientId: requiredString(payload.client_id, "client_id"),
    scopes: scopeClaim(payload.scope),
  };
}

function scopeClaim(value: unknown): string[] {
  return typeof value === "string" && value.trim() ? value.split(/\s+/) : [];
}

export function requiredString(value: unknown, label: string): string {
  if (typeof value === "string" && value) return value;
  throw new Error(`missing ${label}`);
}

export function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

export function audienceMatches(value: unknown, expected: string): boolean {
  if (typeof value === "string") return value === expected;
  const values = snapshotOwnDataArray(value);
  return values !== null && values.every((entry) => typeof entry === "string")
    && values.includes(expected);
}
