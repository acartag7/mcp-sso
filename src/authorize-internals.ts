import { OAuthError } from "./errors.ts";
import { snapshotOwnStringArray } from "./own-property.ts";

export function redirectWithCode(
  redirectUri: string,
  code: string,
  issuer: string,
  state?: string,
): string {
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  url.searchParams.set("iss", issuer);
  if (state) url.searchParams.set("state", state);
  url.hash = "";
  return url.href;
}

export function hostOf(value: string): string | undefined {
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}`;
  } catch {
    return undefined;
  }
}

export function dedupe(values: string[]): string[] {
  const out: string[] = [];
  for (const value of values) if (!out.includes(value)) out.push(value);
  return out;
}

export function requiredStr(value: string | undefined, label: string): string {
  if (typeof value === "string" && value) return value;
  throw new OAuthError("invalid_request", `${label} is required`);
}

export function optionalStr(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "string") return value;
  throw new OAuthError("invalid_request", `${label} must be a string`);
}

export function grantedScopes(value: unknown, catalog: readonly string[]): string[] {
  const scopes = snapshotOwnStringArray(value);
  if (scopes === null || !scopes.every((scope) => catalog.includes(scope))) {
    throw new OAuthError("server_error", "Stored grant scopes are malformed", 500);
  }
  return [...scopes];
}
