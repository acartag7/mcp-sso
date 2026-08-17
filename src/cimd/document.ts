import { CimdError } from "./errors.ts";
import { parseRedirectEntry } from "../redirect-entry.ts";

export interface CimdDocument {
  readonly client_id: string;
  readonly client_name: string;
  readonly redirect_uris: readonly string[];
  readonly application_type?: CimdApplicationType;
  /** Library-selected public method; absent for a natively public document. */
  readonly selectedClientAuthMethod?: "none";
  readonly raw: Record<string, unknown>;
}

export type CimdApplicationType = "native" | "web";

const PRIVATE_JWK_MEMBERS = new Set(["d", "p", "q", "dp", "dq", "qi", "oth", "k"]);

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
  const applicationType = parsed.application_type;
  let validatedApplicationType: CimdApplicationType | undefined;
  if (typeof clientId !== "string" || clientId !== rawClientId) throw invalid();
  if (typeof clientName !== "string" || clientName.length === 0 || clientName.length > 256) throw invalid();
  if (!Array.isArray(redirectUris) || redirectUris.length < 1 || redirectUris.length > 16) throw invalid();
  for (const redirectUri of redirectUris) assertCimdRedirectUri(redirectUri);

  if (Object.hasOwn(parsed, "application_type")) {
    if (applicationType !== "native" && applicationType !== "web") throw invalid();
    validatedApplicationType = applicationType;
  }

  const selectedClientAuthMethod = selectClientAuthMethod(parsed);
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
    ...(validatedApplicationType === undefined ? {} : { application_type: validatedApplicationType }),
    ...(selectedClientAuthMethod === undefined ? {} : { selectedClientAuthMethod }),
    raw: parsed,
  };
}

function selectClientAuthMethod(document: Record<string, unknown>): "none" | undefined {
  const hasMethod = Object.hasOwn(document, "token_endpoint_auth_method");
  const hasChoices = Object.hasOwn(document, "token_endpoint_auth_methods_supported");
  const method = document.token_endpoint_auth_method;
  if (hasChoices) {
    const choices = document.token_endpoint_auth_methods_supported;
    if (!Array.isArray(choices)
      || !choices.every((choice) => typeof choice === "string" && choice.length > 0)
      || !choices.includes("none")) throw invalid();
    if (hasMethod && (typeof method !== "string" || !choices.includes(method))) throw invalid();
  }
  if (!hasMethod || method === "none") return undefined;
  if (method === "private_key_jwt" && hasChoices) return "none";
  throw invalid();
}

export function assertCimdRedirectUri(raw: unknown): void {
  try {
    parseRedirectEntry(raw);
  } catch {
    throw invalid();
  }
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
  if (!Array.isArray(value)
    || !value.every((entry) => typeof entry === "string" && entry.length > 0)
    || !value.includes("authorization_code")) {
    throw invalid();
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function invalid(): CimdError {
  return new CimdError("document_invalid");
}
