import type { DatabaseSync } from "node:sqlite";
import type { ClientRegistration, UserClientRegistration } from "../ports/client-store.ts";
import { StoreInputError } from "../ports/store.ts";
import { assertRegistrationRedirectPolicy } from "../redirect.ts";

const GENERATED_CLIENT_ID = /^mcpdc_[0-9a-f]{32}$/u;

interface ClientRow {
  client_id: unknown;
  redirect_uris_json: unknown;
  application_type: unknown;
  issued_at_epoch: unknown;
}

export function saveSqliteClient(db: DatabaseSync, value: ClientRegistration): void {
  const client = snapshotUserClient(value);
  db.prepare(`INSERT INTO oauth_clients (
    client_id, redirect_uris_json, application_type, issued_at_epoch
  ) VALUES (?, ?, ?, ?)`).run(
    client.clientId,
    JSON.stringify(client.redirectUris),
    client.applicationType,
    client.issuedAtEpoch,
  );
}

export function findSqliteClient(db: DatabaseSync, clientId: string): UserClientRegistration | null {
  if (typeof clientId !== "string" || !GENERATED_CLIENT_ID.test(clientId)) return null;
  const row = db.prepare(
    `SELECT client_id, redirect_uris_json, application_type, issued_at_epoch
     FROM oauth_clients WHERE client_id = ?`,
  ).get(clientId) as ClientRow | undefined;
  if (!row) return null;
  if (row.client_id !== clientId
    || typeof row.redirect_uris_json !== "string"
    || (row.application_type !== "native" && row.application_type !== "web")
    || typeof row.issued_at_epoch !== "number") {
    throw new Error("Stored client row is invalid");
  }
  return snapshotUserClient({
    clientId: row.client_id,
    redirectUris: parseRedirectJson(row.redirect_uris_json),
    applicationType: row.application_type,
    issuedAtEpoch: row.issued_at_epoch,
  });
}

function snapshotUserClient(value: unknown): UserClientRegistration {
  try {
    if (value === null || typeof value !== "object") throw invalidClient();
    const record = value as unknown as Record<string, unknown>;
    const clientId = record.clientId;
    const applicationType = record.applicationType;
    const issuedAtEpoch = record.issuedAtEpoch;
    const redirectValue = record.redirectUris;
    if (typeof clientId !== "string" || !GENERATED_CLIENT_ID.test(clientId)) throw invalidClient();
    if (applicationType !== "native" && applicationType !== "web") throw invalidClient();
    if (!Number.isSafeInteger(issuedAtEpoch) || (issuedAtEpoch as number) < 0) throw invalidClient();
    if (!Array.isArray(redirectValue)) throw invalidClient();
    const length = redirectValue.length;
    if (!Number.isInteger(length) || length < 1 || length > 16) throw invalidClient();
    const redirectUris = Array.from({ length }, (_, index) => redirectValue[index]);
    for (const redirectUri of redirectUris) {
      assertRegistrationRedirectPolicy(redirectUri, applicationType);
    }
    return {
      clientId,
      redirectUris: redirectUris as string[],
      applicationType,
      issuedAtEpoch: issuedAtEpoch as number,
    };
  } catch (error) {
    if (error instanceof StoreInputError) throw error;
    throw invalidClient();
  }
}

function parseRedirectJson(value: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("Stored client redirect URIs are invalid");
  }
  return parsed;
}

function invalidClient(): StoreInputError {
  return new StoreInputError("client registration is invalid");
}
