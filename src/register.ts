// registerClient — RFC 7591 Dynamic Client Registration (contracts §9.2, fix #4).
// Stateless mode (default) mints an ephemeral client_id and persists nothing;
// stored mode persists the ClientRegistration (with applicationType) to the
// ClientStore. Both modes validate each redirect_uri through the global allowlist
// (§10.1) at registration time; stored-mode authorize-time then applies the
// per-type policy (§10.2, RC item b).

import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import type { ApplicationType } from "./ports/client-store.ts";
import { assertBridgeConfig, type BridgeConfig } from "./config.ts";
import { OAuthError } from "./errors.ts";
import { assertAllowedRedirectUri } from "./redirect.ts";
import { snapshotOwnDataRecord, snapshotOwnStringArray } from "./own-property.ts";

export interface RegisterDeps {
  config: BridgeConfig;
  clock: ClockPort;
  audit: AuditPort;
}

export interface RegisterInput {
  redirectUris?: string[];
  applicationType?: ApplicationType;
  /** RFC 7591 client-metadata fields that signal a MACHINE client (§17.2). Open
   *  registration rejects `token_endpoint_auth_method` other than `"none"` and
   *  any `grant_types` containing `client_credentials` so the open endpoint can
   *  NEVER mint a secret-bearing client. Passed through here only to be
   *  validated and rejected — they are never persisted. */
  tokenEndpointAuthMethod?: string;
  grantTypes?: string[];
}

export interface RegisteredClient {
  client_id: string;
  client_id_issued_at: number;
  redirect_uris: string[];
  token_endpoint_auth_method: "none";
}

export async function registerClient(deps: RegisterDeps, input: RegisterInput): Promise<RegisteredClient> {
  const depFields = snapshotOwnDataRecord(deps);
  if (depFields === null || !depFields.config || !depFields.clock || !depFields.audit) {
    throw new TypeError("Registration dependencies must be own data properties");
  }
  const config = assertBridgeConfig(depFields.config);
  const clock = depFields.clock as ClockPort;
  const audit = depFields.audit as AuditPort;
  try {
    const inputSnapshot = snapshotOwnDataRecord(input);
    if (inputSnapshot === null) throw new OAuthError("invalid_request", "registration input must be a data object");
    const safeInput = inputSnapshot as unknown as RegisterInput;
    // §17.2: reject machine-shaped registrations FIRST. Open DCR must never mint
    // a secret-bearing (machine) client — only out-of-band provisioning can.
    if (safeInput.tokenEndpointAuthMethod !== undefined && safeInput.tokenEndpointAuthMethod !== "none") {
      throw new OAuthError(
        "invalid_client_metadata",
        "token_endpoint_auth_method other than 'none' is not accepted via open registration (§17.2)",
      );
    }
    const grantTypes = optionalStringArray(safeInput.grantTypes, "grant_types");
    if (grantTypes?.includes("client_credentials")) {
      throw new OAuthError(
        "invalid_client_metadata",
        "grant_types containing client_credentials is not accepted via open registration (§17.2)",
      );
    }
    const redirectUris = optionalStringArray(safeInput.redirectUris, "redirect_uris");
    if (!redirectUris || redirectUris.length === 0) throw new OAuthError("invalid_request", "redirect_uris is required");
    for (const uri of redirectUris) assertAllowedRedirectUri(uri, config.redirectAllowlist);
    const applicationType: ApplicationType = safeInput.applicationType ?? "web";
    if (applicationType !== "native" && applicationType !== "web") {
      // application_type is client metadata (RFC 7591 §3.1); an invalid value —
      // including "machine", which is a §17.2 machine-shape signal — is
      // invalid_client_metadata, grouped with the machine-shape rejections above.
      throw new OAuthError(
        "invalid_client_metadata",
        "application_type must be 'native' or 'web'; machine clients are provisioned out-of-band (§17.2)",
      );
    }
    const clientId = `mcpdc_${cryptoRandom()}`;
    const issuedAt = Math.floor(clock.nowMs() / 1000);
    if (config.dcr.mode === "stored") {
      await config.dcr.store.save({ clientId, redirectUris, applicationType, issuedAtEpoch: issuedAt });
    }
    await audit.writeAuthEvent({
      occurredAt: new Date(clock.nowMs()).toISOString(),
      event: "oauth.register", status: "success",
      redirectHost: redirectUris[0] ? hostOf(redirectUris[0]) : undefined,
    });
    return { client_id: clientId, client_id_issued_at: issuedAt, redirect_uris: redirectUris, token_endpoint_auth_method: "none" };
  } catch (error) {
    await audit.writeAuthEvent({
      occurredAt: new Date(clock.nowMs()).toISOString(),
      event: "oauth.register", status: "failure",
      reason: error instanceof OAuthError ? error.code : "invalid_request",
    });
    throw error;
  }
}

function optionalStringArray(value: unknown, label: string): string[] | undefined {
  if (value === undefined) return undefined;
  const snapshot = snapshotOwnStringArray(value);
  if (snapshot === null || snapshot.some((item) => item.length === 0)) {
    throw new OAuthError("invalid_request", `${label} must be a dense array of non-empty strings`);
  }
  return [...snapshot];
}

function cryptoRandom(): string {
  return globalThis.crypto.randomUUID().replaceAll("-", "");
}

function hostOf(value: string): string | undefined {
  try {
    const u = new URL(value);
    return `${u.protocol}//${u.host}`;
  } catch {
    return undefined;
  }
}
