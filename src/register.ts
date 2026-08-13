// registerClient — RFC 7591 Dynamic Client Registration (contracts §9.2, fix #4).
// Stateless mode (default) mints an ephemeral client_id and persists nothing;
// stored mode persists the ClientRegistration (with applicationType) to the
// ClientStore. Both modes validate each redirect_uri through the global allowlist
// (§10.1) at registration time; stored-mode authorize-time then applies the
// per-type policy (§10.2, RC item b).

import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import type { ApplicationType } from "./ports/client-store.ts";
import type { BridgeConfig } from "./config.ts";
import { OAuthError } from "./errors.ts";
import { assertAllowedRedirectUri, assertRegistrationRedirectPolicy } from "./redirect.ts";
import { writeAuditBestEffort } from "./audit/best-effort.ts";

const MAX_GRANT_TYPES = 32;
const MAX_GRANT_TYPE_BYTES = 256;

export interface RegisterDeps {
  config: BridgeConfig;
  clock: ClockPort;
  audit: AuditPort;
}

export interface RegisterInput {
  redirectUris?: unknown;
  /** RAW client metadata — deliberately `unknown`, not `ApplicationType`. A
   *  present-but-non-string value must be REJECTED (`invalid_client_metadata`),
   *  never coerced to the `"web"` default: silently best-effort-parsing a
   *  malformed value is exactly the fail-open pattern the house rules forbid.
   *  Only ABSENT (`undefined`) takes the default. */
  applicationType?: unknown;
  /** RFC 7591 client-metadata fields that signal a MACHINE client (§17.2). Open
   *  registration rejects `token_endpoint_auth_method` other than `"none"` and
   *  any `grant_types` containing `client_credentials` so the open endpoint can
   *  NEVER mint a secret-bearing client. Passed through here only to be
   *  validated and rejected — they are never persisted. */
  tokenEndpointAuthMethod?: unknown;
  grantTypes?: unknown;
}

export interface RegisteredClient {
  client_id: string;
  client_id_issued_at: number;
  redirect_uris: string[];
  token_endpoint_auth_method: "none";
}

export async function registerClient(deps: RegisterDeps, input: RegisterInput): Promise<RegisteredClient> {
  const { config, clock, audit } = deps;
  try {
    // §17.2: reject machine-shaped registrations FIRST. Open DCR must never mint
    // a secret-bearing (machine) client — only out-of-band provisioning can.
    if (input.tokenEndpointAuthMethod !== undefined) {
      if (typeof input.tokenEndpointAuthMethod !== "string" || input.tokenEndpointAuthMethod.length === 0) {
        throw metadataError("token_endpoint_auth_method must be a non-empty string when present");
      }
      if (input.tokenEndpointAuthMethod !== "none") {
        throw metadataError("token_endpoint_auth_method other than 'none' is not accepted via open registration (§17.2)");
      }
    }
    const grantTypes = optionalGrantTypes(input.grantTypes);
    if (grantTypes?.includes("client_credentials")) {
      throw metadataError("grant_types containing client_credentials is not accepted via open registration (§17.2)");
    }
    const redirectEntries = requiredRedirectArray(input.redirectUris);
    // ABSENT ⇒ the "web" default; PRESENT-but-anything-else ⇒ reject (no coercion).
    const rawApplicationType = input.applicationType === undefined ? "web" : input.applicationType;
    if (rawApplicationType !== "native" && rawApplicationType !== "web") {
      // application_type is client metadata (RFC 7591 §3.1); an invalid value —
      // including "machine", which is a §17.2 machine-shape signal — is
      // invalid_client_metadata, grouped with the machine-shape rejections above.
      throw new OAuthError(
        "invalid_client_metadata",
        "application_type must be 'native' or 'web'; machine clients are provisioned out-of-band (§17.2)",
      );
    }
    const applicationType: ApplicationType = rawApplicationType;
    const redirectUris = redirectEntries.map((entry) => {
      const uri = assertAllowedRedirectUri(entry, config.redirectAllowlist);
      if (config.dcr.mode === "stored") assertRegistrationRedirectPolicy(uri, applicationType);
      return uri;
    });
    const clientId = `mcpdc_${cryptoRandom()}`;
    const issuedAt = Math.floor(clock.nowMs() / 1000);
    if (config.dcr.mode === "stored") {
      await config.dcr.store.save({ clientId, redirectUris, applicationType, issuedAtEpoch: issuedAt });
    }
    await writeAuditBestEffort(audit, {
      occurredAt: new Date(clock.nowMs()).toISOString(),
      event: "oauth.register", status: "success",
      redirectHost: redirectUris[0] ? hostOf(redirectUris[0]) : undefined,
    });
    return { client_id: clientId, client_id_issued_at: issuedAt, redirect_uris: redirectUris, token_endpoint_auth_method: "none" };
  } catch (error) {
    await writeAuditBestEffort(audit, {
      occurredAt: new Date(clock.nowMs()).toISOString(),
      event: "oauth.register", status: "failure",
      reason: error instanceof OAuthError ? error.code : "invalid_request",
    });
    throw error;
  }
}

function requiredRedirectArray(value: unknown): unknown[] {
  if (value === undefined) throw new OAuthError("invalid_request", "redirect_uris is required");
  if (!Array.isArray(value)) throw metadataError("redirect_uris must be an array");
  // Capture length ONCE, require an integer in the closed domain, then read each
  // selected index once. A Proxy that changes length across reads cannot enlarge
  // the scan past the cap, and NaN/1.5 cannot collapse a present array to empty.
  const length = value.length;
  if (!Number.isInteger(length) || length < 1 || length > 16) {
    throw metadataError("redirect_uris must contain 1..16 entries");
  }
  return Array.from({ length }, (_, index) => value[index]);
}

function optionalGrantTypes(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) throw metadataError("grant_types must be an array");
  // Same read-once discipline as redirect_uris: one length, one read per index.
  const length = value.length;
  if (!Number.isInteger(length) || length < 0 || length > MAX_GRANT_TYPES) {
    throw metadataError(`grant_types must contain 0..${MAX_GRANT_TYPES} entries`);
  }
  const snapshot = Array.from({ length }, (_, index) => value[index]);
  for (const entry of snapshot) {
    if (typeof entry !== "string" || entry.length === 0) {
      throw metadataError("grant_types entries must be non-empty primitive strings");
    }
    if (Buffer.byteLength(entry, "utf8") > MAX_GRANT_TYPE_BYTES) {
      throw metadataError(`grant_types entries must not exceed ${MAX_GRANT_TYPE_BYTES} UTF-8 bytes`);
    }
  }
  return snapshot as string[];
}

function metadataError(message: string): OAuthError {
  return new OAuthError("invalid_client_metadata", message);
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
