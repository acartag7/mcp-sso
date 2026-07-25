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
import { assertAllowedRedirectUri } from "./redirect.ts";

export interface RegisterDeps {
  config: BridgeConfig;
  clock: ClockPort;
  audit: AuditPort;
}

export interface RegisterInput {
  redirectUris?: string[];
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
  const { config, clock, audit } = deps;
  try {
    // §17.2: reject machine-shaped registrations FIRST. Open DCR must never mint
    // a secret-bearing (machine) client — only out-of-band provisioning can.
    if (input.tokenEndpointAuthMethod !== undefined && input.tokenEndpointAuthMethod !== "none") {
      throw new OAuthError(
        "invalid_client_metadata",
        "token_endpoint_auth_method other than 'none' is not accepted via open registration (§17.2)",
      );
    }
    if (input.grantTypes?.includes("client_credentials")) {
      throw new OAuthError(
        "invalid_client_metadata",
        "grant_types containing client_credentials is not accepted via open registration (§17.2)",
      );
    }
    const rawRedirectUris = arrayOfStrings(input.redirectUris);
    if (rawRedirectUris.length === 0) throw new OAuthError("invalid_request", "redirect_uris is required");
    // STORE the normalized form the validator returns, never the raw input. The
    // §10.2 web policy compares a presented redirect_uri against the registered
    // ones by exact string equality, against an already-normalized `url.href`.
    // Storing raw meant a client registering `https://c.test:443/cb` (accepted —
    // it passes the allowlist) could afterwards authorize with NOTHING: neither
    // its own registered string nor the normalized one ever matched, and the
    // breakage surfaced at authorize rather than at registration.
    const redirectUris = rawRedirectUris.map((uri) => assertAllowedRedirectUri(uri, config.redirectAllowlist));
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

function arrayOfStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
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
