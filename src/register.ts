// registerClient — RFC 7591 Dynamic Client Registration (contracts §9.2, fix #4).
// Stateless mode (default) mints an ephemeral client_id and persists nothing;
// stored mode persists the ClientRegistration (with applicationType) to the
// ClientStore. Both modes validate each redirect_uri through the global allowlist
// (§10.1) at registration time; stored-mode authorize-time then applies the
// per-type policy (§10.2, RC item b).

import type { ClockPort } from "./ports/clock.js";
import type { AuditPort } from "./ports/audit.js";
import type { ApplicationType } from "./ports/client-store.js";
import type { BridgeConfig } from "./config.js";
import { OAuthError } from "./errors.js";
import { assertAllowedRedirectUri } from "./redirect.js";

export interface RegisterDeps {
  config: BridgeConfig;
  clock: ClockPort;
  audit: AuditPort;
}

export interface RegisterInput {
  redirectUris?: string[];
  applicationType?: ApplicationType;
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
    const redirectUris = arrayOfStrings(input.redirectUris);
    if (redirectUris.length === 0) throw new OAuthError("invalid_request", "redirect_uris is required");
    for (const uri of redirectUris) assertAllowedRedirectUri(uri, config.redirectAllowlist);
    const applicationType: ApplicationType = input.applicationType ?? "web";
    if (applicationType !== "native" && applicationType !== "web") {
      throw new OAuthError("invalid_request", "application_type must be 'native' or 'web'");
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
