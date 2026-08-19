// Shared fixtures for the StorePort conformance suite (contracts §12). Kept in
// one module so every section builds its records identically — a downstream
// adapter that passes one section on hand-rolled inputs and another on these
// would not have been held to the same contract.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { ClockPort } from "../ports/clock.ts";
import type { SaveAuthCodeInput, SaveRefreshTokenInput, StorePort } from "../ports/store.ts";

/** A store factory: one fresh, independent store per conformance row. */
export type MakeStore = () => StorePort | Promise<StorePort>;

export const NOW = "2026-07-03T12:00:00.000Z";
export const LATER = "2026-07-03T12:05:00.000Z";
export const FUTURE = "2026-07-03T13:00:00.000Z";
export const PAST = "2026-07-03T11:00:00.000Z";
export const RESOURCE_A = "https://api-a.test/mcp";
export const RESOURCE_B = "https://api-b.test/mcp";
export const STORE_EXPIRY_SWEEP_INTERVAL_MS = 300_000;

export function startExpiryCollection(store: StorePort, clock: ClockPort): void {
  assert.equal(typeof store.startExpiryCollection, "function");
  store.startExpiryCollection?.(clock);
}

export async function settleUntil(done: () => boolean): Promise<void> {
  for (let turn = 0; turn < 1_000 && !done(); turn++) {
    // setTimeout is mocked in these rows; a one-shot real setInterval turn gives
    // live SQL I/O time to settle instead of spinning through setImmediate only.
    await new Promise<void>((resolve) => {
      const interval = setInterval(() => { clearInterval(interval); resolve(); }, 1);
    });
  }
  assert.equal(done(), true, "scheduled work did not settle");
}

export function authCode(rawCode: string, expiresAt: string, grantGeneration?: number | null): SaveAuthCodeInput {
  return {
    codeHash: sha256Hex(rawCode), clientId: "client-1", subject: "subject-1",
    redirectUri: "https://client.test/callback", resource: "https://api.test/mcp",
    scopes: ["mcp:read"], codeChallenge: "pkce-challenge",
    codeChallengeMethod: "S256", expiresAt, grantGeneration,
  };
}

export function refresh(rawToken: string, familyId: string, previousTokenHash: string | null, expiresAt: string, grantGeneration?: number | null, resource = RESOURCE_A): SaveRefreshTokenInput {
  return {
    tokenHash: sha256Hex(rawToken), familyId, previousTokenHash,
    clientId: "client-1", subject: "subject-1", resource,
    scopes: ["mcp:read"], expiresAt, grantGeneration,
  };
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
