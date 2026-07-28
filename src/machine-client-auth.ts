import type { ClientStore } from "./ports/client-store.ts";
import type { ClockPort } from "./ports/clock.ts";
import {
  hashMachineClientSecret,
  verifyPresentedHash,
} from "./machine-client-secret.ts";
import {
  parseMachineClientRegistration,
  type ParsedActiveMachineClientRegistration,
} from "./machine-client-record.ts";

/** Read and authenticate one immutable machine-client snapshot. */
export async function authenticateMachineClientSecret(
  deps: { store: ClientStore; clock: ClockPort },
  clientId: string,
  presentedSecret: string,
): Promise<ParsedActiveMachineClientRegistration | null> {
  if (typeof presentedSecret !== "string" || presentedSecret.length === 0) return null;
  const presentedHash = hashMachineClientSecret(presentedSecret);
  const now = Math.floor(deps.clock.nowMs() / 1000);
  const client = parseMachineClientRegistration(
    await deps.store.find(clientId),
    clientId,
    now,
  );
  return client?.status === "active"
    && verifyPresentedHash(presentedHash, client.secrets, now)
    ? client
    : null;
}

/** Timing-safe verification. Missing, disabled, malformed, or poisoned rows
 * return false; store I/O failures still propagate. */
export async function verifyMachineClientSecret(
  deps: { store: ClientStore; clock: ClockPort },
  clientId: string,
  presentedSecret: string,
): Promise<boolean> {
  return await authenticateMachineClientSecret(deps, clientId, presentedSecret) !== null;
}
