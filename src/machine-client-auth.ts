import type { ClientStore } from "./ports/client-store.ts";
import type { ClockPort } from "./ports/clock.ts";
import type { MachineClientDeps } from "./machine-client.ts";
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
  deps: { store: ClientStore; clock: ClockPort; resource: string },
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
  const activeClient = client?.status === "active" && client.resource === deps.resource
    ? client : null;
  const matched = verifyPresentedHash(
    presentedHash,
    activeClient?.secrets ?? [],
    now,
  );
  return activeClient && matched ? activeClient : null;
}

/** Timing-safe verification. Missing, disabled, malformed, or poisoned rows
 * return false; store I/O failures still propagate. */
export async function verifyMachineClientSecret(
  deps: MachineClientDeps,
  clientId: string,
  presentedSecret: string,
): Promise<boolean> {
  return await authenticateMachineClientSecret(deps, clientId, presentedSecret) !== null;
}
