// ConsolePairingIdentity provenance boundary for the root-exported pairing
// orchestrator. Caller-owned methods and every selected returned field stay
// inside callPort; the handler later touches only library-owned plain data.

import type {
  ConsolePairingIdentity, ConsolePairingVerifyInput, PairingSession,
} from "../identity/console-pairing.ts";
import type { IdentityResult } from "../ports/identity.ts";
import { callPort } from "../port-failure.ts";
import { snapshotIdentityResult } from "../port-result.ts";

const MAX_PAIRING_NONCE_BYTES = 256;
const UTC_ISO_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

export async function beginPairingSession(
  pairing: ConsolePairingIdentity,
): Promise<PairingSession> {
  return await callPort("ConsolePairingIdentity", "beginSession", async () => {
    const returned: unknown = await pairing.beginSession();
    if (returned === null || typeof returned !== "object" || Array.isArray(returned)) {
      throw new TypeError("ConsolePairingIdentity.beginSession must return an object");
    }
    const record = returned as Record<string, unknown>;
    const nonce = record.nonce;
    const expiresAt = record.expiresAt;
    if (typeof nonce !== "string" || nonce.length === 0
      || new TextEncoder().encode(nonce).byteLength > MAX_PAIRING_NONCE_BYTES) {
      throw new TypeError("ConsolePairingIdentity.beginSession returned an invalid nonce");
    }
    if (typeof expiresAt !== "string" || !UTC_ISO_MILLISECONDS.test(expiresAt)
      || new Date(expiresAt).toISOString() !== expiresAt) {
      throw new TypeError("ConsolePairingIdentity.beginSession returned an invalid expiry");
    }
    return Object.freeze({ nonce, expiresAt });
  });
}

export async function verifyPairingIdentity(
  pairing: ConsolePairingIdentity,
  input: ConsolePairingVerifyInput,
): Promise<IdentityResult> {
  return await callPort("ConsolePairingIdentity", "verify", async () =>
    snapshotIdentityResult(await pairing.verify(input)));
}
