import type { IdentityClaims } from "../ports/identity.ts";
import type { NormResponse } from "./http.ts";
import { snapshotCompletionResponse } from "./response-boundary.ts";

export async function completeIdentity(
  onIdentity: (identity: IdentityClaims) => NormResponse | Promise<NormResponse>,
  identity: IdentityClaims,
  timeoutMs: number,
): Promise<NormResponse> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error("completion timeout")), timeoutMs);
  });
  try {
    const pending = Promise.resolve().then(() => onIdentity(identity));
    pending.catch(() => undefined);
    return snapshotCompletionResponse(await Promise.race([pending, timeout]));
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
