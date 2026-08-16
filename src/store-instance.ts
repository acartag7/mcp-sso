import type { StorePort } from "./ports/store.ts";
import { assertStoreInstanceId } from "./ports/store.ts";
import { callPort } from "./port-failure.ts";

export function assertStoreInstanceCapability(store: StorePort): asserts store is StorePort & {
  getStoreInstanceId(): Promise<string>;
  rotateStoreInstanceId(): Promise<string>;
} {
  if (typeof store.getStoreInstanceId !== "function") {
    throw new Error("StorePort.getStoreInstanceId is required for consent replay isolation");
  }
  if (typeof store.rotateStoreInstanceId !== "function") {
    throw new Error("StorePort.rotateStoreInstanceId is required for clone and restore isolation");
  }
  if (typeof store.commitConsentApproval !== "function") {
    throw new Error("StorePort.commitConsentApproval is required for atomic consent approval");
  }
}

export async function storeInstanceId(store: StorePort): Promise<string> {
  // The capability probe READS three properties. An accessor- or Proxy-backed
  // store can throw from the read itself, which happens before the method call —
  // so the probe belongs inside the same provenance boundary, not in front of it.
  const value = await callPort("StorePort", "getStoreInstanceId", async () => {
    assertStoreInstanceCapability(store);
    return await store.getStoreInstanceId();
  });
  assertStoreInstanceId(value);
  return value;
}
