import type { StorePort } from "./ports/store.ts";
import { assertStoreInstanceId } from "./ports/store.ts";

export function assertStoreInstanceCapability(store: StorePort): asserts store is StorePort & {
  getStoreInstanceId(): Promise<string>;
} {
  if (typeof store.getStoreInstanceId !== "function") {
    throw new Error("StorePort.getStoreInstanceId is required for consent replay isolation");
  }
}

export async function storeInstanceId(store: StorePort): Promise<string> {
  assertStoreInstanceCapability(store);
  const value = await store.getStoreInstanceId();
  assertStoreInstanceId(value);
  return value;
}
