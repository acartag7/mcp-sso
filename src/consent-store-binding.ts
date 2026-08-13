import type { BridgeConfig } from "./config.ts";
import type { StorePort } from "./ports/store.ts";
import { assertStoreInstanceCapability, storeInstanceId } from "./store-instance.ts";

const bindings = new WeakMap<BridgeConfig, StorePort>();

export function bindConsentStore(config: BridgeConfig, store: StorePort): void {
  assertStoreInstanceCapability(store);
  bindings.set(config, store);
}

export function consentStoreInstanceId(config: BridgeConfig): Promise<string> | undefined {
  const store = bindings.get(config);
  return store ? storeInstanceId(store) : undefined;
}
