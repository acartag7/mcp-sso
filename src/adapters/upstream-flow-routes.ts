import type { Bridge } from "./bridge.ts";
import { AuthConfigError, pathAfterOrigin } from "../config.ts";
import type { UpstreamRedirectFlow } from "./upstream-flow.ts";
import { isProxy } from "node:util/types";
import { effectiveRouteKey } from "./upstream-flow-internals.ts";

interface FlowMetadata {
  bridge: Bridge;
  complete: "bridge" | "identity";
  initiation: "/oauth/authorize" | "/login";
  callback: string;
  resource: string;
}

const metadata = new WeakMap<object, FlowMetadata>();
const ADAPTER_ROUTES = [
  "/oauth/authorize", "/login", "/oauth/authorize/approve", "/oauth/token",
  "/oauth/register", "/oauth/revoke", "/oauth/jwks",
];

export function assertFlowFactoryRoutes(bridge: Bridge, complete: "bridge" | "identity", callback: string): void {
  const resource = pathAfterOrigin(bridge.config.resource);
  const initiation = complete === "bridge" ? "/oauth/authorize" : "/login";
  if (reserved(callback, resource)) throw new AuthConfigError(`callbackPath must not alias a reserved route: ${callback}`);
  if (effectiveRouteKey(initiation) === effectiveRouteKey(resource) || wellKnown(initiation)) {
    throw new AuthConfigError(`flow initiation must not alias the resource path: ${initiation}`);
  }
}

export function registerUpstreamFlowMetadata(
  flow: UpstreamRedirectFlow, bridge: Bridge, complete: "bridge" | "identity", callback: string,
): void {
  metadata.set(flow, {
    bridge, complete, callback,
    initiation: complete === "bridge" ? "/oauth/authorize" : "/login",
    resource: pathAfterOrigin(bridge.config.resource),
  });
}

export function assertDistinctUpstreamFlowRoutes(bridge: Bridge, flows: readonly UpstreamRedirectFlow[]): void {
  if (!Array.isArray(flows) || isProxy(flows) || flows.length < 1 || flows.length > 2) throw invalidSet();
  let descriptors: PropertyDescriptorMap;
  try { descriptors = Object.getOwnPropertyDescriptors(flows) as unknown as PropertyDescriptorMap; }
  catch { throw invalidSet(); }
  if (Reflect.ownKeys(descriptors).length !== flows.length + 1) throw invalidSet();
  const entries: FlowMetadata[] = [];
  const instances = new Set<object>();
  for (let index = 0; index < flows.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) throw invalidSet();
    const flow = descriptor.value as object;
    const entry = metadata.get(flow);
    if (!entry || entry.bridge !== bridge || instances.has(flow)) throw invalidSet();
    instances.add(flow); entries.push(entry);
  }
  const occupied = new Set<string>();
  const resource = effectiveRouteKey(pathAfterOrigin(bridge.config.resource));
  for (const entry of entries) {
    if (effectiveRouteKey(entry.resource) !== resource) throw invalidSet();
    for (const route of [entry.initiation, entry.callback]) {
      const key = effectiveRouteKey(route);
      if (occupied.has(key) || key === resource || wellKnown(route)) throw invalidSet();
      occupied.add(key);
    }
  }
}

export function assertUpstreamFlowCompletion(flow: UpstreamRedirectFlow, expected: "bridge" | "identity"): void {
  if (metadata.get(flow as object)?.complete !== expected) throw invalidSet();
}

function reserved(path: string, resource: string): boolean {
  const key = effectiveRouteKey(path);
  return key === effectiveRouteKey(resource) || ADAPTER_ROUTES.some((route) => effectiveRouteKey(route) === key) || wellKnown(path);
}

function wellKnown(path: string): boolean {
  const key = effectiveRouteKey(path);
  return key === "/.well-known" || key.startsWith("/.well-known/");
}

function invalidSet(): AuthConfigError {
  return new AuthConfigError("upstream flow route set is invalid or ambiguous");
}
