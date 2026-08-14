// Bounded, immutable scope-implication policy (contracts §5, §11).
// The graph is validated once at boot and branded out-of-band; a cast object
// passed directly to requireScope cannot silently widen authorization.

export interface ScopeImplication {
  granted: string;
  implies: readonly string[];
}

export interface ScopeHierarchyPolicy {
  resource: string;
  implications: readonly ScopeImplication[];
}

export const MAX_SCOPE_HIERARCHY_ROWS = 128;
export const MAX_SCOPE_HIERARCHY_EDGES = 4096;

type MakeError = (message: string) => Error;
type Graph = ReadonlyMap<string, ReadonlySet<string>>;

const VALIDATED_GRAPHS = new WeakMap<ScopeHierarchyPolicy, Graph>();

export function snapshotScopeHierarchy(
  value: unknown,
  resource: string,
  catalog: readonly string[],
  makeError: MakeError,
): ScopeHierarchyPolicy | undefined {
  if (value === undefined) return undefined;
  const source = exactRecord(value, "scopeHierarchy", ["resource", "implications"], makeError);
  const boundResource = read(source, "resource", "scopeHierarchy.resource", makeError);
  if (typeof boundResource !== "string" || boundResource !== resource) {
    throw makeError("scopeHierarchy.resource must equal BridgeConfig.resource byte-for-byte");
  }
  const rawRows = read(source, "implications", "scopeHierarchy.implications", makeError);
  const rows = snapshotArray(rawRows, "scopeHierarchy.implications", MAX_SCOPE_HIERARCHY_ROWS, makeError);
  const catalogSet = new Set(catalog);
  const graph = new Map<string, Set<string>>();
  const publishedRows: ScopeImplication[] = [];
  let edgeCount = 0;

  for (let index = 0; index < rows.length; index += 1) {
    const label = `scopeHierarchy.implications[${index}]`;
    const row = exactRecord(rows[index], label, ["granted", "implies"], makeError);
    const granted = read(row, "granted", `${label}.granted`, makeError);
    if (typeof granted !== "string" || !catalogSet.has(granted)) {
      throw makeError(`${label}.granted must be a member of scopeCatalog`);
    }
    if (graph.has(granted)) throw makeError(`scopeHierarchy has duplicate granted scope "${granted}"`);
    const rawTargets = read(row, "implies", `${label}.implies`, makeError);
    const targets = snapshotArray(rawTargets, `${label}.implies`, MAX_SCOPE_HIERARCHY_ROWS, makeError);
    if (targets.length === 0) throw makeError(`${label}.implies must not be empty`);
    const edges = new Set<string>();
    const publishedTargets: string[] = [];
    for (let targetIndex = 0; targetIndex < targets.length; targetIndex += 1) {
      const target = targets[targetIndex];
      if (typeof target !== "string" || !catalogSet.has(target)) {
        throw makeError(`${label}.implies[${targetIndex}] must be a member of scopeCatalog`);
      }
      if (target === granted) throw makeError(`scopeHierarchy scope "${granted}" cannot imply itself`);
      if (edges.has(target)) throw makeError(`${label}.implies has duplicate scope "${target}"`);
      edgeCount += 1;
      if (edgeCount > MAX_SCOPE_HIERARCHY_EDGES) {
        throw makeError(`scopeHierarchy must contain at most ${MAX_SCOPE_HIERARCHY_EDGES} direct edges`);
      }
      edges.add(target);
      publishedTargets.push(target);
    }
    graph.set(granted, edges);
    publishedRows.push(Object.freeze({ granted, implies: Object.freeze(publishedTargets) }));
  }

  assertAcyclic(graph, makeError);
  const policy = Object.freeze({
    resource: boundResource,
    implications: Object.freeze(publishedRows),
  });
  VALIDATED_GRAPHS.set(policy, graph);
  return policy;
}

export function hierarchyImplies(
  policy: ScopeHierarchyPolicy | undefined,
  grantedScopes: readonly string[],
  required: string,
): boolean {
  if (!policy) return false;
  const graph = VALIDATED_GRAPHS.get(policy);
  if (!graph) return false;
  const visited = new Set<string>();
  const pending = [...grantedScopes];
  while (pending.length > 0) {
    const current = pending.pop();
    if (typeof current !== "string" || visited.has(current)) continue;
    if (current === required) return true;
    visited.add(current);
    for (const implied of graph.get(current) ?? []) pending.push(implied);
  }
  return false;
}

function assertAcyclic(graph: Map<string, Set<string>>, makeError: MakeError): void {
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (scope: string): void => {
    if (visiting.has(scope)) throw makeError(`scopeHierarchy contains a cycle at "${scope}"`);
    if (visited.has(scope)) return;
    visiting.add(scope);
    for (const implied of graph.get(scope) ?? []) visit(implied);
    visiting.delete(scope);
    visited.add(scope);
  };
  for (const scope of graph.keys()) visit(scope);
}

function exactRecord(
  value: unknown,
  label: string,
  keys: readonly string[],
  makeError: MakeError,
): Record<PropertyKey, unknown> {
  if (typeof value !== "object" || value === null || safeIsArray(value, label, makeError)) {
    throw makeError(`${label} must be an object`);
  }
  let ownKeys: Array<string | symbol>;
  try { ownKeys = Reflect.ownKeys(value); }
  catch { throw makeError(`${label} keys could not be read`); }
  if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== "string" || !keys.includes(key))) {
    throw makeError(`${label} must contain exactly ${keys.join(" and ")}`);
  }
  return value as Record<PropertyKey, unknown>;
}

function snapshotArray(
  value: unknown,
  label: string,
  max: number,
  makeError: MakeError,
): readonly unknown[] {
  if (!safeIsArray(value, label, makeError)) throw makeError(`${label} must be an array`);
  const length = read(value, "length", `${label}.length`, makeError);
  if (!Number.isSafeInteger(length) || (length as number) < 0 || (length as number) > max) {
    throw makeError(`${label} must contain at most ${max} entries`);
  }
  const copy: unknown[] = [];
  for (let index = 0; index < (length as number); index += 1) {
    copy.push(read(value, index, `${label}[${index}]`, makeError));
  }
  return copy;
}

function safeIsArray(value: unknown, label: string, makeError: MakeError): value is unknown[] {
  try { return Array.isArray(value); }
  catch { throw makeError(`${label} could not be classified`); }
}

function read(source: object, key: PropertyKey, label: string, makeError: MakeError): unknown {
  try { return (source as Record<PropertyKey, unknown>)[key]; }
  catch { throw makeError(`${label} could not be read`); }
}
