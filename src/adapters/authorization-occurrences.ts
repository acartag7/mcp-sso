// The §8.4 raw-occurrence boundary for a consumer's own /mcp composition
// root (contracts §15, the consumer-facing DX helpers). Extracted from
// http.ts so the boundary and its fail-closed input class live in one unit.
import { isProxy } from "node:util/types";
import type { NormRequest } from "./http.ts";

/** §8.4 raw-occurrence boundary: one occurrence as a one-element array, many
 *  as a longer array, absence as undefined, never a collapsed scalar. The
 *  complete fail-closed input class (case-insensitive own-key scan, required
 *  container and element types, single-read snapshots, Proxy rejection,
 *  length-blind enumeration) is enumerated in §15 and pinned in
 *  test/adapters-http.test.ts; both sources get identical treatment. */
export function authorizationOccurrences(
  distinct: Record<string, string[] | undefined> | undefined,
  normalized?: NormRequest["headers"],
): string[] | undefined {
  const source = distinct !== undefined ? distinct : normalized;
  if (source === undefined) return undefined;
  const occurrences: string[] = [];
  const label = distinct !== undefined ? "distinct" : "normalized";
  for (const [key, descriptor] of plainDataProperties(source, `${label} Authorization source`)) {
    // Source-map keys follow enumerability semantics like Object.entries: a
    // non-enumerable source key is not part of the header map.
    if (!descriptor.enumerable) continue;
    const value = descriptor.value;
    if (key.toLowerCase() !== "authorization" || value === undefined) continue;
    if (typeof value === "string" && label === "normalized") occurrences.push(value);
    else if (Array.isArray(value)) {
      // Snapshot first; the snapshot's own length is the emptiness decision,
      // never a proxy-controlled length read before publication.
      const snapshot = validatedOccurrences(value, label);
      if (snapshot.length > 0) occurrences.push(...snapshot);
    } else throw new TypeError(`${label} Authorization occurrence is not a string`);
  }
  return occurrences.length > 0 ? occurrences : undefined;
}

/** Read each element exactly once, validate and publish that snapshot: an
 *  accessor-backed array cannot show one value at validation, another at publication. */
/** The boundary accepts static plain data only. A Proxy is rejected because
 *  its key, length, and element traps are attacker-controlled, so no
 *  enumeration of it is evidence; an accessor property is rejected because its
 *  getter runs attacker code during enumeration and can delete a sibling
 *  occurrence before it is read. Descriptors snapshot every data property's
 *  value once, so keys and values cannot change between inspection and
 *  publication. */
function plainDataProperties(object: object, label: string): Array<[string, PropertyDescriptor]> {
  if (isProxy(object)) throw new TypeError(`${label} is not a plain object`);
  const descriptors = Object.getOwnPropertyDescriptors(object);
  const properties: Array<[string, PropertyDescriptor]> = [];
  for (const key of Object.keys(descriptors)) {
    const descriptor = descriptors[key];
    if (descriptor === undefined) continue;
    if (descriptor.get !== undefined || descriptor.set !== undefined) {
      throw new TypeError(`${label} has an accessor property`);
    }
    properties.push([key, descriptor]);
  }
  return properties;
}

function validatedOccurrences(values: readonly unknown[], source: string): string[] {
  const snapshot: unknown[] = [];
  for (const [key, descriptor] of plainDataProperties(values, `${source} Authorization occurrences`)) {
    // Every own numeric index is an occurrence regardless of enumerability: a
    // non-enumerable element must not silently vanish from the list.
    if (!/^(?:0|[1-9][0-9]*)$/u.test(key)) continue;
    snapshot.push(descriptor.value);
  }
  if (!snapshot.every((entry) => typeof entry === "string")) {
    throw new TypeError(`${source} Authorization occurrence is not a string`);
  }
  return snapshot as string[];
}
