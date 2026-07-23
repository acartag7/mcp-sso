/** Read an explicitly supplied data property without consulting the prototype
 * chain or invoking an accessor. Security opt-ins use this helper so omission
 * always preserves the closed/default behavior. */
export function ownDataValue(value: unknown, key: PropertyKey): unknown {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && "value" in descriptor ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

export function ownBooleanTrue(value: unknown, key: PropertyKey): boolean {
  return ownDataValue(value, key) === true;
}

/** Snapshot a JSON-like object's own enumerable data properties. Inherited
 * values and accessors are never interpreted as input fields. */
export function snapshotOwnDataRecord(value: unknown): Readonly<Record<string, unknown>> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  let descriptors: Record<PropertyKey, PropertyDescriptor>;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value) as unknown as Record<PropertyKey, PropertyDescriptor>;
  } catch {
    return null;
  }
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(descriptors)) {
    const descriptor = ownDataValue(descriptors, key) as PropertyDescriptor | undefined;
    if (descriptor === undefined) return null;
    if (typeof key !== "string" || !descriptor.enumerable || !("value" in descriptor)) return null;
    snapshot[key] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

/** Snapshot a dense JSON-like array without reading inherited indices or
 * accessors. Extra/symbol properties reject because parsed arrays have neither. */
export function snapshotOwnDataArray(value: unknown): readonly unknown[] | null {
  if (!Array.isArray(value)) return null;
  let descriptors: Record<PropertyKey, PropertyDescriptor>;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value) as unknown as Record<PropertyKey, PropertyDescriptor>;
  } catch {
    return null;
  }
  const lengthDescriptor = ownDataValue(descriptors, "length") as PropertyDescriptor | undefined;
  const length = lengthDescriptor && "value" in lengthDescriptor ? lengthDescriptor.value : undefined;
  if (!Number.isSafeInteger(length) || length < 0
    || Reflect.ownKeys(descriptors).length !== length + 1) return null;
  const snapshot: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = ownDataValue(descriptors, String(index)) as PropertyDescriptor | undefined;
    if (!descriptor?.enumerable || !("value" in descriptor)) return null;
    snapshot.push(descriptor.value);
  }
  return Object.freeze(snapshot);
}

export function snapshotOwnStringArray(value: unknown): readonly string[] | null {
  const snapshot = snapshotOwnDataArray(value);
  return snapshot !== null && snapshot.every((entry) => typeof entry === "string")
    ? snapshot as readonly string[] : null;
}

/** Bind an own or class-prototype data method without consulting Object.prototype
 * or invoking accessors. This accepts normal class methods while excluding
 * inherited global state and accessor side effects. */
export function bindDataMethod<T>(target: unknown, key: PropertyKey): T | undefined {
  if ((typeof target !== "object" && typeof target !== "function") || target === null) return undefined;
  const receiver = target as object;
  const visited = new Set<object>();
  let current: object | null = receiver;
  try {
    while (current !== null && current !== Object.prototype) {
      if (visited.has(current)) return undefined;
      visited.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor !== undefined) {
        if (!("value" in descriptor) || typeof descriptor.value !== "function") return undefined;
        const method = descriptor.value as (...args: unknown[]) => unknown;
        return ((...args: unknown[]) => Reflect.apply(method, receiver, args)) as T;
      }
      current = Object.getPrototypeOf(current) as object | null;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function isClassPrototype(value: object): boolean {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, "constructor");
    return descriptor !== undefined && "value" in descriptor
      && typeof descriptor.value === "function" && descriptor.value.prototype === value;
  } catch {
    return false;
  }
}

/** Read a data member from a trusted port/class result. Own accessors are
 * rejected; prototype accessors are accepted only below Object.prototype so
 * standard class DTOs and Fetch Response objects remain compatible without
 * consulting globally polluted properties. Do not use this for raw JSON. */
export function classDataValue(value: unknown, key: PropertyKey): unknown {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return undefined;
  const receiver = value as object;
  const visited = new Set<object>();
  let current: object | null = receiver;
  try {
    while (current !== null && current !== Object.prototype) {
      if (visited.has(current)) return undefined;
      visited.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor !== undefined) {
        if ("value" in descriptor) return descriptor.value;
        if (current === receiver || typeof descriptor.get !== "function") return undefined;
        return Reflect.apply(descriptor.get, receiver, []);
      }
      const next = Object.getPrototypeOf(current) as object | null;
      if (next !== null && next !== Object.prototype && !isClassPrototype(next)) return undefined;
      current = next;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/** Snapshot declared members from a trusted port/class result. This keeps the
 * public structural interfaces compatible with class DTOs while refusing plain
 * inherited fields and never consulting Object.prototype. */
export function snapshotClassDataRecord(
  value: unknown,
  fields: readonly string[],
): Readonly<Record<string, unknown>> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const field of fields) snapshot[field] = classDataValue(value, field);
  return Object.freeze(snapshot);
}
