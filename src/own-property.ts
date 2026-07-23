/** Descriptor fields count only when owned, never via ambient prototype state. */
export function isDataDescriptor(
  descriptor: PropertyDescriptor | undefined,
): descriptor is PropertyDescriptor & { value: unknown } {
  return descriptor !== undefined && Object.hasOwn(descriptor, "value");
}

export function ownDescriptorGetter(
  descriptor: PropertyDescriptor | undefined,
): (() => unknown) | undefined {
  if (descriptor === undefined || !Object.hasOwn(descriptor, "get")) return undefined;
  return typeof descriptor.get === "function" ? descriptor.get : undefined;
}
/** Read an own data property without consulting prototypes or accessors. */
export function ownDataValue(value: unknown, key: PropertyKey): unknown {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return isDataDescriptor(descriptor) ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}
export function ownBooleanTrue(value: unknown, key: PropertyKey): boolean {
  return ownDataValue(value, key) === true;
}
/** Snapshot only a JSON-like object's own enumerable data properties. */
export function snapshotOwnDataRecord(value: unknown): Readonly<Record<string, unknown>> | null {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  } catch {
    return null;
  }
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
    if (typeof key !== "string" || !descriptor.enumerable || !isDataDescriptor(descriptor)) return null;
    snapshot[key] = descriptor.value;
  }
  return Object.freeze(snapshot);
}
/** Snapshot a dense array; inherited, accessor, extra, and symbol keys reject. */
export function snapshotOwnDataArray(value: unknown): readonly unknown[] | null {
  try {
    if (!Array.isArray(value)) return null;
  } catch {
    return null;
  }
  let descriptors: Record<PropertyKey, PropertyDescriptor>;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value) as unknown as Record<PropertyKey, PropertyDescriptor>;
  } catch {
    return null;
  }
  const lengthDescriptor = ownDataValue(descriptors, "length") as PropertyDescriptor | undefined;
  const length = isDataDescriptor(lengthDescriptor) ? lengthDescriptor.value : undefined;
  if (!Number.isSafeInteger(length) || length < 0
    || Reflect.ownKeys(descriptors).length !== length + 1) return null;
  const snapshot: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = ownDataValue(descriptors, String(index)) as PropertyDescriptor | undefined;
    if (!descriptor?.enumerable || !isDataDescriptor(descriptor)) return null;
    snapshot.push(descriptor.value);
  }
  return Object.freeze(snapshot);
}
export function snapshotOwnStringArray(value: unknown): readonly string[] | null {
  const snapshot = snapshotOwnDataArray(value);
  return snapshot !== null && snapshot.every((entry) => typeof entry === "string")
    ? snapshot as readonly string[] : null;
}
/** Bind a protocol data method; exotic iterator prototypes remain supported. */
export function bindDataMethod<T>(target: unknown, key: PropertyKey): T | undefined {
  return bindMethod<T>(target, key, false);
}
/** Bind an own or class-prototype method for injected ports and transports. */
export function bindClassDataMethod<T>(target: unknown, key: PropertyKey): T | undefined {
  try {
    if (Array.isArray(target)) return undefined;
  } catch {
    return undefined;
  }
  return bindMethod<T>(target, key, true);
}
function bindMethod<T>(target: unknown, key: PropertyKey,
  classPrototypeOnly: boolean): T | undefined {
  if ((typeof target !== "object" && typeof target !== "function") || target === null) return undefined;
  const receiver = target as object;
  if (isObjectPrototype(receiver)) return undefined;
  const visited = new Set<object>();
  let current: object | null = receiver;
  try {
    while (current !== null) {
      if (visited.has(current) || visited.size >= 32) return undefined;
      visited.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor !== undefined) {
        if (!isDataDescriptor(descriptor) || typeof descriptor.value !== "function") return undefined;
        const method = descriptor.value as (...args: unknown[]) => unknown;
        return ((...args: unknown[]) => Reflect.apply(method, receiver, args)) as T;
      }
      const next = Object.getPrototypeOf(current) as object | null;
      if (next === null) return undefined;
      if (classPrototypeOnly) {
        if (isPrototypeRoot(next) || !isClassPrototype(next)) return undefined;
      } else if (isObjectPrototype(next)) return undefined;
      current = next;
    }
  } catch {
    return undefined;
  }
  return undefined;
}
function isClassPrototype(value: object): boolean {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, "constructor");
    if (!isDataDescriptor(descriptor) || typeof descriptor.value !== "function") return false;
    const prototypeDescriptor = Object.getOwnPropertyDescriptor(descriptor.value, "prototype");
    return isDataDescriptor(prototypeDescriptor) && prototypeDescriptor.value === value;
  } catch {
    return false;
  }
}
function isPrototypeRoot(value: object): boolean {
  try { return Object.getPrototypeOf(value) === null; }
  catch { return true; }
}
const FUNCTION_TO_STRING = Function.prototype.toString;
const OBJECT_SOURCE = Reflect.apply(FUNCTION_TO_STRING, Object, []);

/** Identify cross-realm Object.prototype without rejecting custom null roots. */
function isObjectPrototype(value: object): boolean {
  if (value === Object.prototype) return true;
  try {
    if (Object.getPrototypeOf(value) !== null) return false;
    const constructor = Object.getOwnPropertyDescriptor(value, "constructor");
    if (!isDataDescriptor(constructor) || typeof constructor.value !== "function") return false;
    const prototype = Object.getOwnPropertyDescriptor(constructor.value, "prototype");
    return isDataDescriptor(prototype) && prototype.value === value
      && prototype.writable === false && prototype.configurable === false
      && Reflect.apply(FUNCTION_TO_STRING, constructor.value, []) === OBJECT_SOURCE;
  } catch {
    return true;
  }
}
/** Read trusted class data below Object.prototype. Do not use for raw JSON. */
const CLASS_DATA_ABSENT = Symbol("class-data-absent");
const CLASS_DATA_INVALID = Symbol("class-data-invalid");

function inspectClassDataValue(
  value: unknown,
  key: PropertyKey,
): unknown | typeof CLASS_DATA_ABSENT | typeof CLASS_DATA_INVALID {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) {
    return CLASS_DATA_INVALID;
  }
  try {
    if (Array.isArray(value)) return CLASS_DATA_INVALID;
  } catch {
    return CLASS_DATA_INVALID;
  }
  const receiver = value as object;
  if (isObjectPrototype(receiver)) return CLASS_DATA_INVALID;
  const visited = new Set<object>();
  let current: object | null = receiver;
  try {
    while (current !== null) {
      if (visited.has(current) || visited.size >= 32) return CLASS_DATA_INVALID;
      visited.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor !== undefined) {
        if (isDataDescriptor(descriptor)) return descriptor.value;
        const getter = ownDescriptorGetter(descriptor);
        if (current === receiver || getter === undefined) return CLASS_DATA_INVALID;
        return Reflect.apply(getter, receiver, []);
      }
      const next = Object.getPrototypeOf(current) as object | null;
      if (next === null) return CLASS_DATA_ABSENT;
      if (isPrototypeRoot(next)) {
        return Object.getOwnPropertyDescriptor(next, key) === undefined
          ? CLASS_DATA_ABSENT : CLASS_DATA_INVALID;
      }
      if (!isClassPrototype(next)) {
        return CLASS_DATA_INVALID;
      }
      current = next;
    }
  } catch {
    return CLASS_DATA_INVALID;
  }
  return CLASS_DATA_ABSENT;
}
export function classDataValue(value: unknown, key: PropertyKey): unknown {
  const inspected = inspectClassDataValue(value, key);
  return inspected === CLASS_DATA_ABSENT || inspected === CLASS_DATA_INVALID
    ? undefined : inspected;
}
export interface ClassDataRecordSnapshot {
  readonly values: Readonly<Record<string, unknown>>;
  readonly invalidField: string | undefined;
}
/** Read each declared member once and preserve its first unreadable field. */
export function inspectClassDataRecord(
  value: unknown,
  fields: readonly string[],
): ClassDataRecordSnapshot | null {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  } catch {
    return null;
  }
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const field of fields) {
    const inspected = inspectClassDataValue(value, field);
    if (inspected === CLASS_DATA_INVALID) {
      return Object.freeze({ values: Object.freeze(snapshot), invalidField: field });
    }
    snapshot[field] = inspected === CLASS_DATA_ABSENT ? undefined : inspected;
  }
  return Object.freeze({ values: Object.freeze(snapshot), invalidField: undefined });
}
/** Snapshot trusted own/class members while refusing plain inherited fields. */
export function snapshotClassDataRecord(
  value: unknown,
  fields: readonly string[],
): Readonly<Record<string, unknown>> | null {
  const inspected = inspectClassDataRecord(value, fields);
  return inspected === null || inspected.invalidField !== undefined
    ? null : inspected.values;
}
