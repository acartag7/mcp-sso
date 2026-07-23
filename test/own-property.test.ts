import assert from "node:assert/strict";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import {
  bindClassDataMethod, bindDataMethod, classDataValue, inspectClassDataRecord,
  isDataDescriptor, ownDataValue, ownDescriptorGetter, snapshotClassDataRecord,
  snapshotOwnDataArray, snapshotOwnDataRecord,
} from "../src/own-property.ts";

test("array snapshots reject sparse arrays even when inherited descriptor data balances the shape", () => {
  const inherited = Object.getOwnPropertyDescriptor(Object.prototype, "0");
  Object.defineProperty(Object.prototype, "0", {
    configurable: true, value: { enumerable: true, value: "inherited" },
  });
  try {
    const sparse: unknown[] = [];
    sparse.length = 1;
    Object.defineProperty(sparse, "extra", { enumerable: true, value: "balancing-own-key" });
    assert.equal(snapshotOwnDataArray(sparse), null);
  } finally {
    if (inherited === undefined) delete (Object.prototype as Record<string, unknown>)["0"];
    else Object.defineProperty(Object.prototype, "0", inherited);
  }
});

test("record and array snapshots reject symbol and extra-key shapes", () => {
  const symbol = Symbol("extra");
  assert.equal(snapshotOwnDataRecord({ field: "value", [symbol]: true }), null);
  const array = ["value"] as unknown[] & Record<PropertyKey, unknown>;
  array.extra = true;
  assert.equal(snapshotOwnDataArray(array), null);
});

test("descriptor helpers require own value and getter fields", () => {
  const valueDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "value");
  const getDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "get");
  const invalidFieldDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "invalidField");
  const prototypeDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "prototype");
  let inheritedGetterCalls = 0;
  let invalidFieldReads = 0;
  let ownAccessorCalls = 0;
  const accessor = {};
  Object.defineProperty(accessor, "field", {
    enumerable: true,
    get() { ownAccessorCalls += 1; return "accessor-value"; },
  });
  class DataTransfer {
    readonly data = "own-data";
    get computed(): string { return "class-getter"; }
  }
  const transfer = new DataTransfer();
  const fakePrototype = Object.create(null) as Record<string, unknown>;
  Object.defineProperties(fakePrototype, {
    constructor: { configurable: true, value: () => undefined },
    forged: { configurable: true, value: "forged" },
  });
  const plainMethodPrototype = Object.create(null) as Record<string, unknown>;
  plainMethodPrototype.run = () => "inherited-method";
  Object.defineProperties(Object.prototype, {
    value: { configurable: true, value: "ambient-value" },
    get: {
      configurable: true,
      value() { inheritedGetterCalls += 1; return "ambient-getter"; },
    },
    invalidField: {
      configurable: true,
      get() { invalidFieldReads += 1; return "allowedScopes"; },
    },
    prototype: { configurable: true, value: fakePrototype },
  });
  try {
    const inheritedDescriptor = Object.create(Object.prototype) as PropertyDescriptor;
    assert.equal(isDataDescriptor(inheritedDescriptor), false);
    assert.equal(ownDescriptorGetter(inheritedDescriptor), undefined);

    assert.equal(ownDataValue(accessor, "field"), undefined);
    assert.equal(snapshotOwnDataRecord(accessor), null);
    assert.equal(classDataValue(accessor, "field"), undefined);
    assert.equal(ownAccessorCalls, 0);

    assert.equal(classDataValue(transfer, "data"), "own-data");
    assert.equal(classDataValue(transfer, "computed"), "class-getter");
    const inspected = inspectClassDataRecord(transfer, ["data"]);
    assert.ok(inspected);
    assert.equal(Object.hasOwn(inspected, "invalidField"), true);
    assert.equal(inspected.invalidField, undefined);
    assert.deepEqual({ ...snapshotClassDataRecord(transfer, ["data"]) }, { data: "own-data" });
    assert.equal(invalidFieldReads, 0);

    assert.equal(classDataValue(Object.create(fakePrototype), "forged"), undefined);
    assert.equal(bindClassDataMethod(Object.create(plainMethodPrototype), "run"), undefined);
    assert.equal(inheritedGetterCalls, 0);
  } finally {
    if (valueDescriptor === undefined) delete (Object.prototype as Record<string, unknown>).value;
    else Object.defineProperty(Object.prototype, "value", valueDescriptor);
    if (getDescriptor === undefined) delete (Object.prototype as Record<string, unknown>).get;
    else Object.defineProperty(Object.prototype, "get", getDescriptor);
    if (invalidFieldDescriptor === undefined) {
      delete (Object.prototype as Record<string, unknown>).invalidField;
    } else {
      Object.defineProperty(Object.prototype, "invalidField", invalidFieldDescriptor);
    }
    if (prototypeDescriptor === undefined) {
      delete (Object.prototype as Record<string, unknown>).prototype;
    } else {
      Object.defineProperty(Object.prototype, "prototype", prototypeDescriptor);
    }
  }
});

test("class and protocol walks stop at foreign realm roots", () => {
  const foreignRoot = runInNewContext("Object.prototype") as object;
  const foreign = runInNewContext(`
    Object.prototype.flag = "ambient-value";
    Object.prototype.run = function () { return "ambient-method"; };
    ({})
  `) as object;
  for (const root of [Object.prototype, foreignRoot]) {
    assert.equal(classDataValue(root, "toString"), undefined);
    assert.equal(bindDataMethod<() => string>(root, "toString"), undefined);
    assert.equal(bindClassDataMethod<() => string>(root, "toString"), undefined);
  }
  assert.equal(classDataValue(foreign, "flag"), undefined);
  assert.equal(bindDataMethod<() => string>(foreign, "run"), undefined);
  assert.equal(bindClassDataMethod<() => string>(foreign, "run"), undefined);
});

test("strict captures reject arrays but accept own null-prototype members", () => {
  let ambientCalls = 0;
  const previous = Object.getOwnPropertyDescriptor(Array.prototype, "run");
  Object.defineProperty(Array.prototype, "run", {
    configurable: true,
    value() { ambientCalls += 1; return "ambient"; },
  });
  try {
    assert.equal(bindClassDataMethod<() => string>([], "run"), undefined);
    assert.equal(classDataValue([], "run"), undefined);
    assert.equal(ambientCalls, 0);
  } finally {
    if (previous === undefined) delete (Array.prototype as unknown as Record<string, unknown>).run;
    else Object.defineProperty(Array.prototype, "run", previous);
  }

  const ownRoot = Object.assign(Object.create(null), {
    data: "own-data",
    run() { return "own-method"; },
  }) as object;
  assert.equal(classDataValue(ownRoot, "data"), "own-data");
  assert.equal(bindClassDataMethod<() => string>(ownRoot, "run")?.(), "own-method");

  const protocolRoot = Object.assign(Object.create(null), {
    run() { return "protocol-method"; },
  }) as object;
  assert.equal(
    bindDataMethod<() => string>(Object.create(protocolRoot), "run")?.(),
    "protocol-method",
  );
});

test("prototype walks and revoked proxies fail closed within a fixed bound", () => {
  let prototypeReads = 0;
  const handler: ProxyHandler<object> = {
    getPrototypeOf() {
      prototypeReads += 1;
      if (prototypeReads > 100) throw new Error("probe limit");
      return new Proxy({}, handler);
    },
  };
  assert.equal(bindDataMethod(new Proxy({}, handler), "missing"), undefined);
  assert.ok(prototypeReads <= 65);

  const revokedObject = Proxy.revocable({}, {});
  const revokedArray = Proxy.revocable([], {});
  revokedObject.revoke();
  revokedArray.revoke();
  assert.equal(snapshotOwnDataRecord(revokedObject.proxy), null);
  assert.equal(inspectClassDataRecord(revokedObject.proxy, ["field"]), null);
  assert.equal(snapshotOwnDataArray(revokedArray.proxy), null);
});
