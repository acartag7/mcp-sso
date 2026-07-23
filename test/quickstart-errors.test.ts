import assert from "node:assert/strict";
import { test } from "node:test";
import { errorMessage, isErrorWithCode } from "../src/quickstart-errors.ts";

test("filesystem error helpers ignore inherited fields and hostile accessors", () => {
  const codeDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "code");
  const messageDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "message");
  Object.defineProperties(Object.prototype, {
    code: { configurable: true, writable: true, value: "ENOENT" },
    message: { configurable: true, get() { throw new Error("must not run"); } },
  });
  try {
    assert.equal(isErrorWithCode({}, ["ENOENT"]), false);
    assert.equal(errorMessage({}), "unknown error");
    const own = Object.assign(new Error("disk unavailable"), { code: "ENOENT" });
    assert.equal(isErrorWithCode(own, ["ENOENT"]), true);
    assert.equal(errorMessage(own), "disk unavailable");
  } finally {
    if (codeDescriptor === undefined) delete (Object.prototype as Record<string, unknown>).code;
    else Object.defineProperty(Object.prototype, "code", codeDescriptor);
    if (messageDescriptor === undefined) delete (Object.prototype as Record<string, unknown>).message;
    else Object.defineProperty(Object.prototype, "message", messageDescriptor);
  }
});
