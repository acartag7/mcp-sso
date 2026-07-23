import assert from "node:assert/strict";
import { test } from "node:test";
import { readCimdBody } from "../src/cimd/body-reader.ts";

test("CIMD body reader does not close an async iterator after natural completion", async () => {
  let returns = 0;
  const body = {
    [Symbol.asyncIterator]() {
      let sent = false;
      return {
        async next() {
          if (sent) return { done: true, value: undefined };
          sent = true;
          return { done: false, value: new TextEncoder().encode("{}") };
        },
        async return() { returns += 1; throw new Error("early-close only"); },
      };
    },
  };
  assert.equal(await readCimdBody(body, 10), "{}");
  assert.equal(returns, 0);
});

test("CIMD body cleanup cannot replace a size-limit rejection", async () => {
  const body = {
    [Symbol.asyncIterator]() {
      return {
        async next() { return { done: false, value: new Uint8Array(2) }; },
        async return() { throw new Error("cleanup failure"); },
      };
    },
  };
  await assert.rejects(
    readCimdBody(body, 1),
    (error: unknown) => error instanceof Error
      && (error as Error & { reason?: string }).reason === "size_exceeded",
  );
});
