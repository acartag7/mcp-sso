import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import type { CimdTransport } from "../src/cimd/transport.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { ScriptedCimdTransport } from "./parity/scripted-cimd-transport.ts";
import type { HttpExchange, ObservedOutbound } from "./parity/types.ts";

const request: Parameters<CimdTransport["connectAndGet"]>[0] = {
  connectIp: "not-an-ip",
  family: 4,
  port: -1,
  servername: "unused.invalid",
  hostHeader: "issuer.example:8443",
  requestTarget: "/.well-known/oauth-authorization-server?resource=%2Fmcp",
  signal: AbortSignal.abort(),
  redirect: "manual",
};

test("observes the exact CIMD GET and returns transport metadata without network I/O", async () => {
  let observed: ObservedOutbound | undefined;
  let ambientFetchCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    ambientFetchCalls += 1;
    throw new Error("ambient fetch must not run");
  };
  try {
    const transport = new ScriptedCimdTransport((call) => {
      observed = call;
      return response(207, { "content-type": "application/json" }, { value: { ok: true } });
    });
    const result = await transport.connectAndGet(request);

    assert.deepStrictEqual(observed, {
      method: "GET",
      url: "https://issuer.example:8443/.well-known/oauth-authorization-server?resource=%2Fmcp",
      headers: {
        host: "issuer.example:8443",
        accept: "application/json",
        "accept-encoding": "identity",
      },
    });
    assert.equal(Object.hasOwn(observed!, "body"), false);
    assert.equal(result.status, 207);
    assert.equal(result.redirected, false);
    assert.equal(result.finalUrl, "https://issuer.example:8443/.well-known/oauth-authorization-server?resource=%2Fmcp");
    assert.equal(ambientFetchCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("preserves repeated response headers in fresh arrays", async () => {
  const scriptedHeaders = { "set-cookie": ["first=1", "second=2"], "x-one": "value" };
  const transport = new ScriptedCimdTransport(() => response(200, scriptedHeaders, { absent: true }));

  const first = await transport.connectAndGet(request);
  const second = await transport.connectAndGet(request);
  assert.deepStrictEqual(Object.entries(first.headersDistinct), [
    ["set-cookie", ["first=1", "second=2"]],
    ["x-one", ["value"]],
  ]);
  assert.equal(Object.getPrototypeOf(first.headersDistinct), null);
  assert.notStrictEqual(first.headersDistinct["set-cookie"], scriptedHeaders["set-cookie"]);
  assert.notStrictEqual(first.headersDistinct["set-cookie"], second.headersDistinct["set-cookie"]);
  (first.headersDistinct["set-cookie"] as string[])[0] = "changed=1";
  assert.deepStrictEqual(scriptedHeaders["set-cookie"], ["first=1", "second=2"]);
  assert.deepStrictEqual(second.headersDistinct["set-cookie"], ["first=1", "second=2"]);
});

test("preserves __proto__ as an own repeated header without a prototype", async () => {
  const scriptedHeaders = JSON.parse('{"__proto__":["first","second"]}') as HttpExchange["response"]["headers"];
  const transport = new ScriptedCimdTransport(() => response(200, scriptedHeaders, { absent: true }));

  const result = await transport.connectAndGet(request);
  assert.equal(Object.getPrototypeOf(result.headersDistinct), null);
  assert.equal(Object.hasOwn(result.headersDistinct, "__proto__"), true);
  assert.deepStrictEqual(result.headersDistinct.__proto__, ["first", "second"]);
  assert.notStrictEqual(result.headersDistinct.__proto__, scriptedHeaders.__proto__);
});

test("rejects capture and non-string response headers without echoing their values", async (t) => {
  const hostileCapture = "do-not-echo-capture";
  const hostileNumber = 7331;
  const cases: Array<{ name: string; headers: unknown }> = [
    { name: "capture", headers: { "x-test": { $capture: { fixture: hostileCapture, name: "token", format: "raw" } } } },
    { name: "non-string", headers: { "x-test": hostileNumber } },
  ];
  for (const fixture of cases) {
    await t.test(fixture.name, async () => {
      const transport = new ScriptedCimdTransport(() => response(200, fixture.headers as never, { absent: true }));
      await assert.rejects(transport.connectAndGet(request), (error: unknown) => {
        assert.ok(error instanceof FixtureRunnerError);
        assert.equal(error.message, "outbound response header x-test contains a capture or non-string value");
        assert.equal(error.message.includes(hostileCapture), false);
        assert.equal(error.message.includes(String(hostileNumber)), false);
        return true;
      });
    });
  }
});

test("rejects CR and LF response headers without echoing their values", async (t) => {
  for (const [name, hostile] of [["CR", "safe\rdo-not-echo"], ["LF", "safe\ndo-not-echo"]] as const) {
    await t.test(name, async () => {
      const transport = new ScriptedCimdTransport(() => response(200, { "x-test": hostile }, { absent: true }));
      await assert.rejects(transport.connectAndGet(request), (error: unknown) => {
        assert.ok(error instanceof FixtureRunnerError);
        assert.equal(error.message, "outbound response header x-test cannot contain CR or LF");
        assert.equal(error.message.includes(hostile), false);
        return true;
      });
    });
  }
});

test("encodes absent, JSON string, and non-JSON string response bodies", async (t) => {
  const cases: Array<{
    name: string;
    headers: HttpExchange["response"]["headers"];
    body: HttpExchange["response"]["body"];
    expected: string[];
  }> = [
    { name: "absent", headers: {}, body: { absent: true } as const, expected: [] },
    {
      name: "JSON string",
      headers: { "content-type": "application/json" },
      body: { value: "literal" } as const,
      expected: ['"literal"'],
    },
    {
      name: "non-JSON string",
      headers: { "content-type": "text/plain" },
      body: { value: "literal" } as const,
      expected: ["literal"],
    },
  ];
  for (const fixture of cases) {
    await t.test(fixture.name, async () => {
      const transport = new ScriptedCimdTransport(() => response(200, fixture.headers, fixture.body));
      const result = await transport.connectAndGet(request);
      const actual = (await chunks(result.encodedBody)).map((chunk) => Buffer.from(chunk).toString("utf8"));
      assert.deepStrictEqual(actual, fixture.expected);
    });
  }
});

test("returns fresh response chunks across calls", async () => {
  const scripted = response(200, { "content-type": "text/plain" }, { value: "literal" });
  const transport = new ScriptedCimdTransport(() => scripted);
  const first = await chunks((await transport.connectAndGet(request)).encodedBody);
  const second = await chunks((await transport.connectAndGet(request)).encodedBody);

  assert.notStrictEqual(first[0], second[0]);
  first[0]![0] = 0;
  assert.equal(Buffer.from(second[0]!).toString("utf8"), "literal");
});

test("implementation has no ambient HTTP, HTTPS, net, or TLS dependency", async () => {
  const source = await readFile(new URL("./parity/scripted-cimd-transport.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /node:(?:http|https|net|tls)/u);
  assert.doesNotMatch(source, /\bfetch\s*\(|\.(?:get|request|connect|createConnection)\s*\(/u);
  assert.match(source, /\bconnectAndGet\s*\(/u);
});

function response(
  status: number,
  headers: HttpExchange["response"]["headers"],
  body: HttpExchange["response"]["body"],
): HttpExchange["response"] {
  return { status, headers, body };
}

async function chunks(
  body: Awaited<ReturnType<CimdTransport["connectAndGet"]>>["encodedBody"],
): Promise<Uint8Array[]> {
  const result: Uint8Array[] = [];
  for await (const chunk of body as AsyncIterable<Uint8Array>) result.push(chunk);
  return result;
}
