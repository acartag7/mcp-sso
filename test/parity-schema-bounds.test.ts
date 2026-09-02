import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { loadFixture } from "./parity/schema-json.ts";
import type { BootFixture, HttpFixture, ParityFixture } from "./parity/types.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const HTTP_PATH = resolve(PROJECT_ROOT, "fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable.json");
const BOOT_PATH = resolve(PROJECT_ROOT, "fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed.json");
const AT = "2026-09-01T00:00:00.000Z";
const INSTANCE_ID = "abcdefghijklmnopqrstuv";
const SHAPES = ["http", "boot"] as const;
type Shape = (typeof SHAPES)[number];

function asHttp(fixture: ParityFixture): HttpFixture {
  if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
  return fixture;
}

function asBoot(fixture: ParityFixture): BootFixture {
  const source = asHttp(fixture);
  const { when: _when, then: _then, given, ...base } = source;
  const { protectedResource: _protectedResource, ...bootGiven } = given;
  return {
    ...base,
    kind: "boot",
    given: { ...bootGiven, entrypoint: "Bridge" },
    then: { boot: { outcome: "accepted" }, outbound: [] },
  };
}

async function loadWith(shape: Shape, mutate: (fixture: ParityFixture) => void): Promise<ParityFixture> {
  const source = structuredClone(await loadFixture(shape === "http" ? HTTP_PATH : BOOT_PATH));
  const fixture = shape === "http" ? asHttp(source) : asBoot(source);
  mutate(fixture);
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-bounds-"));
  const path = join(directory, "fixture.json");
  try {
    await writeFile(path, JSON.stringify(fixture), "utf8");
    return await loadFixture(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function rejectsSchema(shape: Shape, mutate: (fixture: ParityFixture) => void, detail: string): Promise<void> {
  let caught: unknown;
  try { await loadWith(shape, mutate); }
  catch (error) { caught = error; }
  assert.ok(caught instanceof FixtureRunnerError, `expected a schema rejection carrying: ${detail}`);
  assert.match(caught.message, /schema validation failed/u);
  assert.ok(caught.message.includes(detail), `${caught.message} does not carry: ${detail}`);
}

test("the request method is one of the six declared verbs and nothing else", async () => {
  for (const method of ["GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE"] as const) {
    const loaded = await loadWith("http", (fixture) => {
      if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
      fixture.when.request.method = method;
    });
    if (loaded.kind !== "fixture") throw new Error("expected HTTP fixture");
    assert.equal(loaded.when.request.method, method);
  }
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    (fixture.when.request as { method: string }).method = "CONNECT";
  }, "fixture/when/request/method must be equal to one of the allowed values");
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    (fixture.when.request as { method: string }).method = "TRACE";
  }, "fixture/when/request/method must be equal to one of the allowed values");
});

test("a wire header map admits at most 64 names", async () => {
  const sixtyFour = Object.fromEntries(Array.from({ length: 64 }, (_, index) => [`x-h${String(index).padStart(2, "0")}`, "v"]));
  const sixtyFive = { ...sixtyFour, "x-overflow": "v" };
  const loaded = await loadWith("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.then.headers = sixtyFour;
  });
  if (loaded.kind !== "fixture") throw new Error("expected HTTP fixture");
  assert.equal(Object.keys(loaded.then.headers ?? {}).length, 64);
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.then.headers = sixtyFive;
  }, "fixture/then/headers must NOT have more than 64 properties");
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    (fixture.when.request as { headers: Record<string, unknown> }).headers = sixtyFive;
  }, "fixture/when/request/headers must NOT have more than 64 properties");
});

test("every declared wire header map enforces the 64-name bound on its own", async () => {
  const sixtyFive = Object.fromEntries(Array.from({ length: 65 }, (_, index) => [`x-m${String(index).padStart(2, "0")}`, "v"]));
  const detail = "must NOT have more than 64 properties";
  const exchange = (headers: Record<string, string>): object => ({
    request: { method: "GET", url: "https://idp.example.com/metadata", headers: {}, body: { absent: true } },
    response: { status: 200, headers, body: { absent: true } },
  });
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.then.outbound = [{ method: "GET", url: "https://idp.example.com/token", headers: sixtyFive, body: "x" }];
  }, `fixture/then/outbound/0/headers ${detail}`);
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.given.http = [{ ...exchange({}), request: { method: "GET", url: "https://idp.example.com/metadata", headers: sixtyFive, body: { absent: true } } } as never];
  }, `fixture/given/http/0/request/headers ${detail}`);
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.given.http = [exchange(sixtyFive) as never];
  }, `fixture/given/http/0/response/headers ${detail}`);
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.given.protectedResource = {
      requiredScope: null, success: { status: 200, headers: sixtyFive, body: { absent: true } },
    };
  }, `fixture/given/protectedResource/success/headers ${detail}`);
});

test("every declared value branch enforces the 8192-character bound on its own", async () => {
  const over = "b".repeat(8193);
  const detail = "must NOT have more than 8192 characters";
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.when.request.headers = { "x-inbound": over };
  }, `fixture/when/request/headers/x-inbound ${detail}`);
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.when.request.headers = { "x-inbound": ["ok", over] };
  }, `fixture/when/request/headers/x-inbound/1 ${detail}`);
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.given.http = [{
      request: { method: "GET", url: "https://idp.example.com/metadata", headers: {}, body: { absent: true } },
      response: { status: 200, headers: { "content-type": ["ok", over] }, body: { absent: true } },
    }];
  }, `fixture/given/http/0/response/headers/content-type/1 ${detail}`);
});

test("an occurrence array admits at most 16 entries on either branch", async () => {
  const seventeen = Array.from({ length: 17 }, () => "x");
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.when.request.headers = { "x-inbound": seventeen };
  }, "fixture/when/request/headers/x-inbound must NOT have more than 16 items");
  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.given.http = [{
      request: { method: "GET", url: "https://idp.example.com/metadata", headers: {}, body: { absent: true } },
      response: { status: 200, headers: { "content-type": seventeen }, body: { absent: true } },
    }];
  }, "fixture/given/http/0/response/headers/content-type must NOT have more than 16 items");
});

test("a field name is at most 256 bytes and one occurrence at most 8192 bytes", async () => {
  const longName = `x-${"n".repeat(254)}`;
  const loaded = await loadWith("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.then.headers = { [longName]: "v" };
  });
  if (loaded.kind !== "fixture") throw new Error("expected HTTP fixture");
  assert.deepEqual(Object.keys(loaded.then.headers ?? {}), [longName]);

  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.then.headers = { [`x-${"n".repeat(255)}`]: "v" };
  }, "fixture/then/headers must NOT have more than 256 characters");

  const big = "v".repeat(8192);
  const loadedBig = await loadWith("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.given.http = [{
      request: { method: "GET", url: "https://idp.example.com/metadata", headers: {}, body: { absent: true } },
      response: { status: 200, headers: { "content-type": big }, body: { absent: true } },
    }];
  });
  if (loadedBig.kind !== "fixture") throw new Error("expected HTTP fixture");
  assert.equal((loadedBig.given.http[0]?.response.headers as Record<string, string>)["content-type"], big);

  await rejectsSchema("http", (fixture) => {
    if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
    fixture.given.http = [{
      request: { method: "GET", url: "https://idp.example.com/metadata", headers: {}, body: { absent: true } },
      response: { status: 200, headers: { "content-type": `${big}!` }, body: { absent: true } },
    }];
  }, "fixture/given/http/0/response/headers/content-type must NOT have more than 8192 characters");
});
