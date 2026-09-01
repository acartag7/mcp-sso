import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { ScriptedDnsResolver } from "./parity/scripted-dns.ts";

const exchange = (url: string): { request: { url: string } } => ({ request: { url } });
const answer = [{ address: "93.184.216.34", family: 4 }];
const undeclaredError = "fixture DNS lookup is not declared by an HTTPS exchange";

test("declared HTTPS hostname resolves to the fixed public address", async () => {
  const resolver = new ScriptedDnsResolver([exchange("https://client.example/metadata.json")]);
  assert.deepEqual(await resolver.resolve("client.example"), answer);
});

test("URL parsing canonicalizes hostname case and an explicit default port", async () => {
  const resolver = new ScriptedDnsResolver([exchange("HTTPS://CLIENT.EXAMPLE:443/metadata.json")]);
  assert.deepEqual(await resolver.resolve("client.example"), answer);
});

test("multiple declared HTTPS hostnames are admitted", async () => {
  const resolver = new ScriptedDnsResolver([
    exchange("https://first.example/client.json"),
    exchange("https://second.example/keys.json"),
  ]);
  assert.deepEqual(await resolver.resolve("first.example"), answer);
  assert.deepEqual(await resolver.resolve("second.example"), answer);
});

test("exact localhost resolves to the fixed loopback address", async () => {
  const resolver = new ScriptedDnsResolver([exchange("https://localhost/client.json")]);
  assert.deepEqual(await resolver.resolve("localhost"), [{ address: "127.0.0.1", family: 4 }]);
});

test("a localhost subdomain resolves to the fixed loopback address", async () => {
  const resolver = new ScriptedDnsResolver([exchange("https://client.localhost/client.json")]);
  assert.deepEqual(await resolver.resolve("client.localhost"), [{ address: "127.0.0.1", family: 4 }]);
});

test("a localhost suffix near-miss resolves to the public address", async () => {
  const resolver = new ScriptedDnsResolver([exchange("https://notlocalhost/client.json")]);
  assert.deepEqual(await resolver.resolve("notlocalhost"), answer);
});

test("undeclared hostname fails without echoing the hostname", async () => {
  const hostname = "private.undeclared.example";
  await assert.rejects(
    () => new ScriptedDnsResolver([]).resolve(hostname),
    (error: unknown) => error instanceof FixtureRunnerError
      && error.message === undeclaredError && !error.message.includes(hostname),
  );
});

test("a hostname declared only over HTTP remains rejected", async () => {
  const resolver = new ScriptedDnsResolver([exchange("http://client.example/metadata.json")]);
  await assert.rejects(
    () => resolver.resolve("client.example"),
    (error: unknown) => error instanceof FixtureRunnerError && error.message === undeclaredError,
  );
});

test("mutating one answer cannot affect a later answer", async () => {
  const resolver = new ScriptedDnsResolver([exchange("https://client.example/metadata.json")]);
  const first = await resolver.resolve("client.example");
  first[0]!.address = "127.0.0.1";
  first.push({ address: "127.0.0.2", family: 4 });
  assert.deepEqual(await resolver.resolve("client.example"), answer);
});

test("implementation has no ambient DNS or network dependency", async () => {
  const source = await readFile(new URL("./parity/scripted-dns.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /node:(?:dgram|dns|http|https|net|tls)/u);
  assert.doesNotMatch(source, /\b(?:fetch|connect|lookup|resolve4|resolve6)\s*\(/u);
});
