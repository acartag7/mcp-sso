import assert from "node:assert/strict";
import test from "node:test";
import type { ClientRegistration, MachineClientRegistration, UserClientRegistration } from "../src/ports/client-store.ts";
import { StoreInputError } from "../src/ports/store.ts";
import { runClientStoreConformance } from "../src/testing/client-store-conformance.ts";
import { FixtureClientStore } from "./parity/client-store.ts";
import type { LogicalTables } from "./parity/logical-state.ts";
import { hydrateLogicalState, projectLogicalState } from "./parity/logical-state.ts";
import type { ClientRegistrationRow } from "./parity/types.ts";

const CLIENT_ID = "mcpdc_0123456789abcdef0123456789abcdef";
const ABSENT_ID = "mcpdc_fedcba98765432100123456789abcdef";
const INSTANCE_ID = "Kd9tR2wLxQ7pZm4Vb1Ns6A";
const LOOPBACK = "http://127.0.0.1:8123/callback";
const HTTPS = "https://client.test/callback";
const ISSUED_AT = 1_756_684_800;

const HYDRATED_ROW: ClientRegistrationRow = {
  client_id: CLIENT_ID,
  redirect_uris: [LOOPBACK],
  application_type: "native",
  issued_at_epoch: ISSUED_AT,
};

const HYDRATED: UserClientRegistration = {
  clientId: CLIENT_ID,
  redirectUris: [LOOPBACK],
  applicationType: "native",
  issuedAtEpoch: ISSUED_AT,
};

const WEB: UserClientRegistration = {
  clientId: CLIENT_ID,
  redirectUris: [HTTPS],
  applicationType: "web",
  issuedAtEpoch: 1,
};

const MACHINE: MachineClientRegistration = {
  clientId: "mcc_0123456789abcdef0123456789abcdef",
  redirectUris: [],
  applicationType: "machine",
  issuedAtEpoch: 1,
  allowedScopes: ["mcp:read"],
  secrets: [],
};

/** A table that records every lookup, so a test can assert that a rejected id
 *  never reaches stored state at all. */
class ReadRecordingTable extends Map<string, ClientRegistration> {
  readonly reads: string[] = [];

  override get(key: string): ClientRegistration | undefined {
    this.reads.push(key);
    return super.get(key);
  }
}

function isInvalidClient(error: unknown): boolean {
  assert(error instanceof StoreInputError);
  assert.equal(error.message, "client registration is invalid");
  return true;
}

function hydratedTables(rows: ClientRegistrationRow[]): LogicalTables {
  return hydrateLogicalState({ client_registration: rows });
}

function storeOver(tables: LogicalTables): FixtureClientStore {
  return new FixtureClientStore(tables.clients);
}

runClientStoreConformance("FixtureClientStore", () => storeOver(hydrateLogicalState({})));

test("a registration hydrated from given.state is found with its exact fields", async () => {
  const store = storeOver(hydratedTables([HYDRATED_ROW]));
  assert.deepEqual(await store.find(CLIENT_ID), HYDRATED);
  await store.close();
});

test("a found registration is a copy that cannot be mutated into stored state", async () => {
  const tables = hydratedTables([HYDRATED_ROW]);
  const store = storeOver(tables);
  const found = await store.find(CLIENT_ID);
  assert.ok(found !== null);
  found.redirectUris[0] = "https://attacker.test/callback";
  found.redirectUris.push("https://extra.test/callback");
  found.issuedAtEpoch = 0;
  assert.deepEqual(await store.find(CLIENT_ID), HYDRATED);
  assert.deepEqual(tables.clients.get(CLIENT_ID), HYDRATED);
  await store.close();
});

test("saving an id that already exists is rejected and replaces nothing", async () => {
  const tables = hydratedTables([HYDRATED_ROW]);
  const store = storeOver(tables);
  await assert.rejects(
    () => store.save({ ...HYDRATED, redirectUris: ["http://127.0.0.1:9999/callback"], issuedAtEpoch: 2 }),
    (error: unknown) => {
      assert(error instanceof StoreInputError);
      assert.equal(error.message, "client id already exists");
      return true;
    },
  );
  assert.deepEqual([...tables.clients], [[CLIENT_ID, HYDRATED]]);
  await store.close();
});

const MALFORMED: Array<[string, unknown]> = [
  ["an id outside the generated pattern", { ...WEB, clientId: "client-a" }],
  ["an id whose hex is upper case", { ...WEB, clientId: CLIENT_ID.toUpperCase() }],
  ["a non-string id", { ...WEB, clientId: 1 }],
  ["an unsupported application type", { ...WEB, applicationType: "desktop" }],
  ["a machine application type", { ...MACHINE, clientId: CLIENT_ID }],
  ["a negative issued_at_epoch", { ...WEB, issuedAtEpoch: -1 }],
  ["a fractional issued_at_epoch", { ...WEB, issuedAtEpoch: 1.5 }],
  ["an issued_at_epoch beyond the safe integer range", { ...WEB, issuedAtEpoch: 2 ** 53 }],
  ["no redirect URIs", { ...WEB, redirectUris: [] }],
  ["more redirect URIs than the cap", { ...WEB, redirectUris: Array.from({ length: 17 }, () => HTTPS) }],
  ["redirect URIs that are not an array", { ...WEB, redirectUris: HTTPS }],
  ["a non-string redirect URI", { ...WEB, redirectUris: [1] }],
  ["a hole in the redirect URI list", { ...WEB, redirectUris: [HTTPS, , HTTPS] }],
  ["no registration at all", null],
];

for (const [malformed, client] of MALFORMED) {
  test(`saving a registration with ${malformed} is rejected before it is stored`, async () => {
    const tables = hydrateLogicalState({});
    const store = storeOver(tables);
    await assert.rejects(() => store.save(client as ClientRegistration), isInvalidClient);
    assert.equal(tables.clients.size, 0);
    await store.close();
  });
}

test("the registration redirect policy decides each URI by application type", async () => {
  const rejected: UserClientRegistration[] = [
    { ...WEB, redirectUris: [LOOPBACK] },
    { ...WEB, redirectUris: [HTTPS, LOOPBACK] },
    { ...HYDRATED, redirectUris: [HTTPS] },
    { ...HYDRATED, redirectUris: [LOOPBACK, HTTPS] },
  ];
  for (const client of rejected) {
    const tables = hydrateLogicalState({});
    const store = storeOver(tables);
    await assert.rejects(() => store.save(client), isInvalidClient);
    assert.equal(tables.clients.size, 0);
    await store.close();
  }
  for (const client of [WEB, HYDRATED]) {
    const store = storeOver(hydrateLogicalState({}));
    await store.save(client);
    assert.deepEqual(await store.find(client.clientId), client);
    await store.close();
  }
});

test("an id outside the generated pattern is null without reading the table", async () => {
  const table = new ReadRecordingTable([["client-a", { ...HYDRATED, clientId: "client-a" }]]);
  const store = new FixtureClientStore(table);
  for (const clientId of ["client-a", CLIENT_ID.toUpperCase(), "mcpdc_", ""]) {
    assert.equal(await store.find(clientId), null);
  }
  assert.deepEqual(table.reads, []);
  await store.close();
});

test("a generated id with no registration is null", async () => {
  const table = new ReadRecordingTable();
  const store = new FixtureClientStore(table);
  assert.equal(await store.find(ABSENT_ID), null);
  assert.deepEqual(table.reads, [ABSENT_ID]);
  await store.close();
});

test("a saved registration projects as a client_registration row in contract form", async () => {
  const tables = hydrateLogicalState({});
  const store = storeOver(tables);
  await store.save(WEB);
  await store.save({ ...HYDRATED, clientId: ABSENT_ID });
  assert.deepEqual(projectLogicalState(tables, INSTANCE_ID).client_registration, [
    { client_id: CLIENT_ID, redirect_uris: [HTTPS], application_type: "web", issued_at_epoch: 1 },
    { client_id: ABSENT_ID, redirect_uris: [LOOPBACK], application_type: "native", issued_at_epoch: ISSUED_AT },
  ]);
  await store.close();
});

test("a saved registration keeps no reference to the caller's redirect array", async () => {
  const tables = hydrateLogicalState({});
  const store = storeOver(tables);
  const redirectUris = [HTTPS];
  await store.save({ ...WEB, redirectUris });
  redirectUris[0] = "https://attacker.test/callback";
  assert.deepEqual(await store.find(CLIENT_ID), WEB);
  assert.deepEqual(
    projectLogicalState(tables, INSTANCE_ID).client_registration,
    [{ client_id: CLIENT_ID, redirect_uris: [HTTPS], application_type: "web", issued_at_epoch: 1 }],
  );
  await store.close();
});

test("a machine registration is refused by save and projects no client_registration row", async () => {
  const tables = hydrateLogicalState({});
  const store = storeOver(tables);
  await assert.rejects(() => store.save(MACHINE), isInvalidClient);
  assert.equal(tables.clients.size, 0);
  assert.equal(await store.find(MACHINE.clientId), null);
  tables.clients.set(MACHINE.clientId, MACHINE);
  assert.deepEqual(projectLogicalState(tables, INSTANCE_ID).client_registration, []);
  await store.close();
});

test("a stored record that is not a user registration fails closed on find", async () => {
  const tables = hydrateLogicalState({});
  const store = storeOver(tables);
  tables.clients.set(CLIENT_ID, { ...MACHINE, clientId: CLIENT_ID });
  await assert.rejects(() => store.find(CLIENT_ID), isInvalidClient);
  await store.close();
});
