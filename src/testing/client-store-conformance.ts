// Shared user ClientStore conformance. Every reference adapter that implements
// ClientStore invokes this runner; persistence-specific tests stay with the adapter.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ClientRegistration, ClientStore } from "../ports/client-store.ts";

type CloseableClientStore = ClientStore & { close(): Promise<void> };

const WEB: ClientRegistration = {
  clientId: "mcpdc_0123456789abcdef0123456789abcdef",
  redirectUris: ["https://client.test/callback"],
  applicationType: "web",
  issuedAtEpoch: 1,
};

export function runClientStoreConformance(
  label: string,
  make: () => CloseableClientStore,
): void {
  test(`${label}: ClientStore returns fresh registration snapshots`, async () => {
    const store = make();
    await store.save(WEB);
    const first = await store.find(WEB.clientId);
    assert.ok(first && first.applicationType !== "machine");
    first.redirectUris[0] = "https://mutated.test/callback";
    assert.deepEqual(await store.find(WEB.clientId), WEB);
    await store.close();
  });

  test(`${label}: ClientStore rejects collisions without replacement`, async () => {
    const store = make();
    await store.save(WEB);
    await assert.rejects(
      () => store.save({ ...WEB, redirectUris: ["https://attacker.test/callback"] }),
    );
    assert.deepEqual(await store.find(WEB.clientId), WEB);
    await store.close();
  });

  test(`${label}: ClientStore rejects malformed and unsupported records`, async () => {
    const store = make();
    const malformed = [
      { ...WEB, clientId: "foreign" },
      { ...WEB, issuedAtEpoch: -1 },
      { ...WEB, redirectUris: ["http://127.0.0.1/callback"] },
      { ...WEB, applicationType: "native", redirectUris: ["https://client.test/callback"] },
      {
        clientId: "mcc_0123456789abcdef0123456789abcdef",
        redirectUris: [],
        applicationType: "machine",
        issuedAtEpoch: 1,
        allowedScopes: ["mcp:read"],
        secrets: [],
      },
    ] as ClientRegistration[];
    for (const client of malformed) await assert.rejects(() => store.save(client));
    assert.equal(await store.find("foreign"), null);
    await store.close();
  });

  test(`${label}: ClientStore methods fail after its connection closes`, async () => {
    const store = make();
    await store.close();
    await assert.rejects(() => store.find(WEB.clientId), /Store is closed/);
    await assert.rejects(() => store.save(WEB), /Store is closed/);
  });
}
