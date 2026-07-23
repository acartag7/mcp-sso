import assert from "node:assert/strict";
import { test } from "node:test";
import type { Bridge } from "../src/adapters/bridge.ts";
import { handlePairingAuthorize } from "../src/adapters/pairing-flow.ts";
import type { ConsolePairingIdentity } from "../src/identity/console-pairing.ts";
import type { NormRequest } from "../src/adapters/http.ts";

const PARAMS = [
  "response_type", "client_id", "redirect_uri", "code_challenge",
  "code_challenge_method", "resource", "scope", "state",
] as const;

function dependencies() {
  let sessions = 0;
  let authorizations = 0;
  const bridge = {
    async handleAuthorize() { authorizations += 1; throw new Error("must not authorize"); },
  } as unknown as Bridge;
  const pairing = {
    async beginSession() { sessions += 1; return { nonce: "n", expiresAt: "2099-01-01T00:00:00.000Z" }; },
  } as unknown as ConsolePairingIdentity;
  return { bridge, pairing, counts: () => ({ sessions, authorizations }) };
}

function request(query: NormRequest["query"], body: unknown = undefined): NormRequest {
  return { query, body, headers: {} };
}

test("pairing authorize rejects repeated OAuth parameters before starting a session", async () => {
  for (const key of PARAMS) {
    const deps = dependencies();
    const response = await handlePairingAuthorize(
      deps,
      "GET",
      request({ [key]: ["first", "second"] }),
    );
    assert.equal(response.status, 400, key);
    assert.deepEqual(deps.counts(), { sessions: 0, authorizations: 0 }, key);
  }
});

test("pairing authorize rejects repeated body parameters and cross-channel duplicates", async () => {
  const bodyDuplicate = dependencies();
  const bodyResponse = await handlePairingAuthorize(
    bodyDuplicate,
    "POST",
    request({}, { client_id: ["first", "second"] }),
  );
  assert.equal(bodyResponse.status, 400);
  assert.deepEqual(bodyDuplicate.counts(), { sessions: 0, authorizations: 0 });

  const crossChannel = dependencies();
  const crossResponse = await handlePairingAuthorize(
    crossChannel,
    "POST",
    request({ client_id: "first" }, { client_id: "second" }),
  );
  assert.equal(crossResponse.status, 400);
  assert.deepEqual(crossChannel.counts(), { sessions: 0, authorizations: 0 });
});
