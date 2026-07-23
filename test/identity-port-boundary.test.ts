import assert from "node:assert/strict";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import {
  captureIdentityPort, captureRedirectIdentityPort,
  parseIdentityResult, parseRedirectExchangeResult,
  type IdentityClaims, type IdentityResult, type RedirectExchangeResult,
} from "../src/ports/identity.ts";

class ClassIdentity implements IdentityClaims {
  get subject(): string { return "class-user"; }
  get allowedScopes(): string[] { return ["mcp:read"]; }
}

class ClassIdentityResult {
  readonly ok = true as const;
  get identity(): IdentityClaims { return new ClassIdentity(); }
}

class ClassRedirectResult {
  readonly ok = true as const;
  get identity(): IdentityClaims { return new ClassIdentity(); }
}

test("identity result parsers accept structurally valid class DTOs", () => {
  const identityResult: IdentityResult = new ClassIdentityResult();
  const redirectResult: RedirectExchangeResult = new ClassRedirectResult();

  assert.deepEqual(parseIdentityResult(identityResult), {
    ok: true,
    identity: { subject: "class-user", allowedScopes: ["mcp:read"], claims: undefined },
  });
  assert.deepEqual(parseRedirectExchangeResult(redirectResult), {
    ok: true,
    identity: { subject: "class-user", allowedScopes: ["mcp:read"], claims: undefined },
  });
});

test("identity result parsers reject plain inherited fields without invoking them", () => {
  let reads = 0;
  const prototype = Object.create(null) as Record<string, unknown>;
  Object.defineProperty(prototype, "ok", {
    get() { reads += 1; return true; },
  });
  const result = Object.create(prototype) as Record<string, unknown>;
  result.identity = { subject: "inherited-user" };

  assert.equal(parseIdentityResult(result), null);
  assert.equal(parseRedirectExchangeResult(result), null);
  assert.equal(reads, 0);
});

test("identity ports are captured from own or class methods only", async () => {
  let inheritedCalls = 0;
  const inherited = Object.create({
    async verify() {
      inheritedCalls += 1;
      return { ok: true, identity: { subject: "ambient-user" } };
    },
  });
  assert.equal(captureIdentityPort(inherited), null);

  class Port {
    readonly redirectUri = "https://auth.test/oauth/callback";
    async verify() { return { ok: true as const, identity: { subject: "class-user" } }; }
    buildAuthorizationUrl() { return "https://idp.test/authorize"; }
    async exchangeAndVerify() {
      return { ok: true as const, identity: { subject: "class-user" } };
    }
  }
  const port = new Port();
  assert.deepEqual(await captureIdentityPort(port)?.verify("credential"), {
    ok: true, identity: { subject: "class-user" },
  });
  assert.equal(
    captureRedirectIdentityPort(port)?.buildAuthorizationUrl({
      state: "s", nonce: "n", codeChallenge: "c", codeChallengeMethod: "S256",
    }),
    "https://idp.test/authorize",
  );
  assert.equal(inheritedCalls, 0);
});

test("identity port capture rejects arrays with polluted prototypes", () => {
  const descriptors = new Map<PropertyKey, PropertyDescriptor | undefined>();
  for (const [key, value] of [
    ["verify", async () => ({ ok: true, identity: { subject: "ambient-user" } })],
    ["redirectUri", "https://auth.test/oauth/callback"],
    ["buildAuthorizationUrl", () => "https://idp.test/authorize"],
    ["exchangeAndVerify", async () => ({ ok: true, identity: { subject: "ambient-user" } })],
  ] as const) {
    descriptors.set(key, Object.getOwnPropertyDescriptor(Array.prototype, key));
    Object.defineProperty(Array.prototype, key, { configurable: true, value });
  }
  try {
    assert.equal(captureIdentityPort([]), null);
    assert.equal(captureRedirectIdentityPort([]), null);
  } finally {
    for (const [key, descriptor] of descriptors) {
      if (descriptor === undefined) delete (Array.prototype as unknown as Record<PropertyKey, unknown>)[key];
      else Object.defineProperty(Array.prototype, key, descriptor);
    }
  }
});

test("identity parsers stop at a foreign realm Object prototype", () => {
  const result = runInNewContext(`
    Object.prototype.ok = true;
    Object.prototype.identity = { subject: "ambient-user" };
    ({})
  `);
  assert.equal(parseIdentityResult(result), null);
  assert.equal(parseRedirectExchangeResult(result), null);
});

test("identity parsers reject optional ceilings present only on a root prototype", () => {
  const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, "allowedScopes");
  Object.defineProperty(Object.prototype, "allowedScopes", {
    configurable: true, value: ["mcp:read"],
  });
  try {
    const result = { ok: true, identity: { subject: "local-user" } };
    assert.deepEqual(parseIdentityResult(result), {
      ok: false, reason: "malformed_allowed_scopes",
    });
    assert.deepEqual(parseRedirectExchangeResult(result), {
      ok: false, kind: "identity_rejected", reason: "malformed_allowed_scopes",
    });
  } finally {
    if (descriptor === undefined) delete (Object.prototype as Record<string, unknown>).allowedScopes;
    else Object.defineProperty(Object.prototype, "allowedScopes", descriptor);
  }

  const foreignIdentity = runInNewContext(`
    Object.prototype.allowedScopes = ["mcp:read"];
    ({ subject: "foreign-user" })
  `);
  assert.deepEqual(parseIdentityResult({ ok: true, identity: foreignIdentity }), {
    ok: false, reason: "malformed_allowed_scopes",
  });
  assert.deepEqual(parseRedirectExchangeResult({ ok: true, identity: foreignIdentity }), {
    ok: false, kind: "identity_rejected", reason: "malformed_allowed_scopes",
  });
});

test("redirect results classify malformed present scope ceilings as identity rejection", () => {
  for (const allowedScopes of ["mcp:read", ["mcp:read", 42]]) {
    assert.deepEqual(parseRedirectExchangeResult({
      ok: true,
      identity: { subject: "class-user", allowedScopes },
    }), {
      ok: false,
      kind: "identity_rejected",
      reason: "malformed_allowed_scopes",
    });
  }
  assert.deepEqual(parseRedirectExchangeResult({
    ok: true,
    identity: { subject: "class-user", allowedScopes: [] },
  }), {
    ok: true,
    identity: { subject: "class-user", allowedScopes: [], claims: undefined },
  });
});

test("identity parsers reject unreadable ceilings without widening", () => {
  const expectedIdentity = { ok: false, reason: "malformed_allowed_scopes" };
  const expectedRedirect = {
    ok: false, kind: "identity_rejected", reason: "malformed_allowed_scopes",
  };

  let ownReads = 0;
  const ownAccessor = { subject: "class-user" };
  Object.defineProperty(ownAccessor, "allowedScopes", {
    enumerable: true,
    get() { ownReads += 1; return []; },
  });
  assert.deepEqual(parseIdentityResult({ ok: true, identity: ownAccessor }), expectedIdentity);
  assert.deepEqual(parseRedirectExchangeResult({ ok: true, identity: ownAccessor }), expectedRedirect);
  assert.equal(ownReads, 0);

  const inherited = Object.assign(
    Object.create({ allowedScopes: [] }),
    { subject: "class-user" },
  );
  assert.deepEqual(parseIdentityResult({ ok: true, identity: inherited }), expectedIdentity);
  assert.deepEqual(parseRedirectExchangeResult({ ok: true, identity: inherited }), expectedRedirect);

  let throwingReads = 0;
  class ThrowingCeiling {
    readonly subject = "class-user";
    get allowedScopes(): string[] { throwingReads += 1; throw new Error("unreadable"); }
  }
  assert.deepEqual(
    parseIdentityResult({ ok: true, identity: new ThrowingCeiling() }),
    expectedIdentity,
  );
  assert.deepEqual(
    parseRedirectExchangeResult({ ok: true, identity: new ThrowingCeiling() }),
    expectedRedirect,
  );
  assert.equal(throwingReads, 2);
});

test("identity parsers snapshot class getters exactly once", () => {
  class ChangingCeiling {
    readonly subject = "class-user";
    reads = 0;
    get allowedScopes(): string[] | undefined {
      this.reads += 1;
      return this.reads === 1 ? [] : undefined;
    }
  }
  const directIdentity = new ChangingCeiling();
  assert.deepEqual(parseIdentityResult({ ok: true, identity: directIdentity }), {
    ok: true,
    identity: { subject: "class-user", allowedScopes: [], claims: undefined },
  });
  assert.equal(directIdentity.reads, 1);

  const redirectIdentity = new ChangingCeiling();
  assert.deepEqual(parseRedirectExchangeResult({ ok: true, identity: redirectIdentity }), {
    ok: true,
    identity: { subject: "class-user", allowedScopes: [], claims: undefined },
  });
  assert.equal(redirectIdentity.reads, 1);
});
