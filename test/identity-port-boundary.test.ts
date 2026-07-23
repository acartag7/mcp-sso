import assert from "node:assert/strict";
import { test } from "node:test";
import {
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
