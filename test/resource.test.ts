import assert from "node:assert/strict";
import { test } from "node:test";
import { AuthConfigError } from "../src/config.ts";
import { OAuthError } from "../src/errors.ts";
import {
  buildResourceCatalog, canonicalResource, resolveResource, scopeUnion,
} from "../src/resource.ts";

const SECURE = { allowInsecureLocalhost: false };
const LOOPBACK = { allowInsecureLocalhost: true };
const R1 = "https://a.test/mcp";
const R2 = "https://b.test/mcp";

function authError(fn: () => unknown, msg?: RegExp): void {
  assert.throws(fn, (err: unknown) =>
    err instanceof AuthConfigError && (msg === undefined || msg.test(err.message)),
  );
}
function invalidTarget(fn: () => unknown): void {
  assert.throws(fn, (err: unknown) => err instanceof OAuthError && err.code === "invalid_target");
}
function singleton(overrides: Record<string, unknown> = {}): never {
  return { resource: R1, scopeCatalog: ["x"], defaultScopes: ["x"], ...overrides } as never;
}

test("canonicalResource: rejects non-string and empty", () => {
  authError(() => canonicalResource(123, SECURE));
  authError(() => canonicalResource(null, SECURE));
  authError(() => canonicalResource("", SECURE));
});

test("canonicalResource: rejects a missing or wrong scheme prefix", () => {
  authError(() => canonicalResource("ftp://a.test/mcp", SECURE));
  authError(() => canonicalResource("a.test/mcp", SECURE));
  // http:// is NOT accepted when the loopback exception is off.
  authError(() => canonicalResource("http://a.test/mcp", SECURE), /https/);
});

test("canonicalResource: http only on loopback under the dev exception", () => {
  assert.equal(canonicalResource("http://localhost/mcp", LOOPBACK), "http://localhost/mcp");
  assert.equal(canonicalResource("http://127.0.0.1/mcp", LOOPBACK), "http://127.0.0.1/mcp");
  // loopback exception on, but host is not loopback -> still rejected.
  authError(() => canonicalResource("http://a.test/mcp", LOOPBACK), /loopback/);
});

test("canonicalResource: rejects raw syntax WHATWG would rewrite", () => {
  authError(() => canonicalResource("https:////a.test/mcp", SECURE), /authority/); // third slash / slash authority start
  authError(() => canonicalResource("https:/a.test/mcp", SECURE)); // one slash -> no prefix
  authError(() => canonicalResource("https://a.test\\mcp", SECURE), /backslash/);
  authError(() => canonicalResource("https://api.test/mcp ", SECURE), /whitespace/); // trailing space, never trimmed
  authError(() => canonicalResource(" https://api.test/mcp", SECURE)); // leading space fails the prefix check (never trimmed)
  authError(() => canonicalResource("https://api.test/\x00mcp", SECURE), /control/);
  authError(() => canonicalResource("https://api.test/%zz", SECURE), /percent/);
  authError(() => canonicalResource("https://api.test/%2", SECURE), /percent/);
  authError(() => canonicalResource("https://api.test/mcp?", SECURE), /'#'/);
  authError(() => canonicalResource("https://api.test/mcp?x=1", SECURE));
  authError(() => canonicalResource("https://api.test/mcp#", SECURE), /'#'/);
  authError(() => canonicalResource("https://api.test/mcp#frag", SECURE));
  authError(() => canonicalResource("https://user@api.test/mcp", SECURE), /userinfo/);
  authError(() => canonicalResource("https://api.test:/mcp", SECURE), /port/); // explicit empty port
});

test("canonicalResource: never repairs or trims raw syntax", () => {
  authError(() => canonicalResource("https://api.test/mcp\n", SECURE));
  authError(() => canonicalResource("https://API.test/mcp ", SECURE)); // trailing space is a rejection, not a trim
});

test("canonicalResource: valid percent-encodes are accepted", () => {
  // %2F is a well-formed escape; WHATWG keeps it encoded in the path.
  assert.equal(canonicalResource("https://api.test/%41", SECURE), "https://api.test/%41");
});

test("canonicalResource: canonicalization equivalences", () => {
  assert.equal(canonicalResource("HTTPS://A.TEST/mcp", SECURE), R1); // scheme+host lower-cased
  assert.equal(canonicalResource("https://a.test:443/mcp", SECURE), R1); // ordinary default port dropped
  assert.equal(canonicalResource("https://a.test/a/b/../mcp", SECURE), "https://a.test/a/mcp"); // dot segments
});

test("canonicalResource: trailing-slash distinction", () => {
  // origin-only canonicalizes with NO trailing slash (both spellings collapse).
  assert.equal(canonicalResource("https://a.test", SECURE), "https://a.test");
  assert.equal(canonicalResource("https://a.test/", SECURE), "https://a.test");
  // non-root path keeps its exact trailing-slash distinction.
  assert.equal(canonicalResource("https://a.test/mcp", SECURE), "https://a.test/mcp");
  assert.equal(canonicalResource("https://a.test/mcp/", SECURE), "https://a.test/mcp/");
  assert.notEqual(canonicalResource("https://a.test/mcp", SECURE), canonicalResource("https://a.test/mcp/", SECURE));
});

test("buildResourceCatalog: singleton and multi forms each build a frozen catalog", () => {
  const one = buildResourceCatalog(singleton(), SECURE);
  assert.equal(one.entries.length, 1);
  assert.equal(one.entries[0]?.resource, R1);
  assert.equal(Object.isFrozen(one), true);
  assert.equal(Object.isFrozen(one.entries), true);
  assert.equal(Object.isFrozen(one.entries[0]?.scopeCatalog), true);
  assert.deepEqual(Object.keys(one.entries[0] as object).sort(), ["defaultScopes", "resource", "scopeCatalog"]);

  const two = buildResourceCatalog({
    resources: [
      { resource: R1, scopeCatalog: ["a"], defaultScopes: ["a"] },
      { resource: R2, scopeCatalog: ["b"], defaultScopes: [] },
    ],
  }, SECURE);
  assert.equal(two.entries.length, 2);
  assert.equal(two.allowInsecureLocalhost, false);
});

test("buildResourceCatalog: union/singleton mutual exclusion + partial trio", () => {
  authError(() => buildResourceCatalog({
    resource: R1, scopeCatalog: ["x"], defaultScopes: ["x"], resources: [],
  } as never, SECURE), /both/); // both forms
  authError(() => buildResourceCatalog({} as never, SECURE), /either/); // neither form
  authError(() => buildResourceCatalog({ resources: [] }, SECURE), /non-empty/); // empty array
  authError(() => buildResourceCatalog({ resource: R1, scopeCatalog: ["x"] } as never, SECURE), /together/); // partial trio (no defaultScopes)
  authError(() => buildResourceCatalog({ resource: R1, defaultScopes: ["x"] } as never, SECURE), /together/); // partial trio (no scopeCatalog)
});

test("buildResourceCatalog: duplicate canonical resources are rejected", () => {
  authError(() => buildResourceCatalog({
    resources: [
      { resource: "https://a.test/mcp", scopeCatalog: ["a"], defaultScopes: ["a"] },
      { resource: "https://a.test/mcp", scopeCatalog: ["b"], defaultScopes: ["b"] },
    ],
  }, SECURE), /duplicate/);
  // duplicate via canonical equivalence (default port collapses to the same value)
  authError(() => buildResourceCatalog({
    resources: [
      { resource: "https://a.test:443/mcp", scopeCatalog: ["a"], defaultScopes: ["a"] },
      { resource: "https://a.test/mcp", scopeCatalog: ["b"], defaultScopes: ["b"] },
    ],
  }, SECURE), /duplicate/);
});

test("buildResourceCatalog: extra own keys on an entry are rejected by name", () => {
  authError(() => buildResourceCatalog({
    resources: [{ resource: R1, scopeCatalog: ["x"], defaultScopes: ["x"], apiKey: "leak" } as never],
  }, SECURE), /apiKey/);
  const leak = Symbol("leak");
  authError(() => buildResourceCatalog({
    resources: [{ resource: R1, scopeCatalog: ["x"], defaultScopes: ["x"], [leak]: "secret" } as never],
  }, SECURE), /Symbol\(leak\)/);
});

test("buildResourceCatalog: scope validation is fail-closed", () => {
  authError(() => buildResourceCatalog({
    resources: [{ resource: R1, scopeCatalog: [], defaultScopes: [] } as never],
  }, SECURE), /non-empty/);
  authError(() => buildResourceCatalog({
    resources: [{ resource: R1, scopeCatalog: ["a", "a"], defaultScopes: ["a"] } as never],
  }, SECURE), /duplicates/);
  authError(() => buildResourceCatalog({
    resources: [{ resource: R1, scopeCatalog: ["bad scope"], defaultScopes: ["bad scope"] } as never],
  }, SECURE), /scope token/); // whitespace -> not an RFC 6749 token
  authError(() => buildResourceCatalog({
    resources: [{ resource: R1, scopeCatalog: ["a"], defaultScopes: ["b"] } as never],
  }, SECURE), /subset/); // default not in catalog
});

test("scopeUnion: sorted, de-duplicated across all entries", () => {
  const catalog = buildResourceCatalog({
    resources: [
      { resource: R1, scopeCatalog: ["b", "a"], defaultScopes: ["a"] },
      { resource: R2, scopeCatalog: ["b", "c"], defaultScopes: [] },
    ],
  }, SECURE);
  assert.deepEqual(scopeUnion(catalog), ["a", "b", "c"]);
});

test("resolveResource: omission resolves only when exactly one entry", () => {
  const one = buildResourceCatalog(singleton(), SECURE);
  assert.equal(resolveResource(one, undefined).resource, R1);
  const two = buildResourceCatalog({
    resources: [
      { resource: R1, scopeCatalog: ["a"], defaultScopes: ["a"] },
      { resource: R2, scopeCatalog: ["b"], defaultScopes: [] },
    ],
  }, SECURE);
  invalidTarget(() => resolveResource(two, undefined));
});

test("resolveResource: exact match via canonicalization; unknown/malformed -> invalid_target", () => {
  const catalog = buildResourceCatalog({
    resources: [{ resource: R1, scopeCatalog: ["a"], defaultScopes: ["a"] }],
  }, SECURE);
  // canonical equivalence (default port + case) still matches the stored entry.
  assert.equal(resolveResource(catalog, "https://a.test:443/mcp").resource, R1);
  assert.equal(resolveResource(catalog, "HTTPS://A.TEST/mcp").resource, R1);
  invalidTarget(() => resolveResource(catalog, "https://other.test/mcp"));
  invalidTarget(() => resolveResource(catalog, "not a url"));
});

test("legacy attestation: singleton-only, exact canonical equality, never inferred", () => {
  // explicit + exact -> permitted, published as canonical
  const permitted = buildResourceCatalog(singleton({ legacySingletonResource: "https://a.test:443/mcp" }), SECURE);
  assert.equal(permitted.legacyBindingPermitted, true);
  assert.equal(permitted.legacySingletonResource, R1);
  // disagrees with resource -> rejected
  authError(() => buildResourceCatalog(singleton({ legacySingletonResource: "https://b.test/mcp" }), SECURE), /exactly/);
  // multi-resource form always rejects the field
  authError(() => buildResourceCatalog({
    resources: [{ resource: R1, scopeCatalog: ["a"], defaultScopes: ["a"] }],
    legacySingletonResource: R1,
  } as never, SECURE), /singleton form/);
  // never inferred from the sole singleton resource
  const none = buildResourceCatalog(singleton(), SECURE);
  assert.equal(none.legacyBindingPermitted, false);
  assert.equal(none.legacySingletonResource, undefined);
});

// --- Regression: validate-vs-publish TOCTOU + own-property class (gate findings) ---

test("read-once: an accessor-backed field cannot validate as A and publish as B", () => {
  // The canonical instance of this repo's recurring validate-vs-publish class:
  // without a single own-data-property read, the FIRST read passes validation and
  // a LATER read supplies what actually lands in the catalog.
  let reads = 0;
  const evil = {
    get resource() { return ++reads === 1 ? "https://good.test/mcp" : "https://evil.test/mcp"; },
    scopeCatalog: ["a"],
    defaultScopes: ["a"],
  };
  authError(() => buildResourceCatalog({ resources: [evil] } as never, SECURE), /data property/);
  // Same rule on the singleton branch — the sibling path, not just the entry path.
  let singletonReads = 0;
  const evilSingleton = {
    get resource() { return ++singletonReads === 1 ? "https://good.test/mcp" : "https://evil.test/mcp"; },
    scopeCatalog: ["a"],
    defaultScopes: ["a"],
  };
  authError(() => buildResourceCatalog(evilSingleton as never, SECURE), /data property/);
});

test("own properties only: an entry inheriting the trio from a prototype is rejected", () => {
  // Zero own keys, so the unknown-key sweep sees nothing to reject while the
  // values themselves arrive from the prototype chain.
  const proto = { resource: R1, scopeCatalog: ["a"], defaultScopes: ["a"] };
  const inherited = Object.create(proto);
  assert.equal(Reflect.ownKeys(inherited).length, 0);
  authError(() => buildResourceCatalog({ resources: [inherited] } as never, SECURE), /own propert/);
});

test("branch exclusivity is decided by ownership, not by value", () => {
  // `{ resources: [...], resource: undefined }` DECLARES both branches. Selecting
  // multi-resource silently would let a typo'd singleton key disappear.
  authError(() => buildResourceCatalog({
    resources: [{ resource: R1, scopeCatalog: ["a"], defaultScopes: ["a"] }],
    resource: undefined,
  } as never, SECURE), /not both/);
  authError(() => buildResourceCatalog({
    resource: R1, scopeCatalog: ["a"], defaultScopes: ["a"], resources: undefined,
  } as never, SECURE), /not both/);
});

test("resources array is snapshotted once: a length-shifting Proxy cannot smuggle an entry", () => {
  const good = { resource: R1, scopeCatalog: ["a"], defaultScopes: ["a"] };
  const smuggled = { resource: "https://evil.test/mcp", scopeCatalog: ["a"], defaultScopes: ["a"] };
  let lengthReads = 0;
  const shifting = new Proxy([good, smuggled], {
    get(target, prop, receiver) {
      if (prop === "length") return ++lengthReads === 1 ? 1 : 2;
      return Reflect.get(target, prop, receiver);
    },
  });
  const catalog = buildResourceCatalog({ resources: shifting } as never, SECURE);
  // Exactly the one entry the length check accepted — never the later-revealed second.
  assert.deepEqual(catalog.entries.map((e) => e.resource), [R1]);
});
