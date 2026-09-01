import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  BodyValue, BootFixture, BootGiven, BootThen, CaptureSpec, FixtureGiven,
  HeaderValue, HttpFixture, IdentityCheck, Matcher, RequestSpec,
} from "./parity/types.ts";

const keysWithoutPublic: FixtureGiven["keys"] = {
  signingPrivate: "keys/signing-private.pem",
};
const bootKeysWithoutPrivate: BootGiven["keys"] = {};
const given = {
  config: { issuer: "https://issuer.example" },
  clock: "2026-09-01T00:00:00.000Z",
  random: { seed: "seed" },
  keys: keysWithoutPublic,
  state: {},
  http: [],
  identity: { checks: [{ input: { absent: true }, result: { ok: false, reason: "denied" } }] },
  rateLimit: { checks: [] },
  protectedResource: { requiredScope: null },
} satisfies FixtureGiven;
const boot = {
  id: "19-parity/1-boot", kind: "boot", profile: "portable", status: "draft",
  contract: { section: "19", clause: "1", quote: "boot" },
  given: {
    config: null, entrypoint: "createBridgeConfig", clock: "2026-09-01T00:00:00.000Z",
    random: { seed: "seed" }, keys: bootKeysWithoutPrivate, state: {}, http: [], identity: { checks: [] }, rateLimit: { checks: [] },
  },
  then: { boot: { outcome: "accepted" }, outbound: [] },
} satisfies BootFixture;
const base = {
  id: "19-parity/1-fixture",
  kind: "fixture",
  profile: "portable",
  contract: { section: "19", clause: "1", quote: "fixture" },
  status: "draft",
  given,
  when: { request: { method: "GET", path: "/mcp" } },
  then: { status: 200, outbound: [] },
} satisfies HttpFixture;

const emptyHeaders: HeaderValue = [];
const scalarHeader: HeaderValue = "x-one";
const captureHeader: HeaderValue = { $capture: { fixture: "19-parity/1-source", name: "token", format: "raw" } };
const oneHeader: HeaderValue = ["x-one"];
const manyHeaders: HeaderValue = ["x-one", "x-two"];
const absentBody: BodyValue = { absent: true };
const matcherBranches: Matcher[] = ["exact", { absent: true }, { equals: null }, { matches: "pattern" }, { contains: "text" }, { schema: {} }];
const requestBodies: Array<NonNullable<RequestSpec["body"]>> = [{ json: null }, { form: [{ name: "field", value: "value" }] }, { text: "text" }];
const bootAssertions: BootThen["boot"][] = [{ outcome: "accepted" }, { outcome: "rejected", error: { code: "invalid_config" } }];
const captureSources: CaptureSpec["source"][] = [{ bodyPointer: "/token" }, { header: "location", urlQuery: "token" }];
// @ts-expect-error body wrappers select exactly one branch
const ambiguousBody: BodyValue = { absent: true, value: "body" };
// @ts-expect-error matchers select exactly one branch
const ambiguousMatcher: Matcher = { equals: "body", contains: "body" };
// @ts-expect-error request bodies select exactly one encoding
const ambiguousRequestBody: RequestSpec["body"] = { json: {}, text: "body" };
const acceptedWithErrorValue = { outcome: "accepted" as const, error: { code: "invalid_config" } };
// @ts-expect-error accepted boot assertions cannot carry rejection errors
const acceptedWithError: BootThen["boot"] = acceptedWithErrorValue;
// @ts-expect-error capture sources select exactly one source
const ambiguousCaptureSource: CaptureSpec["source"] = { bodyPointer: "/token", header: "location", urlQuery: "token" };
const frozen = {
  ...base,
  status: "frozen",
  receipt: { implementation: "reference", version: "0.4.0", commit: "abcdef1", date: "2026-09-01" },
} satisfies HttpFixture;
const superseded = {
  ...base,
  status: "superseded",
  supersededBy: "19-parity/1-replacement",
} satisfies HttpFixture;
const withNotes = { ...base, notes: "The fixture does not assert an unrelated field." } satisfies HttpFixture;
const draftWithLifecycleMetadata = {
  ...base,
  supersededBy: "19-parity/1-replacement",
  receipt: { implementation: "reference", version: "0.4.0", commit: "abcdef1", date: "2026-09-01" },
} satisfies HttpFixture;

// @ts-expect-error frozen status requires a receipt
const frozenWithoutReceipt = { ...base, status: "frozen" } satisfies HttpFixture;
// @ts-expect-error superseded status requires a replacement id
const supersededWithoutReplacement = { ...base, status: "superseded" } satisfies HttpFixture;

// @ts-expect-error identity checks choose result or throw, never both
const identityWithBothOutcomes: IdentityCheck = {
  input: { absent: true }, result: { ok: false, reason: "denied" }, throw: { kind: "generic" },
};
// @ts-expect-error identity checks require one result or throw outcome
const identityWithoutOutcome: IdentityCheck = { input: { absent: true } };
const admittedIdentity = {
  input: { value: "credential" }, result: { ok: true, identity: { subject: "subject" } },
} satisfies IdentityCheck;
const admittedResultWithReason = { ok: true as const, identity: { subject: "subject" }, reason: "denied" };
// @ts-expect-error admitted identity results cannot carry rejection reasons
const admittedWithReason: IdentityCheck = { input: { value: "credential" }, result: admittedResultWithReason };
const oauthIdentityThrow = { input: { value: "credential" },
  throw: { kind: "oauth", code: "access_denied", description: "denied", status: 403 },
} satisfies IdentityCheck;
const genericIdentityThrow = { input: { value: "credential" }, throw: { kind: "generic" } } satisfies IdentityCheck;
const genericThrowWithOAuthFieldsValue = { kind: "generic" as const, code: "access_denied" };
// @ts-expect-error generic identity throws carry no OAuth fields
const genericThrowWithOAuthFields: IdentityCheck = { input: { value: "credential" }, throw: genericThrowWithOAuthFieldsValue };

const schemaValidLiteralBootConfigs: BootGiven["config"][] = [null, false, "malformed", []];

test("raw fixture type samples retain wire and lifecycle shapes", () => {
  assert.deepEqual([base.kind, boot.kind], ["fixture", "boot"]);
});
