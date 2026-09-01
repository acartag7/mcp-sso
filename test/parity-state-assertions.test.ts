import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { assertState } from "./parity/state-assertions.ts";
import type {
  AuthorizationCodeRow, ClientRegistrationRow, ConsentJtiRow, LogicalState, RefreshTokenRow,
  StateAssertion,
} from "./parity/types.ts";

const RESOURCE = "https://api.example.com/mcp";
const CLIENT_ID = "mcp-client-7Qk2mZr9";
const REDIRECT_URI = "http://127.0.0.1:33418/callback";
const SECOND_REDIRECT_URI = "http://127.0.0.1:33419/callback";
const INSTANCE_ID = "7Qk2mZr9Tv1XbN4sLd6Hpe";
const CODE_EXPIRES_AT = "2026-08-31T10:05:00.000Z";
const LATER_EXPIRES_AT = "2026-08-31T11:05:00.000Z";
const REFRESH_EXPIRES_AT = "2026-09-30T10:00:00.000Z";
const CONSUMED_AT = "2026-08-31T10:02:00.000Z";
const REVOKED_AT = "2026-08-31T09:30:00.000Z";
const ISSUED_AT_EPOCH = 1756636800;
const REVERSED_SCOPES = ["mcp:write", "mcp:read"];
const MODES = ["exact", "contains"] as const;

function hex(seed: string): string {
  return seed.repeat(Math.ceil(64 / seed.length)).slice(0, 64);
}

const CODE_A = hex("a1"), CODE_B = hex("b2");
const REFRESH_A = hex("c3"), REFRESH_B = hex("d4");
const JTI_A = hex("e5"), JTI_B = hex("f6");
const FAMILY_A = hex("0a"), FAMILY_B = hex("1b");

type CodeFields = Partial<AuthorizationCodeRow>;
type RefreshFields = Partial<RefreshTokenRow>;

function codeRow(codeHash: string, extra: CodeFields): AuthorizationCodeRow {
  return {
    code_hash: codeHash, client_id: CLIENT_ID, subject: "user-4821", redirect_uri: REDIRECT_URI,
    resource: RESOURCE, scopes: ["mcp:read", "mcp:write"], code_challenge: hex("7c"),
    code_challenge_method: "S256", expires_at: CODE_EXPIRES_AT, grant_generation: 1, ...extra,
  };
}

function refreshRow(tokenHash: string, extra: RefreshFields): RefreshTokenRow {
  return {
    token_hash: tokenHash, family_id: FAMILY_A, client_id: CLIENT_ID, subject: "user-4821",
    resource: RESOURCE, scopes: ["mcp:read", "mcp:write"], expires_at: REFRESH_EXPIRES_AT,
    grant_generation: 1, ...extra,
  };
}

function codeA(extra: CodeFields = {}): AuthorizationCodeRow { return codeRow(CODE_A, extra); }
function codeB(extra: CodeFields = {}): AuthorizationCodeRow { return codeRow(CODE_B, { subject: "user-9033", ...extra }); }
function refreshA(extra: RefreshFields = {}): RefreshTokenRow { return refreshRow(REFRESH_A, { consumed_at: CONSUMED_AT, ...extra }); }
function refreshB(extra: RefreshFields = {}): RefreshTokenRow { return refreshRow(REFRESH_B, { previous_token_hash: REFRESH_A, ...extra }); }
function jtiRow(jti: string, expiresAt: string = CODE_EXPIRES_AT): ConsentJtiRow { return { jti, expires_at: expiresAt }; }
function clientRow(applicationType: "native" | "web" = "native"): ClientRegistrationRow {
  return {
    client_id: CLIENT_ID, redirect_uris: [REDIRECT_URI, SECOND_REDIRECT_URI],
    application_type: applicationType, issued_at_epoch: ISSUED_AT_EPOCH,
  };
}

function snapshot(): Required<LogicalState> {
  return {
    authorization_code: [codeA(), codeB()],
    consent_jti: [jtiRow(JTI_A)],
    refresh_token: [refreshA(), refreshB()],
    revoked_family: [
      { family_id: FAMILY_B, resource: RESOURCE, revoked_at: REVOKED_AT, grant_generation: 1 },
    ],
    client_registration: [clientRow()],
    store_instance: [{ instance_id: INSTANCE_ID }],
  };
}

function snapshotWith(extra: Partial<Required<LogicalState>>): Required<LogicalState> {
  return { ...snapshot(), ...extra };
}

function withoutKind(kind: keyof LogicalState): LogicalState {
  const rows: LogicalState = snapshot();
  delete rows[kind];
  return rows;
}

function assertion(rows: LogicalState, mode: StateAssertion["mode"] = "exact", absent: StateAssertion["absent"] = []): StateAssertion {
  return { mode, rows, absent };
}

test("exact accepts reordered rows and omits kinds whose observed rows are empty", () => {
  assertState(snapshot(), assertion(snapshotWith({
    authorization_code: [codeB(), codeA()], refresh_token: [refreshB(), refreshA()],
  })), "fixture");

  const sparse = snapshotWith({ consent_jti: [], revoked_family: [], store_instance: [] });
  assertState(sparse, assertion({
    authorization_code: [codeA(), codeB()], refresh_token: [refreshA(), refreshB()],
    client_registration: [clientRow()],
  }), "fixture");
});

test("exact rejects extra, missing, changed, unlisted, and reordered array members", () => {
  const cases: Array<[string, Required<LogicalState>, LogicalState]> = [
    ["an extra observed row", snapshotWith({ consent_jti: [jtiRow(JTI_A), jtiRow(JTI_B)] }), snapshot()],
    ["a missing observed row", snapshotWith({ refresh_token: [refreshA()] }), snapshot()],
    ["a differing scalar field", snapshot(), snapshotWith({ consent_jti: [jtiRow(JTI_A, LATER_EXPIRES_AT)] })],
    ["a non-empty kind omitted from rows", snapshot(), withoutKind("store_instance")],
    ["a reordered scope list", snapshot(),
      snapshotWith({ authorization_code: [codeA({ scopes: REVERSED_SCOPES }), codeB()] })],
  ];

  for (const [name, observed, rows] of cases) {
    assert.throws(
      () => assertState(observed, assertion(rows), "fixture"), /fixture exact state/, name,
    );
  }
});

test("contains accepts a strict subset of rows and an empty row set", () => {
  assertState(snapshot(), assertion({
    refresh_token: [refreshB()], store_instance: [{ instance_id: INSTANCE_ID }],
  }, "contains"), "fixture");

  assertState(snapshot(), assertion({}, "contains"), "fixture");
});

test("contains rejects a missing key, a changed row, and a reordered scope list", () => {
  const cases: Array<[Required<LogicalState>, LogicalState, RegExp]> = [
    [snapshotWith({ refresh_token: [refreshA()] }), { refresh_token: [refreshB()] },
      /fixture contains refresh_token:/],
    [snapshot(), { client_registration: [clientRow("web")] },
      /fixture contains client_registration:/],
    [snapshot(), { authorization_code: [codeA({ scopes: REVERSED_SCOPES })] },
      /fixture contains authorization_code:/],
  ];

  for (const [observed, rows, message] of cases) {
    assert.throws(
      () => assertState(observed, assertion(rows, "contains"), "fixture"), message,
    );
  }
});

test("a duplicate primary key in the expected rows is a runner error in both modes", () => {
  for (const mode of MODES) {
    assert.throws(
      () => assertState(snapshot(), assertion({
        authorization_code: [codeA(), codeA({ subject: "user-9033" })],
      }, mode), "fixture"),
      (error: unknown) => error instanceof FixtureRunnerError
        && /fixture expected state has duplicate authorization_code primary key/.test(error.message),
      mode,
    );
    assert.throws(
      () => assertState(snapshot(), assertion({
        revoked_family: [...snapshot().revoked_family, ...snapshot().revoked_family],
      }, mode), "fixture"),
      /fixture expected state has duplicate revoked_family primary key/, mode,
    );
  }
});

test("a duplicate primary key in the observed snapshot is a runner error in both modes", () => {
  const duplicateJti = snapshotWith({ consent_jti: [jtiRow(JTI_A), jtiRow(JTI_A)] });
  const duplicateRefresh = snapshotWith({
    refresh_token: [refreshA(), refreshA({ subject: "user-9033" })],
  });

  for (const mode of MODES) {
    assert.throws(
      () => assertState(duplicateJti, assertion({}, mode), "fixture"),
      (error: unknown) => error instanceof FixtureRunnerError
        && /fixture observed state has duplicate consent_jti primary key/.test(error.message),
      mode,
    );
    assert.throws(
      () => assertState(duplicateRefresh, assertion({}, mode), "fixture"),
      /fixture observed state has duplicate refresh_token primary key/, mode,
    );
  }
});

test("absent selectors pass when no row matches and fail when one does, in both modes", () => {
  for (const mode of MODES) {
    const rows: LogicalState = mode === "exact" ? snapshot() : {};
    assertState(snapshot(), assertion(rows, mode, [
      { kind: "authorization_code", where: { code_hash: CODE_A, subject: "user-0000" } },
      { kind: "revoked_family", where: { family_id: FAMILY_A } },
    ]), "fixture");

    assert.throws(
      () => assertState(snapshot(), assertion(rows, mode, [
        { kind: "refresh_token", where: { family_id: FAMILY_A, consumed_at: CONSUMED_AT } },
      ]), "fixture"),
      /fixture forbidden state selector/, mode,
    );
  }
});

test("an absent selector matches neither an omitted optional field nor an inherited one", () => {
  assertState(snapshot(), assertion(snapshot(), "exact", [
    { kind: "refresh_token", where: { token_hash: REFRESH_B, consumed_at: CONSUMED_AT } },
  ]), "fixture");

  const inherited = Object.create({ consumed_at: CONSUMED_AT }) as RefreshTokenRow;
  Object.assign(inherited, refreshRow(REFRESH_A, {}));
  assertState(snapshotWith({ refresh_token: [inherited] }), assertion(
    snapshotWith({ refresh_token: [inherited] }), "exact",
    [{ kind: "refresh_token", where: { consumed_at: CONSUMED_AT } }],
  ), "fixture");
});

test("normalization leaves the caller's arrays and rows untouched", () => {
  const observed = snapshotWith({
    authorization_code: [codeB(), codeA()], consent_jti: [jtiRow(JTI_B), jtiRow(JTI_A)],
  });
  const expectedRows: LogicalState = {
    authorization_code: [codeB(), codeA()], refresh_token: [refreshB(), refreshA()],
  };
  const observedBefore = structuredClone(observed);
  const expectedBefore = structuredClone(expectedRows);

  assertState(observed, assertion(expectedRows, "contains"), "fixture");

  assert.deepStrictEqual(observed, observedBefore);
  assert.deepStrictEqual(expectedRows, expectedBefore);
});

test("an unknown record kind or a second store_instance row is a runner error on either side", () => {
  const twoInstances = [{ instance_id: INSTANCE_ID }, { instance_id: "7Qk2mZr9Tv1XbN4sLd6Hpf" }];
  const unknownKind = { ...snapshot(), machine_client: [] } as unknown as Required<LogicalState>;
  for (const mode of MODES) {
    assert.throws(
      () => assertState(snapshotWith({ store_instance: twoInstances }), assertion({}, mode), "fixture"),
      (error: unknown) => error instanceof FixtureRunnerError
        && /fixture observed state has 2 store_instance rows/.test(error.message),
      mode,
    );
    assert.throws(() => assertState(snapshot(), assertion({ store_instance: twoInstances }, mode), "fixture"),
      /fixture expected state has 2 store_instance rows/, mode);
    assert.throws(() => assertState(unknownKind, assertion({}, mode), "fixture"),
      /fixture observed state has unknown record kind machine_client/, mode);
    assert.throws(() => assertState(snapshot(), assertion(unknownKind, mode), "fixture"),
      /fixture expected state has unknown record kind machine_client/, mode);
  }
});
