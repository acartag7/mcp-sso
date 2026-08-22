// StorePort conformance for the shared identity-subject boundary.
import assert from "node:assert/strict";
import { test } from "node:test";
import { StoreInputError } from "../ports/store.ts";
import {
  authCode, FUTURE, NOW, refresh, sha256Hex, type MakeStore, type StoreConformanceOptions,
} from "./store-conformance-fixtures.ts";

const INVALID_SUBJECTS = [
  "", " ", " subject", "subject ", "bad\uFFFD", "\uD800", "\uDC00",
  "x".repeat(385), "😀".repeat(385),
] as const;

export function registerSubjectRows(label: string, make: MakeStore, _options: StoreConformanceOptions = {}): void {
  test(`${label}: identity-bearing writes reject every malformed subject before mutation`, async () => {
    const store = await make();
    for (const [index, subject] of INVALID_SUBJECTS.entries()) {
      await assert.rejects(
        store.saveAuthCode({ ...authCode(`bad-subject-code-${index}`, FUTURE), subject }),
        (error: unknown) => error instanceof StoreInputError,
      );
      assert.equal(await store.consumeAuthCode(sha256Hex(`bad-subject-code-${index}`), NOW), null);
      await assert.rejects(
        store.saveRefreshToken({ ...refresh(`bad-subject-refresh-${index}`, `bad-subject-family-${index}`, null, FUTURE), subject }),
        (error: unknown) => error instanceof StoreInputError,
      );
      assert.equal(await store.findRefreshToken(sha256Hex(`bad-subject-refresh-${index}`)), null);
      await assert.rejects(
        store.findGrantedScopes(subject, "client-1", NOW),
        (error: unknown) => error instanceof StoreInputError,
      );
      const jti = `bad-subject-jti-${index}`;
      await assert.rejects(
        store.commitConsentApproval(await store.getStoreInstanceId(), jti, FUTURE, {
          ...authCode(`bad-subject-commit-${index}`, FUTURE), subject,
        }),
        (error: unknown) => error instanceof StoreInputError,
      );
      assert.equal(await store.consumeConsentJti(jti, FUTURE), true, "rejected approval did not consume its jti");
    }
    await store.close();
  });

  test(`${label}: exact-width subjects persist and rotation copies the stored subject`, async () => {
    const store = await make();
    for (const [index, subject] of ["x".repeat(384), "😀".repeat(384)].entries()) {
      const rawCode = `subject-width-code-${index}`;
      await store.saveAuthCode({ ...authCode(rawCode, FUTURE), subject });
      assert.equal((await store.consumeAuthCode(sha256Hex(rawCode), NOW))?.subject, subject);
      const raw = `subject-width-refresh-${index}`;
      const next = `subject-width-next-${index}`;
      const family = `subject-width-family-${index}`;
      await store.saveRefreshToken({ ...refresh(raw, family, null, FUTURE), subject });
      assert.deepEqual(await store.findGrantedScopes(subject, "client-1", NOW), ["mcp:read"]);
      const rotated = await store.rotateRefreshToken(sha256Hex(raw), {
        ...refresh(next, family, sha256Hex(raw), FUTURE), subject: "",
      }, NOW);
      assert.equal(rotated?.subject, subject);
      assert.equal((await store.findRefreshToken(sha256Hex(next)))?.subject, subject);
    }
    await store.close();
  });
}
