# Freeze log

This file is append-only. Each entry records a change to a frozen fixture or a bootstrap correction made before the first freeze.

## 2026-08-30 bootstrap correction

`08-resource-server-verifier/8.4-duplicate-authorization-fails-closed` remained `draft`. The fixture gained the complete §5 JSON configuration, corpus key references, explicit empty pre-state, and the `host` profile required by §19.1 and §19.2. The profile records that its exact challenge points to the TypeScript reference implementation's origin-root protected-resource metadata document. Atesaki D1 uses a route-scoped document instead. Its two placeholder bearer values were replaced with independently valid corpus-signed tokens, and its protected-handler success path now returns 204. That change makes an implementation that selects either duplicate fail the fixture instead of passing later through token rejection. No frozen hash or receipt existed, so this change did not unfreeze evidence.

## 2026-08-31 bootstrap correction

`08-resource-server-verifier/8.4-duplicate-authorization-fails-closed` remained `draft`. It gained `kind: "fixture"` when the schema added boot fixtures. The request and expected response did not change. No frozen hash or receipt existed, so this change did not unfreeze evidence.

## 2026-08-31 request-body encoding correction

`08-resource-server-verifier/8.4-duplicate-authorization-fails-closed` remained `draft`. Its JSON request body gained the explicit `json` wrapper required by the request-body encoding contract. The serialized request bytes and expected response did not change. No frozen hash or receipt existed, so this change did not unfreeze evidence.

## 2026-09-02 first freeze

`08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable` and `08-resource-server-verifier/8.4-duplicate-authorization-fails-closed` left `draft` and became the first frozen fixtures, under the §19.4 record amended in the same pull request: receipt, freeze-log entry, and reviewed pull request, with no manifest and no hash lock. The reference runner passed both on `63ed98774c5bbbdd486e1aa9f878c194ca7f1ea3` through Fastify, Express, and Hono (portable) and Fastify (host) with zero skips. Receipts: implementation mcp-sso, version 0.5.0. The executable content of both fixtures is byte-identical to that commit; only `status`, `receipt`, and the host fixture's `notes` changed, the last to drop a sentence calling the fixture a draft. No `given`, `when`, or `then` member changed.

## 2026-09-07 Authorization occurrence freeze

`08-resource-server-verifier/8.4-single-authorization-succeeds-portable` and `08-resource-server-verifier/8.4-zero-authorization-fails-closed-portable` became frozen under §19.4. Their executable content is unchanged from `3f3fb6e111ac7141b81704ad972e09e0dc2a84c5`. [CI run 33821090439](https://github.com/acartag7/mcp-sso/actions/runs/33821090439) passed both through Fastify, Express, and Hono on 2026-09-04. The complete parity run passed 10 executions with zero failures and zero skips. Receipts name mcp-sso 0.5.0 at that commit and run date. Only `status` and `receipt` changed in these fixtures.

## 2026-09-07 bearer input freeze

The following 13 portable fixtures became frozen under §19.4. Their executable content is unchanged from `fee79add342382b80c5d7316739e35547bd53b42`. [CI run 34161390005](https://github.com/acartag7/mcp-sso/actions/runs/34161390005) passed the complete corpus on that main commit on 2026-09-07: 49 executions, zero failures and zero skips. Each portable fixture ran through Fastify, Express, and Hono. Receipts name mcp-sso 0.5.0 at that commit and run date. Only `status` and `receipt` changed in these fixtures. This freeze does not establish complete verifier coverage or a published corpus version.

- `08-resource-server-verifier/8.4-bearer-with-extra-value-portable`
- `08-resource-server-verifier/8.4-bearer-without-separator-portable`
- `08-resource-server-verifier/8.4-bearer-without-token-portable`
- `08-resource-server-verifier/8.4-blank-authorization-portable`
- `08-resource-server-verifier/8.4-coalesced-authorization-portable`
- `08-resource-server-verifier/8.4-duplicate-empty-then-valid-portable`
- `08-resource-server-verifier/8.4-duplicate-invalid-then-valid-portable`
- `08-resource-server-verifier/8.4-duplicate-valid-then-empty-portable`
- `08-resource-server-verifier/8.4-duplicate-valid-then-invalid-portable`
- `08-resource-server-verifier/8.4-empty-authorization-portable`
- `08-resource-server-verifier/8.4-lowercase-bearer-succeeds-portable`
- `08-resource-server-verifier/8.4-token-without-bearer-scheme-portable`
- `08-resource-server-verifier/8.4-wrong-authorization-scheme-portable`

## 2026-09-07 access-token admission freeze

The following 70 fixtures became frozen under §19.4: 64 portable and six host. Their executable content is unchanged from `c6fe2bd7ae3b0e2b7bf0de69dc350d738a91a90e`. [CI run 34164161218](https://github.com/acartag7/mcp-sso/actions/runs/34164161218) passed the complete corpus on that main commit on 2026-09-07: 247 executions, zero failures and zero skips. Portable fixtures ran through Fastify, Express, and Hono; host fixtures ran through Fastify. Receipts name mcp-sso 0.5.0 at that commit and run date. Only `status` and `receipt` changed in these fixtures. The source and distribution gaps remain open; this freeze does not establish complete verifier coverage or a published corpus version.

- `07-crypto-and-token-contracts/7.2-aud-case-portable` (portable)
- `07-crypto-and-token-contracts/7.2-aud-empty-array-portable` (portable)
- `07-crypto-and-token-contracts/7.2-aud-empty-portable` (portable)
- `07-crypto-and-token-contracts/7.2-aud-foreign-array-portable` (portable)
- `07-crypto-and-token-contracts/7.2-aud-missing-portable` (portable)
- `07-crypto-and-token-contracts/7.2-aud-null-portable` (portable)
- `07-crypto-and-token-contracts/7.2-aud-number-portable` (portable)
- `07-crypto-and-token-contracts/7.2-aud-object-portable` (portable)
- `07-crypto-and-token-contracts/7.2-aud-path-portable` (portable)
- `07-crypto-and-token-contracts/7.2-aud-slash-portable` (portable)
- `07-crypto-and-token-contracts/7.2-aud-wrong-portable` (portable)
- `07-crypto-and-token-contracts/7.2-clock-last-canonical-millisecond-portable` (portable)
- `07-crypto-and-token-contracts/7.2-clock-last-canonical-mint-portable` (portable)
- `07-crypto-and-token-contracts/7.2-clock-year-9999-at-expiry-portable` (portable)
- `07-crypto-and-token-contracts/7.2-clock-year-9999-before-expiry-portable` (portable)
- `07-crypto-and-token-contracts/7.2-clock-year-zero-portable` (portable)
- `07-crypto-and-token-contracts/7.2-compact-missing-signature-portable` (portable)
- `07-crypto-and-token-contracts/7.2-exp-array-portable` (portable)
- `07-crypto-and-token-contracts/7.2-exp-boolean-portable` (portable)
- `07-crypto-and-token-contracts/7.2-exp-equal-portable` (portable)
- `07-crypto-and-token-contracts/7.2-exp-expired-portable` (portable)
- `07-crypto-and-token-contracts/7.2-exp-missing-portable` (portable)
- `07-crypto-and-token-contracts/7.2-exp-null-portable` (portable)
- `07-crypto-and-token-contracts/7.2-exp-object-portable` (portable)
- `07-crypto-and-token-contracts/7.2-exp-string-portable` (portable)
- `07-crypto-and-token-contracts/7.2-expiry-first-millisecond-after-portable` (portable)
- `07-crypto-and-token-contracts/7.2-expiry-last-millisecond-before-portable` (portable)
- `07-crypto-and-token-contracts/7.2-expiry-one-second-ahead-portable` (portable)
- `07-crypto-and-token-contracts/7.2-hmac-key-confusion-portable` (portable)
- `07-crypto-and-token-contracts/7.2-iss-array-portable` (portable)
- `07-crypto-and-token-contracts/7.2-iss-case-portable` (portable)
- `07-crypto-and-token-contracts/7.2-iss-empty-portable` (portable)
- `07-crypto-and-token-contracts/7.2-iss-missing-portable` (portable)
- `07-crypto-and-token-contracts/7.2-iss-null-portable` (portable)
- `07-crypto-and-token-contracts/7.2-iss-number-portable` (portable)
- `07-crypto-and-token-contracts/7.2-iss-path-portable` (portable)
- `07-crypto-and-token-contracts/7.2-iss-slash-portable` (portable)
- `07-crypto-and-token-contracts/7.2-iss-wrong-portable` (portable)
- `07-crypto-and-token-contracts/7.2-signature-tampered-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-384-ascii-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-384-scalars-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-385-ascii-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-385-scalars-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-array-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-blank-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-empty-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-leading-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-lone-high-surrogate-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-lone-low-surrogate-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-missing-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-null-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-number-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-object-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-one-scalar-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-replacement-portable` (portable)
- `07-crypto-and-token-contracts/7.2-subject-trailing-portable` (portable)
- `07-crypto-and-token-contracts/7.2-unsigned-none-portable` (portable)
- `07-crypto-and-token-contracts/7.2-valid-access-token-portable` (portable)
- `08-resource-server-verifier/8.1-array-grant-portable` (portable)
- `08-resource-server-verifier/8.1-boolean-grant-portable` (portable)
- `08-resource-server-verifier/8.1-complete-machine-triad-host` (host)
- `08-resource-server-verifier/8.1-conflicting-machine-identities-host` (host)
- `08-resource-server-verifier/8.1-interactive-subject-machine-grant-host` (host)
- `08-resource-server-verifier/8.1-null-grant-portable` (portable)
- `08-resource-server-verifier/8.1-number-grant-portable` (portable)
- `08-resource-server-verifier/8.1-object-grant-portable` (portable)
- `08-resource-server-verifier/8.1-opaque-machine-prefix-client-host` (host)
- `08-resource-server-verifier/8.1-reserved-pair-missing-grant-host` (host)
- `08-resource-server-verifier/8.1-reserved-subject-foreign-client-host` (host)
- `08-resource-server-verifier/8.1-unknown-grant-portable` (portable)
