# Freeze log

This file is append-only. Each entry records a change to a frozen fixture or a bootstrap correction made before the first freeze.

## 2026-08-30 bootstrap correction

`08-resource-server-verifier/8.4-duplicate-authorization-fails-closed` remained `draft`. The fixture gained the complete §5 JSON configuration, corpus key references, explicit empty pre-state, and the `host` profile required by §19.1 and §19.2. The profile records that its exact challenge points to the TypeScript reference implementation's origin-root protected-resource metadata document. Atesaki D1 uses a route-scoped document instead. Its two placeholder bearer values were replaced with independently valid corpus-signed tokens, and its protected-handler success path now returns 204. That change makes an implementation that selects either duplicate fail the fixture instead of passing later through token rejection. No frozen hash or receipt existed, so this change did not unfreeze evidence.

## 2026-08-31 bootstrap correction

`08-resource-server-verifier/8.4-duplicate-authorization-fails-closed` remained `draft`. It gained `kind: "fixture"` when the schema added boot fixtures. The request and expected response did not change. No frozen hash or receipt existed, so this change did not unfreeze evidence.
