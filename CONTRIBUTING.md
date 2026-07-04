# Contributing to mcp-sso

## Build, test, and verify

```bash
pnpm install          # via corepack (packageManager pin); minimumReleaseAge = 15d
pnpm typecheck && pnpm check:lines && pnpm test && pnpm build
```

The suite includes an **end-to-end gate** (`test/e2e-mcp-sdk.test.ts`) that
drives the full OAuth flow and calls the protected `/mcp` through the
**official MCP SDK client** with a bridge-minted token — register →
authorize → token → `/mcp` → refresh → replay-revocation observed → revoke.

## House rules

- **pnpm only**, via corepack (see `packageManager` in `package.json`) — no
  npm/yarn lockfiles, ever.
- **250-line file limit** on everything under `src/`, enforced by
  `pnpm check:lines`.
- **Contract-first**: [`docs/contracts.md`](docs/contracts.md) and
  [`docs/threat-model.md`](docs/threat-model.md) are updated *before*
  implementation changes to any port, schema, or error shape — not after.
- **`jose` is the only runtime dependency.** Adding another one is a real
  decision, not a default — see [`docs/dependency-ledger.md`](docs/dependency-ledger.md).
- Every dependency pin (runtime or dev) must be at least 15 days old at the
  time it's added. `pnpm-workspace.yaml`'s `minimumReleaseAge` enforces this
  at install time; the ledger records the version and publish date for each
  one.

See [`docs/contracts.md`](docs/contracts.md) for the full port/schema/error
surface and [`docs/threat-model.md`](docs/threat-model.md) for the security
model any change needs to respect.
