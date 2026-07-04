# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.** Report it
privately via **GitHub Security Advisories** (the "Security" tab → "Report a
vulnerability"), which keeps the report private to the maintainer until a fix is
coordinated.

> The maintainer must enable **Private vulnerability reporting** and **Security
> advisories** in the repository **Settings → Security & analysis** before this
> channel is usable. If you are reading this and that toggle is off, the channel is
> not yet open — surface it to the maintainer out-of-band.

## Response expectations

This is a solo-maintained project. Acknowledgment of a report is expected within a
few business days. I do not commit to a fixed fix-SLA I cannot keep: for a confirmed
high/critical issue I'll work to ship a fix or mitigation as fast as feasible and
**coordinate disclosure timing with the reporter** before publishing any details.
Lower-severity reports are handled in the normal release cadence.

## Supported versions

Only the latest release line is supported.

| Version | Supported |
| --- | --- |
| `0.x` (latest) | ✅ |
| anything older | ❌ (upgrade) |

Pre-release (`0.0.0` / pre-`v0.1`) is not a supported release.

## Scope

This policy covers the published library **`mcp-sso`** and its subpaths
(`/fastify`, `/express`, `/hono`, `/identity/*`, `/store/*`). The `examples/`
directory is **illustrative wiring, not a supported surface** — please don't report
example-app configuration as a library vulnerability.

## Supply-chain posture

- **One runtime dependency:** `jose` (JWT/JWKS/JOSE primitives). Framework adapters
  and stores are optional peer/built-in (`node:sqlite`); nothing else ships at runtime.
- **15-day install floor:** `pnpm-workspace.yaml` sets `minimumReleaseAge: 21600`
  (minutes = 15 days), so compromised/typosquat packages are refused at install time
  for at least 15 days after publish. Every direct pin is recorded with version +
  publish date in [`docs/dependency-ledger.md`](docs/dependency-ledger.md).
- **SHA-pinned CI:** all GitHub Actions are pinned to 40-hex commit SHAs (no floating
  tags), including the OpenSSF Scorecard scan (`.github/workflows/scorecard.yml`).
- **Fail-closed by design:** ambiguous config, a missing identity, an unknown audience,
  or a replayed token is a hard failure, never a degraded default. See
  [`docs/threat-model.md`](docs/threat-model.md).

## Verifying published packages (provenance)

Releases are published from GitHub Actions with `npm publish --provenance` — the
artifact is signed via **Sigstore** and the signature is bound to the build provenance
(attestation) of the public source repository.

Consumers verify the signature with:

```bash
npm audit signatures    # npm >= 9 — checks the Sigstore signature of installed packages
```

> **Provenance ordering:** the repository **must be public before any real publish**.
> Sigstore attests against the source repo; a private repo breaks provenance
> verification for auditors. (This is also enforced as a comment at the tag trigger in
> `.github/workflows/publish.yml`.)
