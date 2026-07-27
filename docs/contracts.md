# Contracts

> **Contract-first.** This index and its numbered files are the source of truth for every port, schema,
> endpoint, token claim, and error shape in `mcp-sso`. The contract set is written and
> reviewed **before** implementation code, and it MUST be updated before any change
> to a port, schema, or error shape. `docs/threat-model.md` reasons about this
> surface; `docs/dependency-ledger.md` records the pins. If code and the contract set
> disagree, the contract set wins until one of them is deliberately changed.
>
> Status: **v0.2.3 shipped** (`mcp-sso@0.2.3` on npm) + **unreleased v0.3
> hardening on `main`**. The §17 feature contracts are locked; CIMD §17.1,
> generic OIDC, and the Google preset are implemented. CIMD and Google have
> historical live verification; the clean-`main` pre-release rerun and a second,
> non-Google generic-OIDC issuer remain pending. Device flow §17.3 and the
> dedicated GitHub port in §17.6 remain contract-only. Spec conformance
> target: **MCP Authorization 2025-11-25** (the stable spec clients implement); the next
> spec version was scheduled for **2026-07-28** but its final text is not yet
> published (its RC was locked 2026-05-21) —
> the RC's backward-compatible hardening items (e.g. RFC 9207 `iss`) are
> built in now. Before any release claims conformance with the 2026-07-28
> final text, the manual maintainer checklist in
> [`docs/verification.md` — "Spec-release re-verification (due
> 2026-07-28)"](verification.md#spec-release-re-verification-due-2026-07-28)
> MUST be completed.

## Contents

1. [Purpose & scope](contracts/01-purpose-and-scope.md)
2. [The two roles](contracts/02-the-two-roles.md)
3. [Normative references](contracts/03-normative-references.md)
4. [Design principles](contracts/04-design-principles.md)
5. [Configuration contract](contracts/05-configuration-contract.md)
6. [Ports](contracts/06-ports.md)
7. [Crypto & token contracts](contracts/07-crypto-and-token-contracts.md)
8. [Resource-server verifier contract](contracts/08-resource-server-verifier-contract.md)
9. [AS-lite bridge contract](contracts/09-as-lite-bridge-contract.md)
10. [Redirect-URI policy](contracts/10-redirect-uri-policy.md)
11. [Scope contract](contracts/11-scope-contract.md)
12. [Store-conformance contract](contracts/12-store-conformance-contract.md)
13. [Audit contract](contracts/13-audit-contract.md)
14. [Error catalog](contracts/14-error-catalog.md)
15. [Package & export map](contracts/15-package-and-export-map.md)
16. [Spec-conformance matrix](contracts/16-spec-conformance-matrix.md)
17. [v0.2 feature contracts (locked 2026-07-04)](contracts/17-v0-2-feature-contracts.md)
18. [Contract-change protocol](contracts/18-contract-change-protocol.md)

Each numbered file is canonical for its section; this index owns the shared status and routing.
