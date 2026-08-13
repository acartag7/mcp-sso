# Contracts

> **Contract-first.** This index and its numbered files are the source of truth for every port, schema,
> endpoint, token claim, and error shape in `mcp-sso`. The contract set is written and
> reviewed **before** implementation code, and it MUST be updated before any change
> to a port, schema, or error shape. `docs/threat-model.md` reasons about this
> surface; `docs/dependency-ledger.md` records the pins. If code and the contract set
> disagree, the contract set wins until one of them is deliberately changed.
>
> Status: **v0.3.3**. This release is based on exact merged implementation commit
> `5725e77d26651f4c0a303554a3f0fd3bdf897df8`. It carries the v0.3.2
> grant-generation cutover forward and strengthens cross-resource isolation for
> consent, authorization codes, refresh families, stored grants, and machine
> credentials. It also adds bounded Hono OAuth request bodies, revocation
> admission limiting, hardened persistent SQLite opening and JSONL audit-file
> handling, corrected CIMD JSON media-type and shared-cache behavior, and the
> complete shipped-feature release matrix in `docs/verification.md`. Registry
> and tag evidence belongs in the release and verification receipts.
>
> The §17 feature contracts are locked; CIMD §17.1, generic OIDC, and the
> Google preset are implemented. Google has reproducible
> historical live verification; CIMD was live-verified through exact runtime
> commit `af2a61f` with Cloudflare Access, Entra ID, and Google on 2026-07-28.
> A second, non-Google generic-OIDC issuer remains pending. Device flow §17.3 and the
> dedicated GitHub port in §17.6 remain contract-only. Spec conformance target:
> **MCP Authorization 2025-11-25**. The official stable
> [`2026-07-28`](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28)
> artifact was manually re-verified on 2026-08-02. Its DCR deprecation and
> client-side DCR `application_type` requirement align with the v0.3.2
> registration surface. Final conformance remains pending on three known items:
> redirected authorization errors omit RFC 9207 `iss` while metadata advertises
> support; `requireScope` performs exact membership rather than accounting for
> scope hierarchies; and the final artifact's referenced CIMD draft `-00` is now
> completely mapped. D00-4.1.4 now restricts alternate JSON media types to the
> `application/` tree; shared-cache handling is conformant, while one confirmed
> runtime mismatch remains (D00-4.5.2, the native-app precondition on the
> loopback port exception), plus four unresolved
> test-evidence rows. See the matrix in
> [§16.1](contracts/16-spec-conformance-matrix.md#161-cimd-draft--00-requirement-matrix)
> and the completed release checklist in
> [`docs/verification.md` — "Spec-release re-verification (completed
> 2026-08-02)"](verification.md#spec-release-re-verification-completed-2026-08-02).

## Contents

Read this index by task; open the numbered file only when you need its exact
contract:

| You are changing… | Start here |
| --- | --- |
| Boot configuration or a public port | [§5 Configuration](contracts/05-configuration-contract.md), then [§6 Ports](contracts/06-ports.md) |
| Browser authorization, consent, or token exchange | [§9 Bridge](contracts/09-as-lite-bridge-contract.md), [§7 Tokens](contracts/07-crypto-and-token-contracts.md), then [§10 Redirects](contracts/10-redirect-uri-policy.md) |
| Resource-server authentication | [§8 Verifier](contracts/08-resource-server-verifier-contract.md) and [§11 Scopes](contracts/11-scope-contract.md) |
| Durable state or audit | [§12 Stores](contracts/12-store-conformance-contract.md) and [§13 Audit](contracts/13-audit-contract.md) |
| MCP-version claims | [§16 Conformance matrix](contracts/16-spec-conformance-matrix.md) |
| A v0.2 or v0.3 feature | [§17 Feature contracts](contracts/17-v0-2-feature-contracts.md) |

This is one contract set, not 18 independent specifications. The index owns
status and routing; each numbered file owns the exact rules for its section.

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
