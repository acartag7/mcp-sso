# Contracts

> **Contract-first.** This index and its numbered files are the source of truth for every port, schema,
> endpoint, token claim, and error shape in `mcp-sso`. The contract set is written and
> reviewed **before** implementation code, and it MUST be updated before any change
> to a port, schema, or error shape. `docs/threat-model.md` reasons about this
> surface; `docs/dependency-ledger.md` records the pins. If code and the contract set
> disagree, the contract set wins until one of them is deliberately changed.
>
> Status: **v0.3.2**. This release is based on exact merged implementation commit
> `526ad2a2f1167ba7d905cb05cd3c44ce3a2c1d99`. It carries v0.3.1 forward and
> generation-binds stored-DCR authorization codes, refresh families, and refresh
> tokens through `OAuthAuthorizationUseCase.approve`, the atomic
> `consumeAuthCode` and `rotateRefreshToken` store operations, and
> `OAuthTokenUseCase`. `assertStoredDcrGenerationStore` rejects stored-mode
> construction when a custom store lacks the generation capability. Registry
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
> scope hierarchies; and the final artifact's referenced CIMD draft `-00` still
> needs a complete requirement-to-source/test mapping. See the completed evidence
> checklist and follow-up in
> [`docs/verification.md` — "Spec-release re-verification (completed
> 2026-08-02)"](verification.md#spec-release-re-verification-completed-2026-08-02).

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
