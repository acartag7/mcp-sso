# Contracts

> **Contract-first.** This index and its numbered files are the source of truth for every port, schema,
> endpoint, token claim, and error shape in `mcp-sso`. The contract set is written and
> reviewed **before** implementation code, and it MUST be updated before any change
> to a port, schema, or error shape. `docs/threat-model.md` reasons about this
> surface; `docs/dependency-ledger.md` records the pins. If code and the contract set
> disagree, the contract set wins until one of them is deliberately changed.

## Change routing

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

Current release and conformance status: [verification status](verification-status.md).

## Numbered contracts

This is one contract set, not 18 independent specifications. The index owns
routing; each numbered file owns the exact rules for its section.

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
