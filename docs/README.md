# Documentation

Use the first list when you know what you want to do. Use the second when you want a page of a particular kind. Every file has one job: a tutorial teaches by doing, a how-to gets one task done, a reference states facts for lookup, an explanation says why, and the archive keeps dated history.

## I want to

- See it work on my machine: [Get started](getting-started.md) (tutorial, local path).
- Put it in front of my MCP server for real users: [Get started, identity-provider path](getting-started.md#run-the-identity-provider-tutorial) (tutorial), then [Configuration](configuration.md) (reference) and [Configure an identity provider](identity/README.md) (how-to).
- Let Claude Code, Codex CLI, or another MCP client register: [Configure client registration](client-registration.md) (how-to) and [Client registration choices](explanation/client-registration-choices.md) (explanation).
- Give a CI job or a service its own credential: [Provision a machine client](machine-clients.md) (how-to).
- Put SSO in front of a backend that only takes an API key: [Deploy an API-key gateway](gateway-deployment.md) (how-to).
- Know what to set behind a reverse proxy or with several replicas: [Rate limits and client IP trust](explanation/rate-limits-and-client-ip.md) (explanation), then [Configuration](configuration.md).
- Keep an audit trail: [Deploy an audit sink](audit-deployment.md) (how-to).
- Review the security posture: [Threat model](threat-model.md), [Conformance matrix](contracts/16-spec-conformance-matrix.md), [Verification status](verification-status.md), [Client compatibility](client-compatibility.md), and [Dependency ledger](dependency-ledger.md) (all reference).
- Understand why a rule exists: the explanation pages listed below.
- Change a port, schema, or error shape: [Contracts](contracts.md) (reference), starting with its change-routing table.
- Cut a release: [Prepare a release](release-checklist.md) (how-to) and [Release verification requirements](verification.md) (reference).
- Fix something that is not working: [Troubleshoot a deployment](troubleshooting.md) (how-to).
- Find an older result: the [archive](archive/README.md).

## By kind

### Tutorials

- [Get started](getting-started.md): run a local server or configure the repository example with an identity provider.

### How-to guides

- [Configure client registration](client-registration.md)
- [Provision a machine client](machine-clients.md)
- [Deploy an API-key gateway](gateway-deployment.md)
- [Deploy an audit sink](audit-deployment.md)
- [Configure an identity provider](identity/README.md)
- [Run live client verification](live-verification.md)
- [Prepare a release](release-checklist.md)
- [Troubleshoot a deployment](troubleshooting.md)

### Reference

- [Capabilities and deployment limits](reference/capabilities.md)
- [Environment variables](configuration.md)
- [Contracts](contracts.md)
- [Threat model](threat-model.md)
- [Dependency ledger](dependency-ledger.md)
- [Current verification status](verification-status.md)
- [Client compatibility](client-compatibility.md)
- [Live verification harness](reference/live-harness.md)
- [Release verification requirements](verification.md)
- [Tier 3 evidence fields](verification-live.md)

### Explanation

- [OAuth roles and flow](explanation/oauth-roles-and-flow.md)
- [Client registration choices](explanation/client-registration-choices.md)
- [CIMD fetch safety](explanation/cimd-fetch-safety.md)
- [Rate limits and client IP trust](explanation/rate-limits-and-client-ip.md)
- [Redirect URI trust](explanation/redirect-uri-trust.md)
- [Authorization model](authorization.md)
- [Verification design](verification-design.md)
- [Rate-limit outage policy](rate-limit-outage-policy.md)
- [Live verification infrastructure](explanation/live-verification-infrastructure.md)

### Archive

- [Archive index](archive/README.md)
- [Verification history](archive/verification-history.md)
- [Client compatibility, July to August 2026](archive/client-compatibility-2026-07.md)
- [2026-07-08 API-key gateway field report](archive/2026-07-08-api-key-gateway-field-report.md)
- [2026-08-17 redirect-entry grammar implementation record](archive/2026-08-17-redirect-entry-grammar.md)
- [Internal test catalog through 2026-08-21](archive/internal-test-catalog-2026-08-21.md)
- [Contract corrections from 2026-07-07 through 2026-08-19](archive/contract-corrections-2026-07-07-to-2026-08-19.md)
- [Contract development history from 2026-07 through 2026-08](archive/contract-development-history-2026-07-to-2026-08.md)

For agents and tools: the root [`llms.txt`](../llms.txt) lists every page with its kind in one line each, and [`AGENTS.md`](../AGENTS.md) holds the rules for changing this repository.
