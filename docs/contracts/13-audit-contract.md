# 13. Audit contract

Append-only `AuthAuditEvent`s, **metadata-only**. No token values, no
`Authorization`/`Set-Cookie`, no request bodies; redirect URIs canonicalized to
host. Events (the v0.1 set plus the v0.2 additions from §17.7): `oauth.register`,
`oauth.authorize.prepare`, `oauth.authorize.approve`, `oauth.token.authorization_code`,
`oauth.token.refresh`, `oauth.revoke`, `auth.request`, `identity.verify`,
`oauth.pairing.attempt`, `oauth.device.authorization`, `oauth.device.approve`,
`oauth.token.device_code`, `oauth.token.client_credentials`, `oauth.client.provision`,
`oauth.client.rotate_secret`, `oauth.client.disable`, `oauth.cimd.fetch`, and (§17.11, lands with the
upstream-redirect implementation) `oauth.upstream.callback`. Each carries `occurredAt`,
`event`, `status: "success"|"failure"`, and optional `clientId`, `subject`,
`resource`, `scopes`, `redirectHost`, `reason`, `ip` (adapter-populated client IP;
personal data — the deployer owns retention/redaction). The test suite asserts
that serialized audit output never contains raw codes, refresh tokens, or access
tokens, across every event name (the v0.2 names are exercised by synthetic
events through each sink; the v0.1 names additionally by the live OAuth flow).

**0.4.0 amendment (PENDING — NOT ENFORCED at this commit).** The following
events carry the selected canonical `resource` whenever they are emitted:
`oauth.authorize.prepare`, `oauth.authorize.approve`,
`oauth.token.authorization_code`, `oauth.token.refresh`, `oauth.revoke`,
`auth.request`, `oauth.token.client_credentials`, `oauth.client.provision`,
`oauth.client.rotate_secret`, and `oauth.client.disable`.
`oauth.upstream.callback` carries it only after a flow cookie has been verified
and its resource resolved; failures before that boundary omit it. Registration,
identity verification, pairing, and CIMD-fetch events are not grant-resource
events and do not gain a synthetic resource. When the contract-only §17.3
device grant is implemented, `oauth.device.authorization`,
`oauth.device.approve`, and `oauth.token.device_code` carry the record's
selected resource under the same rule. The field remains metadata, never a
token value or request-selected unvalidated string.

The reference sinks satisfy the fail-open port contract: their
`writeAuthEvent` methods do not reject, and `combineAudit` isolates sibling
sinks. `OAuthTokenUseCase` additionally calls every token/revocation audit
through `writeTokenAudit`, which contains both synchronous throws and rejected
promises from a nonconforming custom `AuditPort`. This is a token-boundary
guarantee, not a claim that every use-case repairs arbitrary custom ports.

Machine-client lifecycle success evidence is the exception to the general
fail-open posture. `MachineClientStore.createMachineClient` and
`compareAndSwapMachineClient` receive a metadata-only
`MachineClientMutationAudit` and MUST commit it in the same backend transaction
as the credential row, or commit neither (§6.4, §17.2). The ordinary
`AuditPort` success event is a best-effort fan-out copy after that transaction;
its failure cannot suppress a one-time secret that already has durable
evidence. Failure events remain best-effort because no credential mutation was
committed.
