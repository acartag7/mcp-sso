# 13. Audit contract

Append-only `AuthAuditEvent`s, **metadata-only**. No token values, no
`Authorization`/`Set-Cookie`, no request bodies; redirect URIs canonicalized to
host. Events (the v0.1 set plus the v0.2 additions from §17.7): `oauth.register`,
`oauth.authorize.prepare`, `oauth.authorize.approve`, `oauth.token.authorization_code`,
`oauth.token.refresh`, `oauth.revoke`, `auth.request`, `identity.verify`,
`oauth.pairing.attempt`, `oauth.device.authorization`, `oauth.device.approve`,
`oauth.token.device_code`, `oauth.token.client_credentials`, `oauth.client.provision`,
`oauth.client.rotate_secret`, `oauth.cimd.fetch`, and (§17.11, lands with the
upstream-redirect implementation) `oauth.upstream.callback`. Each carries `occurredAt`,
`event`, `status: "success"|"failure"`, and optional `clientId`, `subject`,
`resource`, `scopes`, `redirectHost`, `reason`, `ip` (adapter-populated client IP;
personal data — the deployer owns retention/redaction). The test suite asserts
that serialized audit output never contains raw codes, refresh tokens, or access
tokens, across every event name (the v0.2 names are exercised by synthetic
events through each sink; the v0.1 names additionally by the live OAuth flow).
