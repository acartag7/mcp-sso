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

The reference sinks satisfy the fail-open port contract: their
`writeAuthEvent` methods do not reject, and `combineAudit` isolates sibling
sinks. Every non-transactional use-case audit passes through
`writeAuditBestEffort` (directly or through a named wrapper), which contains
both synchronous throws and rejected promises from a nonconforming custom
`AuditPort`. Audit-sink failure therefore cannot replace an authoritative OAuth
or resource-server outcome. Machine-client lifecycle success evidence remains
the durable transactional exception described below; its ordinary `AuditPort`
fan-out copy is still best effort.

`WebhookAudit` treats every non-empty deployer-configured header value and
every non-empty query component as a secret regardless of length. A transport
diagnostic that reflects one of those exact values is scrubbed before the
diagnostic is reduced to one bounded, control-free stderr line. This includes
ordinary `key=value` parameters, values reflected without their key, and bare
query components. Redaction and formatting are total: synchronous transport
throws, rejected transport promises, and hostile thrown values cannot make the
reference sink reject.

`JsonlFileAudit` is a filesystem boundary as well as an evidence sink. On a
host where Node exposes `O_NOFOLLOW`, every event opens the configured final
path with `O_APPEND | O_CREAT | O_NONBLOCK | O_NOFOLLOW`, validates the opened
descriptor with `fstat().isFile()`, and writes the complete UTF-8 JSONL line
through that same descriptor before closing it. A symlink (including a dangling
one), FIFO, socket, device, or directory therefore receives no event bytes; a
rename-and-recreate log rotation is picked up by the next event. The sink still
fails open: a rejected target or failed write emits a redacted diagnostic and
does not reject the authentication operation. Where `O_NOFOLLOW` is unavailable,
the reference sink writes no event and emits a fixed diagnostic; it MUST NOT
substitute an `lstat`-then-open sequence that could follow a swapped symlink.
Concurrent calls to one `JsonlFileAudit` instance are serialized through that
descriptor-bound operation, so a short OS write cannot splice two of that
instance's JSONL records together. This is not an interprocess file lock:
separate sink instances or processes writing the same path remain outside this
reference sink's framing guarantee and require a deployer-selected single
writer or coordination mechanism. If a retry fails after appending a positive
prefix, the sink truncates only that verified descriptor tail; if the descriptor
changed and rollback cannot be verified, it drops later events from that
instance rather than append another record to the fragment.

This contract deliberately does not reject hard-linked regular files. A hard
link is indistinguishable from a normal regular audit file at this boundary, and
a link-count policy would change rotation and existing-file compatibility. A
deployer MUST keep the audit file's parent from untrusted writers and rely on
the host's hard-link protections; a stronger hard-link policy needs a separate
contract decision.

Machine-client lifecycle success evidence is the exception to the general
fail-open posture. `MachineClientStore.createMachineClient` and
`compareAndSwapMachineClient` receive a metadata-only
`MachineClientMutationAudit` and MUST commit it in the same backend transaction
as the credential row, or commit neither (§6.4, §17.2). The ordinary
`AuditPort` success event is a best-effort fan-out copy after that transaction;
its failure cannot suppress a one-time secret that already has durable
evidence. Each lifecycle success record includes the exact stored machine-client
`resource` as well as its scopes, so the durable row and audit evidence describe
the same binding. Failure events remain best-effort because no credential
mutation was committed.
