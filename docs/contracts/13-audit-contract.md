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

`oauth.revoke` distinguishes an admitted RFC 7009 no-op from an unexpected
revocation failure without changing either token-existence outcome. An unknown
token emits
`status: "success", reason: "unrecognized_token"`; a known token, including an
idempotent re-revocation, emits success without that reason. The adapter returns
200 in both cases. A store lookup or family-revocation failure emits
`status: "failure", reason: "internal_error"` before a `PortFailureError` is
thrown in the original's place, for the adapter's existing sanitized §9.5
mapping. **The value a pluggable port threw is never re-thrown and never
selects the public response.** A store is caller-supplied code, and `OAuthError`
is a published export, so a store returning an `OAuthError`-shaped failure would
otherwise pass `asOAuth` verbatim and its status/message would answer the
request — breaking RFC 7009's always-200 rule and making the store's internal
text an oracle on token existence. The re-cast happens at every
public-response-owning pluggable-port call site (`callPort`), never at the
use-case catch, because the library's own
`invalid_grant`/`invalid_client`/`invalid_consent` MUST still reach the client.
The original is carried on `PortFailureError.cause` for local logging only.
For response-owning returned data, the boundary includes selected property and
array-slot reads, not only the awaited method call. Identity results,
redirect-identity results, authorization-code records, refresh-token records,
stored-grant scope arrays, and the upstream consent-JTI boolean are projected or
type-checked into library-owned values inside `callPort`; an accessor or Proxy
trap that throws is therefore re-cast before a later OAuth mapper or audit
classifier can observe it. Plain malformed
store records fail closed through the existing library-owned grant errors.
Stored-DCR registration and machine-client rows retain their dedicated
read-once parsers from §6.4. A stored-DCR `ClientStore.save` outage is audited
as `internal_error`, never misattributed to invalid client metadata.

**Two ports state their specialized boundary explicitly.** A `ClockPort` whose
`nowMs()` throws is re-cast to the same
`RangeError` an out-of-range value produces, so "the clock is unusable" has ONE
failure shape whatever the port did (§6.1). Every underlying clock read uses
that boundary; no direct read remains in a use-case, resolver, identity adapter,
or audit formatter where a port-authored `OAuthError` could select the response.
An `IdentityPort` that throws an `OAuthError` may preserve only an exact 401 or
403 status. The Bridge fixes the OAuth code to `access_denied`, the description
to `Identity rejected: port_error`, and the audit reason to `port_error`; any
port-supplied redirect is dropped. OAuth classification and the status read are
snapshotted inside `callPort`; the Bridge never re-reads the caller-owned thrown
object. An unreadable status and every other status use the generic 500 response;
a safely classified OAuth throw retains the fixed `port_error` audit reason,
while a non-OAuth throw audits `internal_error`. A returned `{ ok: false, reason }`
is the normal shipped rejection path: exact shipped reason codes are allowlisted
for audit, every unknown custom reason becomes `identity_rejected`, and the
public description is the fixed `Identity rejected`. Thus a custom port
cannot turn identity rejection into HTTP 200, invent a public OAuth code, or
write an arbitrary thrown code into audit. Neither event
contains the token, its hash, a family identifier, or the thrown value. A
limiter denial or adapter/body rejection that never enters the revocation
use-case emits no `oauth.revoke` event.

The redirect sibling applies the same ownership rule. A throw or malformed
return from `buildAuthorizationUrl` cannot select the direct OAuth response;
the orchestrator returns its fixed generic 500. `exchangeAndVerify` calls and
their selected returned fields are contained inside the port boundary, while
the existing callback contract maps every failure to fixed `exchange_failed`
or `identity_rejected` channels. Returned identity-rejection reasons use the
same shipped-code allowlist as `IdentityPort.verify`; unknown custom text never
becomes audit data.

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
instance rather than append another record to the fragment. That permanent
transition is an operator-visible state, not an ordinary per-event write error:

```ts
type JsonlFileAuditDisableReason = "partial_write_rollback_unverified";
interface JsonlFileAuditOptions {
  onDisable?: (reason: JsonlFileAuditDisableReason) => void | Promise<void>;
}
```

`JsonlFileAudit(filePath, options?)` and `createJsonlFileAudit(filePath,
options?)` emit the fixed stderr diagnostic `[mcp-sso] audit jsonl disabled:
partial_write_rollback_unverified` exactly once when that instance first
disables appends, and invoke the snapshotted `onDisable` callback exactly once
with the same closed reason. Neither signal includes the path, event, fragment,
or thrown error. The callback is scheduled on a detached `setImmediate` turn
after `writeAuthEvent` can settle, so synchronous work before an async callback's
first `await` is not on the authentication promise path. A callback throw or
returned rejection is contained and is not retried; callback work cannot reject
`writeAuthEvent`, delay authentication, or re-enable the sink. Ordinary write failures and a
partial write whose tail is successfully rolled back do not invoke the hook.
Later calls return fail-open without more file work or duplicate disable
signals. A supplied options value must be a non-null, non-array object, and a
supplied `onDisable` must be a function; malformed values fail at construction
before any filesystem work.

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
