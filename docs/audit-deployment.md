# Audit deployment guide

The library **emits** structured, metadata-only audit events
([§13](./contracts.md#13-audit-contract)); getting them to long-term storage,
indexed, and retained is **your job**. This guide picks the path and states the
delivery guarantees honestly.

> **tl;dr** — for any deployment where events must survive, run
> [`JsonlFileAudit`](./contracts.md#177-audit-reference-sinks--event-coverage)
> to a local file and ship it with a log shipper (Splunk Universal Forwarder,
> Vector, Fluentd). It is the only path durable on disk; the shipper owns retry,
> buffering, and indexing.

## Three options

| Path | Delivery | Durability | When |
|---|---|---|---|
| **`JsonlFileAudit` + a log shipper** (recommended) | Durable on disk the moment `appendFile` returns; the shipper delivers to your indexer with its own retry/buffer. | **Durable** (disk) | Production. The shipper absorbs sink outages, retries, and indexing — the layer that should own those concerns. |
| **`WebhookAudit` → a SIEM HEC** | **At-most-once.** One POST per event. No retry, no buffering, no backgrounding. | Best-effort | Low-volume or loss-tolerant flows; a side-channel into Splunk/Elastic HEC where dropping events under outage is acceptable. |
| **Custom `AuditPort`** | Whatever you implement. | Whatever you implement. | When you need batching, a durable queue (Kafka/SQS), custom retry, or a non-JSONL/non-HTTP shape (e.g. OpenSearch directly). |

### 1. `JsonlFileAudit` + a log shipper (recommended)

```ts
import { Bridge, RequestAuthorizer, JsonlFileAudit } from "mcp-sso";

const audit = new JsonlFileAudit("/var/log/mcp-sso/audit.jsonl");
const bridge = new Bridge({ config, store, clock, audit });
const authorizer = new RequestAuthorizer({ config, clock, audit });
```

The sink creates the file `0600` and appends one JSON line per event with
`O_APPEND` (kernel-atomic for the small lines we emit). JSON encoding escapes
`\n`/`\r`, so a hostile `reason` can never start a new line. The file is
**log-injection-safe by construction**. The library does **not** rotate it —
point your shipper at the file and let the shipper rotate. (Mechanism details:
[§17.7](./contracts.md#177-audit-reference-sinks--event-coverage).)

Shippers that work well with append-only JSONL:

- **Splunk Universal Forwarder** — `monitor` input on the file; it tracks the
  offset and ships to the indexer. Splunk recommends this over HEC for
  high-volume local files because the UF buffers and retries locally.
- **Vector** (`file` source → your sink) — in-process `disk` buffers; handles
  rotation (inode follow) and backpressure.
- **Fluentd** (`in_tail`) — `pos_file` tracks offset, `read_from_head` on first
  run.

### 2. `WebhookAudit` → a SIEM HEC

```ts
import { WebhookAudit } from "mcp-sso";

const webhook = new WebhookAudit("https://siem.example.com/services/collector", {
  headers: { Authorization: `Bearer ${process.env.SIEM_HEC_TOKEN}` },
});
```

Delivery is **at-most-once** — a single `POST` per event with a 5 s timeout, and
no retry queue. A non-2xx, a timeout, or a thrown `fetch` loses that event.
Sink construction enforces:

- The URL must be `https://` (raw prefix check).
- URLs with userinfo (`user:pass@`) are rejected — credentials belong in
  `headers`.
- Redirects are not followed.

Use this for side-channels where loss is tolerable, or fan it out alongside the
file sink via `combineAudit` so the file stays the source of truth.

### 3. Custom `AuditPort`

```ts
import type { AuditPort, AuthAuditEvent } from "mcp-sso";

class QueuedAudit implements AuditPort {
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> {
    // push to Kafka / SQS / your durable queue; own batching + retry here.
  }
}
```

The interface is a single async method. This is where to wire guaranteed
delivery via a durable queue — the library will not do it for you (see below).

## Delivery guarantees — what the library does NOT do

The library treats audit as **evidence, not a gate**.

- **No buffering, no backgrounding, no redelivery.** Each sink's
  `writeAuthEvent` is awaited inline by the use-case (verifier, register,
  authorize, token, pairing). There is no queue, no retry loop, no dead-letter.
- **Fail-open.** A sink that rejects (disk full, HEC 5xx, network down) must
  not block the auth operation. Every shipped sink swallows its own errors and
  surfaces a redacted diagnostic on stderr.
  - What is redacted: `src/audit/util.ts` scrubs bearer tokens, `key=value`
    assignments, ≥32-char opaque runs, and configured header/URL-query values
    before anything reaches stderr.
- **Events CAN be lost under sink outage** — that is the accepted residual
  ([threat-model row 24](./threat-model.md)). A failed `WebhookAudit` POST is
  gone; a failed `JsonlFileAudit` append is gone (the next event still appends
  once the filesystem recovers).
- **If your compliance posture requires no lost events**, the file + shipper
  path is the only supported answer. The file is durable on disk before the
  shipper is involved, and the shipper is the component designed to absorb
  indexer outages.

## Fan-out with `combineAudit`

Wire multiple sinks; one sink's failure never stops the others:

```ts
import { combineAudit, JsonlFileAudit, WebhookAudit } from "mcp-sso";

const audit = combineAudit(
  new JsonlFileAudit("/var/log/mcp-sso/audit.jsonl"), // source of truth (durable)
  new WebhookAudit("https://siem.example.com/services/collector", {
    headers: { Authorization: `Bearer ${process.env.SIEM_HEC_TOKEN}` },
  }), // side-channel (at-most-once)
);

const bridge = new Bridge({ config, store, clock, audit });
const authorizer = new RequestAuthorizer({ config, clock, audit });
```

`combineAudit` runs each sink through `Promise.allSettled`. A synchronous throw
(an `undefined` sink, or a custom sink that throws before returning a promise)
becomes a rejected promise that `allSettled` absorbs. The composite never
rejects; the other sinks still run.

## Defaults

- **`noopAudit` is the default at the composition root** — the example's
  `buildApp()` and `createConsolePairingIdentity()` default to it.
- **`Bridge` and `RequestAuthorizer` require `audit` explicitly** —
  `BridgeDeps.audit` / `RequestAuthDeps.audit` are required, with no fallback.
  If you construct them directly, pass `noopAudit` yourself.
- **The use-cases `await` `writeAuthEvent` with no `try/catch`.** A sink that
  rejects would turn every IO hiccup into a 500 — which is why every shipped
  sink is fail-open by construction.
- **`examples/fastify-sqlite` wires a `JsonlFileAudit`** to
  `${MCP_SSO_DIR}/audit.jsonl`, so events appear on a zero-config boot. The
  example's `buildApp()` (the path the test suite drives) still defaults to
  `noopAudit`; pass an `audit` dep to observe events in tests.

## What the events look like

Flat, metadata-only objects ([§13](./contracts.md#13-audit-contract)):
`occurredAt`, `event`, `status`, plus optional `clientId` / `subject` /
`resource` / `scopes` / `redirectHost` / `reason` / `ip`. No token values, no
`Authorization` / `Set-Cookie`, no request bodies, and never the console-pairing
code. The test suite asserts this across every event name
(`test/audit-no-secrets.test.ts`) and the live pairing flow
(`test/e2e-pairing.test.ts`).

## See also

- Contracts [§13 (audit contract)](./contracts.md#13-audit-contract) and
  [§17.7 (reference sinks + event coverage)](./contracts.md#177-audit-reference-sinks--event-coverage).
- [Threat model row 24](./threat-model.md) — audit-sink loss / injection.
- The README [audit bullet](../README.md) for one-paragraph positioning.
