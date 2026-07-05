# Audit deployment guide

This is the deployer-facing guide for the **reference audit sinks** shipped in
v0.2 (contracts §17.7, §13; threat-model row 24). The library *emits* structured
metadata-only events; how they reach long-term storage, get indexed, and meet a
retention/compliance target is **the deployer's job**. This document lays out the
three supported paths and the honest delivery guarantees.

> **tl;dr** — for any deployment that needs the events to survive, run
> [`JsonlFileAudit`](./contracts.md#177-audit-reference-sinks--event-coverage) to a local file and ship it with
> a log shipper (Splunk Universal Forwarder, Vector, Fluentd). That is the only
> path that is durable on disk; the shipper owns retry, buffering, and indexing.

## The three options

| Path | Delivery | Durability | When to use |
|---|---|---|---|
| **`JsonlFileAudit` + a log shipper** (recommended) | The file is durable on disk the moment `appendFile` returns; the shipper delivers to your indexer with its own retry/buffer. | **Durable** (disk) | Production. The shipper (Splunk Universal Forwarder, Vector, Fluentd) absorbs sink outages, retries, and indexes — exactly the layer that should own those concerns. |
| **`WebhookAudit` → a SIEM HEC** | **At-most-once.** One POST per event; **no retry, no buffering, no backgrounding.** A 5xx, a timeout, or a network blip loses the event. | Best-effort | Low-volume or loss-tolerant flows; side-channels into Splunk/Elastic HEC where dropping a few events under outage is acceptable. |
| **Custom `AuditPort`** | Whatever you implement. | Whatever you implement. | When you need batching, a durable queue (Kafka/SQS), custom retry, or a non-JSONL/non-HTTP shape (e.g. directly to OpenSearch). |

### 1. `JsonlFileAudit` + a log shipper (recommended)

`JsonlFileAudit(path)` writes one `JSON.stringify`'d event per line, appends with
`O_APPEND` (kernel-atomic for the small lines we emit), and creates the file
`0600`. JSON encoding escapes `\n`/`\r`, so a hostile `reason` can never start a
new line — the file is **log-injection-safe by construction**. The library does
**not** rotate the file; point your shipper at it and let the shipper rotate.

```ts
import { Bridge, RequestAuthorizer } from "mcp-sso";
import { JsonlFileAudit } from "mcp-sso";

const audit = new JsonlFileAudit("/var/log/mcp-sso/audit.jsonl");
const bridge = new Bridge({ config, store, clock, audit });
const authorizer = new RequestAuthorizer({ config, clock, audit });
```

Shippers known to work well with append-only JSONL:

- **Splunk Universal Forwarder** — add a `monitor` input on the file; it tracks
  the offset and ships to the indexer. Splunk recommends this over HEC for
  high-volume local files precisely because the UF buffers and retries locally.
- **Vector** (`file` source → your sink) — durable, in-process buffering with
  `disk` buffers; handles rotation (inode follow) and backpressure.
- **Fluentd** (`in_tail`) — the long-standing choice; `pos_file` tracks offset,
  `read_from_head` on first run.

### 2. `WebhookAudit` → a SIEM HEC

```ts
import { WebhookAudit } from "mcp-sso";

const webhook = new WebhookAudit("https://siem.example.com/services/collector", {
  headers: { Authorization: `Bearer ${process.env.SIEM_HEC_TOKEN}` },
  // timeoutMs defaults to 5000; fetchImpl is a test-only DI seam (defaults to global fetch).
});
```

The URL must be `https://` (raw prefix check at construction); URLs with userinfo
(`user:pass@`) are rejected — credentials belong in `headers`. Redirects are not
followed (`redirect: "manual"`); a single `POST` per event with a 5 s timeout
(`AbortSignal.timeout`). **At-most-once**: a non-2xx, a timeout, or a thrown
`fetch` loses that event — there is no retry queue. Use this for side-channels
where loss is tolerable, or fan it out *alongside* the file sink via `combineAudit`
so the file remains the source of truth.

### 3. Custom `AuditPort`

```ts
import type { AuditPort, AuthAuditEvent } from "mcp-sso";

class QueuedAudit implements AuditPort {
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> {
    // push to Kafka / SQS / your durable queue; own batching + retry here.
  }
}
```

The `AuditPort` interface is a single async method. If you need guaranteed
delivery, this is where to wire a durable queue — the library will not do it for
you (see below).

## Delivery guarantees — what the library does NOT do

The library treats audit as **evidence, not a gate**. Concretely:

- **No buffering, no backgrounding, no redelivery.** Each sink's `writeAuthEvent`
  is awaited inline by the use-case (verifier, register, authorize, token,
  pairing). There is no queue, no retry loop, no dead-letter.
- **Fail-open.** A sink that rejects (disk full, HEC 5xx, network down) **must
  not** block the auth operation — every shipped sink swallows its own errors and
  surfaces a redacted diagnostic on stderr (`src/audit/util.ts` scrubs
  bearer tokens, `key=value` assignments, ≥32-char opaque runs, and configured
  header/URL-query values before anything reaches stderr). **This means events
  CAN be lost under sink outage** — that is the accepted residual
  (threat-model row 24). A failed `WebhookAudit` POST is gone; a failed
  `JsonlFileAudit` append is gone (the next event still appends once the FS
  recovers).
- **Implication:** if your compliance posture requires *no* lost events, the
  file + shipper path is the only supported answer — the file is durable on disk
  before the shipper is involved, and the shipper is the component designed to
  absorb indexer outages.

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

`combineAudit` wraps each sink call so a *synchronous* throw (an `undefined`
sink, a custom sink that throws before returning a promise) is converted to a
rejected promise that `Promise.allSettled` absorbs — the composite never rejects
and the other sinks still run.

## Defaults

- **`noopAudit` is the default at the composition root** — the example's
  `buildApp()` and `createConsolePairingIdentity()` default to it. `Bridge` and
  `RequestAuthorizer` **require `audit` explicitly** (`BridgeDeps.audit` /
  `RequestAuthDeps.audit` are required, no fallback), so pass `noopAudit`
  yourself if you construct them directly. The use-cases `await` `writeAuthEvent`
  with no `try/catch`, so a sink that rejects would turn every IO hiccup into a
  500 — which is why every shipped sink is fail-open by construction.
- **The standalone `examples/fastify-sqlite` wires a `JsonlFileAudit`** to
  `${MCP_SSO_DIR}/audit.jsonl` so you can see events immediately on a zero-config
  boot. The example's `buildApp()` (the path the test suite drives) defaults to
  `noopAudit`; pass an `audit` dep to observe events in tests.

## What the events look like

Events are flat, metadata-only objects (contracts §13): `occurredAt`, `event`,
`status`, and optional `clientId` / `subject` / `resource` / `scopes` /
`redirectHost` / `reason` / `ip`. **No token values, no `Authorization` /
`Set-Cookie`, no request bodies, and (for the v0.2 console-pairing flow) never the
pairing code.** The test suite asserts this across every event name
(`test/audit-no-secrets.test.ts`) and across the live pairing flow
(`test/e2e-pairing.test.ts`).

## See also

- Contracts [§13 (audit contract)](./contracts.md#13-audit-contract) and
  [§17.7 (reference sinks + event coverage)](./contracts.md#177-audit-reference-sinks--event-coverage).
- [Threat model row 24](./threat-model.md) (audit-sink loss / injection).
- The README's [audit bullet](../README.md) for the one-paragraph positioning.
