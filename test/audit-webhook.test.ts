// WebhookAudit — proves the §17.7 contract: https-only (raw prefix check before
// URL parsing), redirects NOT followed (redirect:"manual"), at-most-once (no
// retry on any outcome), fail-open (never rejects), and a SIEM bearer token in
// `headers` never reaches stderr. A fetchImpl seam avoids TLS/https-server
// gymnastics (the codebase injects Redis/Pool clients the same way).

import assert from "node:assert/strict";
import { test } from "node:test";
import { WebhookAudit } from "../src/audit/webhook.ts";
import type { AuthAuditEvent } from "../src/ports/audit.ts";

const baseEvent: AuthAuditEvent = {
  occurredAt: "2026-07-05T12:00:00.000Z",
  event: "oauth.token.refresh",
  status: "success",
  clientId: "client-1",
  ip: "203.0.113.7",
};

/** Minimal stub of the global fetch: records the call and returns a controllable
 *  result. Typed loosely so tests can throw, time out, or return any status. */
interface Recorded {
  url: string;
  init: RequestInit;
}
function makeFetch(result: "ok" | "non2xx" | "redirect" | "throw" | "never", sink: { calls: Recorded[]; signal?: AbortSignal }): typeof fetch {
  return (async (url: any, init?: any) => {
    sink.calls.push({ url: String(url), init: init ?? {} });
    if (result === "throw") throw new Error("network down");
    if (result === "never") {
      return new Promise((_, reject) => {
        // Honor AbortSignal.timeout so the test's tiny timeoutMs resolves it.
        const sig = init?.signal as AbortSignal | undefined;
        if (sig) {
          if (sig.aborted) reject(sig.reason ?? new Error("aborted"));
          sig.addEventListener("abort", () => reject(sig.reason ?? new Error("aborted")), { once: true });
        }
      });
    }
    const status = result === "ok" ? 200 : result === "non2xx" ? 503 : 302;
    return {
      ok: status === 200,
      status,
      redirected: false,
    } as Response;
  }) as typeof fetch;
}

function captureConsoleError(): { messages: string[]; restore: () => void } {
  const original = console.error;
  const messages: string[] = [];
  console.error = (...args: unknown[]) => { messages.push(args.map(String).join(" ")); };
  return { messages, restore: () => { console.error = original; } };
}

test("WebhookAudit: constructor rejects non-https (raw prefix check BEFORE new URL)", () => {
  // The raw check fires before URL parsing; these must all throw at construction,
  // not slip through to the request path.
  for (const bad of ["http://siem.test", "ftp://siem.test", "HTTPS://siem.test", "https.txt", "//siem.test", "", "siem.test"]) {
    assert.throws(
      () => new WebhookAudit(bad as string, { fetchImpl: makeFetch("ok", { calls: [] }) }),
      /https/,
      `expected rejection for ${JSON.stringify(bad)}`,
    );
  }
});

test("WebhookAudit: constructor rejects a malformed https URL that fails new URL()", () => {
  assert.throws(() => new WebhookAudit("https://", { fetchImpl: makeFetch("ok", { calls: [] }) }), /valid absolute https/);
});

test("WebhookAudit: constructor rejects userinfo (user:pass@) — credentials belong in headers, not the URL", () => {
  // Node's fetch throws on userinfo with a TypeError whose message echoes the
  // full URL; if the URL reached the catch, the credentials would land in stderr
  // (and regex redaction cannot reliably catch short `user:pass@` values). Fail
  // closed at construction.
  const fetchImpl = makeFetch("ok", { calls: [] });
  for (const bad of [
    "https://user:pass@siem.test/ingest",
    "https://:pass@siem.test/ingest",
    "https://user@siem.test/ingest",
  ]) {
    assert.throws(
      () => new WebhookAudit(bad, { fetchImpl }),
      /userinfo/i,
      `expected userinfo rejection for ${bad}`,
    );
  }
});

test("WebhookAudit: constructor rejects malformed header configuration", () => {
  for (const headers of [null, [], { X: null }, { X: 1 }, "X: value"]) {
    assert.throws(
      () => new WebhookAudit("https://siem.test/ingest", { headers: headers as never }),
      /headers must be a string-valued object/,
    );
  }
});

test("WebhookAudit: per-event POST is application/json with merged headers", async () => {
  const state = { calls: [] as Recorded[] };
  const sink = new WebhookAudit("https://siem.test/ingest", {
    headers: { Authorization: "Bearer siem-secret-token" },
    fetchImpl: makeFetch("ok", state),
  });
  await sink.writeAuthEvent({ ...baseEvent });

  assert.equal(state.calls.length, 1);
  const init = state.calls[0]!.init;
  assert.equal(init.method, "POST");
  assert.equal(init.redirect, "manual"); // §17.7: redirects not followed
  const headers = new Headers(init.headers);
  assert.equal(headers.get("content-type"), "application/json");
  assert.equal(headers.get("authorization"), "Bearer siem-secret-token");
  assert.deepEqual(JSON.parse(init.body as string), { ...baseEvent });
});

test("WebhookAudit: at-most-once — no retry on non-2xx, and never rejects", async () => {
  const state = { calls: [] as Recorded[] };
  const sink = new WebhookAudit("https://siem.test/ingest", { fetchImpl: makeFetch("non2xx", state) });
  await assert.doesNotReject(() => sink.writeAuthEvent({ ...baseEvent }));
  assert.equal(state.calls.length, 1, "a 503 must NOT trigger a retry");
});

test("WebhookAudit: at-most-once — no retry on throw, and never rejects (fail-open)", async () => {
  const state = { calls: [] as Recorded[] };
  const sink = new WebhookAudit("https://siem.test/ingest", { fetchImpl: makeFetch("throw", state) });
  await assert.doesNotReject(() => sink.writeAuthEvent({ ...baseEvent }));
  assert.equal(state.calls.length, 1, "a network error must NOT trigger a retry");
});

test("WebhookAudit: timeout is honored and fail-open (AbortSignal.timeout fires, no retry)", async () => {
  const state = { calls: [] as Recorded[] };
  const sink = new WebhookAudit("https://siem.test/ingest", {
    timeoutMs: 5,
    fetchImpl: makeFetch("never", state),
  });
  await assert.doesNotReject(() => sink.writeAuthEvent({ ...baseEvent }));
  assert.equal(state.calls.length, 1, "a timeout must NOT trigger a retry");
});

test("WebhookAudit: a 3xx response is not followed (manual), and never rejects", async () => {
  const state = { calls: [] as Recorded[] };
  const sink = new WebhookAudit("https://siem.test/ingest", { fetchImpl: makeFetch("redirect", state) });
  await assert.doesNotReject(() => sink.writeAuthEvent({ ...baseEvent }));
  assert.equal(state.calls.length, 1, "a redirect must NOT be followed and must NOT be retried");
});

test("WebhookAudit: omitting fetchImpl binds the global fetch at construction", async () => {
  // Proves behaviorally that the default is globalThis.fetch (captured at
  // construction), not just that the constructor does not throw.
  const original = globalThis.fetch;
  let called = 0;
  globalThis.fetch = (async () => {
    called += 1;
    return { ok: true, status: 200, redirected: false } as Response;
  }) as typeof fetch;
  try {
    const sink = new WebhookAudit("https://siem.test/ingest"); // no fetchImpl
    await sink.writeAuthEvent({ ...baseEvent });
    assert.equal(called, 1, "the default fetchImpl (globalThis.fetch) was used");
  } finally {
    globalThis.fetch = original;
  }
});

test("WebhookAudit: failure-path stderr never contains the SIEM bearer token or payload", async () => {
  // The test header promises a SIEM bearer token in `headers` never reaches
  // stderr. Pin it: capture console.error through a failing write carrying a
  // secret header + a secret-bearing fetch error, and assert neither leaks.
  const siemToken = "Bearer siem-secret-DO-NOT-LEAK";
  const state = { calls: [] as Recorded[] };
  const sink = new WebhookAudit("https://siem.test/ingest", {
    headers: { Authorization: siemToken },
    fetchImpl: makeFetch("throw", state),
  });
  const secretEvent = { ...baseEvent, reason: "rt.LEAKED_REFRESH_TOKEN_VALUE" };

  const captured = captureConsoleError();
  try {
    await sink.writeAuthEvent(secretEvent); // throws inside -> fail-open
  } finally {
    captured.restore();
  }
  const stderr = captured.messages.join("\n");
  assert.equal(stderr.includes(siemToken), false, "SIEM bearer token leaked to stderr");
  assert.equal(stderr.includes("LEAKED_REFRESH_TOKEN_VALUE"), false, "payload leaked to stderr");
  assert.ok(stderr.length > 0, "a failure was actually surfaced on stderr");
});

test("WebhookAudit: non-2xx stderr never contains the SIEM bearer token or payload", async () => {
  const siemToken = "Bearer siem-secret-DO-NOT-LEAK";
  const state = { calls: [] as Recorded[] };
  const sink = new WebhookAudit("https://siem.test/ingest", {
    headers: { Authorization: siemToken },
    fetchImpl: makeFetch("non2xx", state),
  });
  const captured = captureConsoleError();
  try {
    await sink.writeAuthEvent({ ...baseEvent, reason: "rt.LEAKED_REFRESH_TOKEN_VALUE" });
  } finally {
    captured.restore();
  }
  const stderr = captured.messages.join("\n");
  assert.equal(stderr.includes(siemToken), false, "SIEM bearer token leaked to stderr on non-2xx");
  assert.equal(stderr.includes("LEAKED_REFRESH_TOKEN_VALUE"), false, "payload leaked to stderr on non-2xx");
  assert.ok(stderr.includes("503"), "the non-2xx status was surfaced");
});

test("WebhookAudit: a fetch error echoing secrets is redacted from stderr (diagnostic preserved)", async () => {
  // The transport may throw an Error whose message echoes request headers/body
  // (a custom fetchImpl, or a fetch variant). The sink must redact BOTH the
  // regex patterns (Bearer/long-opaque) AND the exact known header value
  // (header scrub), while keeping a benign diagnostic so the failure is visible.
  const siemToken = "Bearer siem-secret-DO-NOT-LEAK";
  const longToken = "rt_" + "x".repeat(48);
  const sink = new WebhookAudit("https://siem.test/ingest", {
    headers: { Authorization: siemToken },
    fetchImpl: (async () => {
      throw new Error(`upstream said: ${siemToken} ${longToken} details-more`);
    }) as typeof fetch,
  });
  const captured = captureConsoleError();
  try {
    await sink.writeAuthEvent({ ...baseEvent });
  } finally {
    captured.restore();
  }
  const stderr = captured.messages.join("\n");
  assert.equal(stderr.includes(siemToken), false, "SIEM bearer token (header value) leaked");
  assert.equal(stderr.includes("x".repeat(48)), false, "long opaque token leaked");
  assert.equal(stderr.includes(longToken), false, "long opaque token leaked (prefix form)");
  assert.ok(stderr.includes("upstream said"), "a benign diagnostic was preserved");
});

test("WebhookAudit: credential-bearing query string in the URL is scrubbed from stderr", async () => {
  // A query param can carry a credential (e.g. ?access_token=…). The regex
  // redactor does NOT catch `access_token=` (the `_` defeats the \b token
  // boundary), so the configured query value is scrubbed precisely here.
  const secretValue = "abcdef0123456789secretTOKEN";
  const sink = new WebhookAudit(`https://siem.test/ingest?access_token=${secretValue}`, {
    fetchImpl: (async () => {
      throw new Error(`TypeError: fetch failed for https://siem.test/ingest?access_token=${secretValue}`);
    }) as typeof fetch,
  });
  const captured = captureConsoleError();
  try {
    await sink.writeAuthEvent({ ...baseEvent });
  } finally {
    captured.restore();
  }
  const stderr = captured.messages.join("\n");
  assert.equal(stderr.includes(secretValue), false, "query-string credential leaked to stderr");
  assert.equal(stderr.includes("access_token=" + secretValue), false, "access_token pair leaked");
  assert.ok(stderr.length > 0, "the failure was still surfaced");
});

test("WebhookAudit: every configured secret is scrubbed regardless of length or query syntax", async () => {
  const cases = [
    { name: "short header in synchronous throw", url: "https://siem.test/ingest", headers: { "X-Hook-Key": "abc" }, secret: "abc", reflected: "header=abc", synchronous: true },
    { name: "long header in rejected promise", url: "https://siem.test/ingest", headers: { "X-Hook-Key": "configured-long-webhook-secret" }, secret: "configured-long-webhook-secret", reflected: "header=configured-long-webhook-secret", synchronous: false },
    { name: "short query value alone", url: "https://siem.test/ingest?k=xy", secret: "xy", reflected: "value xy", synchronous: false },
    { name: "short key=value pair", url: "https://siem.test/ingest?k=xy", secret: "k=xy", reflected: "pair k=xy", synchronous: false },
    { name: "short full query", url: "https://siem.test/ingest?k=xy", secret: "?k=xy", reflected: "query ?k=xy", synchronous: false },
    { name: "bare query component", url: "https://siem.test/ingest?hooksecret", secret: "hooksecret", reflected: "bare hooksecret", synchronous: false },
  ];
  for (const item of cases) {
    const failure = new Error(`transport reflected ${item.reflected}\nforged-line ${"x".repeat(240)}`);
    const fetchImpl = item.synchronous
      ? (() => { throw failure; }) as typeof fetch
      : (() => Promise.reject(failure)) as typeof fetch;
    const sink = new WebhookAudit(item.url, { headers: item.headers, fetchImpl });
    const captured = captureConsoleError();
    try {
      await assert.doesNotReject(() => sink.writeAuthEvent({ ...baseEvent }), item.name);
    } finally {
      captured.restore();
    }
    const stderr = captured.messages.join("\n");
    assert.equal(stderr.includes(item.secret), false, `${item.name}: configured secret leaked`);
    assert.equal(stderr.includes("\n"), false, `${item.name}: reflected newline survived`);
    assert.ok(stderr.length <= 280, `${item.name}: diagnostic was not bounded`);
  }
});

test("WebhookAudit: transport mutation cannot erase configured secrets from redaction", async () => {
  const captured = captureConsoleError();
  try {
    const sink = new WebhookAudit("https://siem.test/ingest", {
      headers: { "X-Hook-Key": "abc" },
      fetchImpl: (async (_url, init) => {
        (init?.headers as Record<string, string>)["X-Hook-Key"] = "changed";
        throw new Error("transport reflected abc");
      }) as typeof fetch,
    });
    await sink.writeAuthEvent({ ...baseEvent });
  } finally { captured.restore(); }
  const stderr = captured.messages.join("\n");
  assert.equal(stderr.includes("abc"), false);
  assert.match(stderr, /transport reflected/);
});

test("WebhookAudit: exact configured values redact before generic secret patterns", async () => {
  const secret = "prefix-token=abc-suffix";
  const captured = captureConsoleError();
  try {
    const sink = new WebhookAudit("https://siem.test/ingest", {
      headers: { "X-Hook-Key": secret },
      fetchImpl: (async () => { throw new Error(`transport reflected ${secret}`); }) as typeof fetch,
    });
    await sink.writeAuthEvent({ ...baseEvent });
  } finally { captured.restore(); }
  const stderr = captured.messages.join("\n");
  assert.equal(stderr.includes("prefix-"), false);
  assert.match(stderr, /transport reflected/);
});

test("WebhookAudit: raw plus-bearing query values redact when reflected alone", async () => {
  const captured = captureConsoleError();
  try {
    const sink = new WebhookAudit("https://siem.test/ingest?sig=ab+c", {
      fetchImpl: (async () => { throw new Error("transport reflected ab+c"); }) as typeof fetch,
    });
    await sink.writeAuthEvent({ ...baseEvent });
  } finally { captured.restore(); }
  const stderr = captured.messages.join("\n");
  assert.equal(stderr.includes("ab+c"), false);
  assert.match(stderr, /transport reflected/);
});

test("WebhookAudit: the diagnostic placeholder cannot reproduce a configured secret", async () => {
  for (const secret of ["redacted", "[redacted]", "act"]) {
    const captured = captureConsoleError();
    try {
      const sink = new WebhookAudit("https://siem.test/ingest", {
        headers: { "X-Hook-Key": secret },
        fetchImpl: (async () => { throw new Error(`transport reflected ${secret} token=value`); }) as typeof fetch,
      });
      await sink.writeAuthEvent({ ...baseEvent });
    } finally { captured.restore(); }
    assert.equal(captured.messages.join("\n").includes(secret), false, secret);
  }
});

test("WebhookAudit: never rejects when the transport throws a hostile error (throwing message getter)", async () => {
  // The fail-open invariant must hold even when the caught value is hostile —
  // a .message getter that throws must not escape the catch via safeErrorMessage.
  const hostile = { get message() { throw new Error("getter boom"); } };
  const sink = new WebhookAudit("https://siem.test/ingest", {
    fetchImpl: (async () => { throw hostile; }) as typeof fetch,
  });
  await assert.doesNotReject(() => sink.writeAuthEvent({ ...baseEvent }));
});

test("WebhookAudit: hostile-error fallback cannot reproduce a configured secret", async () => {
  for (const secret of ["diagnostic", "unavailable", "act"]) {
    const captured = captureConsoleError();
    try {
      const hostile = { get message() { throw new Error("getter boom"); } };
      const sink = new WebhookAudit("https://siem.test/ingest", {
        headers: { "X-Hook-Key": secret },
        fetchImpl: (async () => { throw hostile; }) as typeof fetch,
      });
      await assert.doesNotReject(() => sink.writeAuthEvent({ ...baseEvent }));
    } finally { captured.restore(); }
    assert.equal(captured.messages.join("\n").includes(secret), false, secret);
  }
});

test("WebhookAudit: final redaction covers the fixed prefix and configured host", async () => {
  for (const item of [
    { url: "https://siem.test/ingest", secret: "siem" },
    { url: "https://collector.test/ingest", secret: "audit" },
  ]) {
    const captured = captureConsoleError();
    try {
      const sink = new WebhookAudit(item.url, {
        headers: { "X-Hook-Key": item.secret },
        fetchImpl: (async () => { throw new Error("network down"); }) as typeof fetch,
      });
      await sink.writeAuthEvent({ ...baseEvent });
    } finally { captured.restore(); }
    assert.equal(captured.messages.join("\n").includes(item.secret), false, item.secret);
  }
});

test("WebhookAudit: exact syntax secrets cannot disguise another credential", async () => {
  const captured = captureConsoleError();
  try {
    const sink = new WebhookAudit("https://siem.test/ingest?padding=+", {
      fetchImpl: (async () => { throw new Error("transport reflected Bearer abc"); }) as typeof fetch,
    });
    await sink.writeAuthEvent({ ...baseEvent });
  } finally { captured.restore(); }
  const stderr = captured.messages.join("\n");
  assert.equal(stderr.includes("abc"), false);
  assert.equal(stderr.includes("Bearerabc"), false);
});

test("WebhookAudit: header secrets are snapshotted in their transmitted normalized form", async () => {
  const captured = captureConsoleError();
  try {
    const sink = new WebhookAudit("https://siem.test/ingest", {
      headers: { "X-Hook-Key": " abc " },
      fetchImpl: (async (_url, init) => {
        const reflected = new Headers(init?.headers).get("x-hook-key");
        throw new Error(`transport reflected ${reflected}`);
      }) as typeof fetch,
    });
    await sink.writeAuthEvent({ ...baseEvent });
  } finally { captured.restore(); }
  assert.equal(captured.messages.join("\n").includes("abc"), false);
});
