import assert from "node:assert/strict";
import { test } from "node:test";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import {
  assertClear, authorizeQuery, failingAudit, harness, readableCookieHeader, request,
} from "./lib/upstream-audit-failure.ts";

test("callback audit boundary: sync throws and async rejections cannot replace framework-free responses", async () => {
  for (const mode of ["sync", "async"] as const) {
    const { flow } = harness(failingAudit(mode));
    const duplicate = await flow.handleCallback(request(
      { state: ["one", "two"], code: "unused" },
      { cookie: readableCookieHeader() },
    ));
    assert.equal(duplicate.status, 400, `${mode}: duplicate response remains authoritative`);
    assert.equal((duplicate.body as { error: string }).error, "invalid_request");
    assertClear(duplicate, `${mode} duplicate`);

    const missing = await flow.handleCallback(request({ state: "unused", code: "unused" }));
    assert.equal(missing.status, 400, `${mode}: missing-cookie response remains authoritative`);
    assert.equal(missing.headers["set-cookie"], undefined, `${mode}: missing cookie is intentionally not cleared`);

    const auth = await flow.handleAuthorize(request(authorizeQuery()));
    assert.equal(auth.status, 302, `${mode}: flow initiation succeeds`);
    const cookie = (auth.headers["set-cookie"] ?? "").split(";", 1)[0] ?? "";
    const state = new URL(auth.headers.location ?? "").searchParams.get("state") ?? "";
    const denied = await flow.handleCallback(request({ state, code: "upstream-code" }, { cookie }));
    assert.equal(denied.status, 302, `${mode}: identity rejection remains a redirect`);
    assert.equal(new URL(denied.headers.location ?? "").searchParams.get("error"), "access_denied");
    assertClear(denied, `${mode} identity rejection`);

    for (const event of ["identity.verify", "oauth.upstream.callback"] as const) {
      const { flow: successFlow } = harness(failingAudit(mode, event), true);
      const successAuth = await successFlow.handleAuthorize(request(authorizeQuery()));
      const successCookie = (successAuth.headers["set-cookie"] ?? "").split(";", 1)[0] ?? "";
      const successState = new URL(successAuth.headers.location ?? "").searchParams.get("state") ?? "";
      const success = await successFlow.handleCallback(request(
        { state: successState, code: "upstream-code" }, { cookie: successCookie },
      ));
      assert.equal(success.status, 200, `${mode}: ${event} failure cannot replace callback success`);
      assert.match(String(success.body), /Authorize access/);
      assertClear(success, `${mode} ${event} success`);
    }
  }
});

test("callback audit boundary preserves callback and identity metadata for a working asynchronous sink", async () => {
  const events: AuthAuditEvent[] = [];
  const audit: AuditPort = {
    writeAuthEvent(event): Promise<void> {
      return Promise.resolve().then(() => { events.push(event); });
    },
  };
  const { flow } = harness(audit);
  const auth = await flow.handleAuthorize(request(authorizeQuery()));
  const cookie = (auth.headers["set-cookie"] ?? "").split(";", 1)[0] ?? "";
  const state = new URL(auth.headers.location ?? "").searchParams.get("state") ?? "";
  const denied = await flow.handleCallback(request({ state, code: "upstream-code" }, { cookie }));
  assert.equal(denied.status, 302);

  const identity = events.find((event) => event.event === "identity.verify");
  assert.deepEqual(identity, {
    occurredAt: "2026-08-12T12:00:00.000Z", event: "identity.verify",
    status: "failure", subject: undefined, reason: "policy_denied", ip: "203.0.113.8",
  });
  const callback = events.find((event) => event.event === "oauth.upstream.callback");
  assert.deepEqual(callback, {
    occurredAt: "2026-08-12T12:00:00.000Z", event: "oauth.upstream.callback",
    status: "failure", reason: "identity_rejected", clientId: "client-1", ip: "203.0.113.8",
  });
});
