# Website login with verified identity claims

Use claims-only redirect completion when a website and its MCP endpoint share one host, but the website needs its own session instead of MCP consent and tokens.

`createUpstreamRedirectFlow({ complete: "identity" })` reuses the bridge completion path for state, nonce, PKCE, signed cookies, replay protection, exchange, verification, audit, and redaction. After verification, it passes bounded `IdentityClaims` to `onIdentity`.

The host owns user binding, durable writes, session creation, and any policy for attributes it stores. mcp-sso does not create a website session or apply another `emailVerified` check. The Google and generic OIDC ports omit `claims.name` unless the provider verifies the email identity.

```ts
import {
  assertDistinctUpstreamFlowRoutes,
  createUpstreamRedirectFlow,
} from "mcp-sso";

const websiteLogin = createUpstreamRedirectFlow({
  bridge,
  identity,
  store,
  clock,
  audit,
  rateLimit,
  complete: "identity",
  callbackPath: "/login/callback",
  completionTimeoutMs: 10_000,
  async onIdentity(claims) {
    const sessionCookie = await sessions.upsertLogin(claims);
    return {
      status: 303,
      headers: {},
      setCookies: [sessionCookie],
      redirect: "/account",
    };
  },
});

assertDistinctUpstreamFlowRoutes(bridge, [websiteLogin]);
// A shipped adapter performs this assertion and mounts /login plus the callback:
await registerOAuthRoutes(app, { bridge, skipAuthorize: true, identityFlow: websiteLogin });
```

Register `https://<issuer-host>/login/callback` at the identity provider. The configured `RedirectIdentityPort.redirectUri` must equal the issuer origin plus the callback path.

> [!IMPORTANT]
> `onIdentity` has a 10-second default timeout and accepts 1,000 through 30,000 milliseconds. A timeout does not cancel host work and cannot tell whether a transaction committed. A new login can invoke `onIdentity` again with the same identity, so person updates and membership bindings must be idempotent.

Both `/login` and `/login/callback` call `RateLimitPort.check` with `website-login:<ip>`. The port controls the quota and window. When both calls land in one window, a limit of 60 admits 30 completed sign-ins for that address. Choose the limit with shared office NAT traffic in mind.

If the identity provider denies the request or verified identity policy rejects the account, the callback returns the same direct 400 response. Using one response prevents the caller from learning whether the provider or local identity policy denied the account. The callback has no caller-controlled failure redirect. A provider denial therefore produces a bare error response in this release.

If `onIdentity` throws, times out, or returns a malformed `NormResponse`, the callback consumes the flow jti, clears the flow cookie, returns a generic direct 500, and audits `completion_failed`. It does not return a host session cookie or include the thrown value in the response, audit, log, or stderr.
