# Live verification harness reference

`scripts/live/` contains the executable live verification tools. This page lists what each tool can establish. Current results belong in [Verification status](../verification-status.md) or [Client compatibility](../client-compatibility.md). Move a result to the [verification archive](../archive/verification-history.md) when a newer campaign supersedes it.

| File | Subject | Evidence |
| --- | --- | --- |
| `run.sh` | One named provider leg | Loads allowlisted values, validates the environment, identifies the runtime commit, and runs one probe. |
| `serve.sh` | One or more named provider legs | Starts the selected example servers, checks listener ownership, exposes the named tunnel, and supervises each child process. |
| `probe-cloudflare.mjs` | Cloudflare Access | Checks that a provider-signed assertion reaches consent and that missing or attacker-signed assertions fail. |
| `probe-entra.mjs` | Microsoft Entra ID | Checks discovery, JWKS availability, the authorization redirect, the flow cookie, and one local group-denial control. |
| `probe-google.mjs` | Google | Checks discovery through the guarded resolver and the authorization redirect to the validated endpoint. |
| `probe-e2e.mjs` | The shipped Fastify and SQLite example | Checks the selected DCR mode, authorization code flow, refresh rotation, replay-family revocation, revocation, an official MCP SDK call, the RFC 9728 challenge, Redis limiting, audit sequences, and credential non-publication. It checks a replayed predecessor and confirms that the live successor is revoked. It then creates a second family and confirms that revocation affects that family. The stateless run checks an unknown opaque client without storing it. The machine-client checks run only in stored mode. |
| `CHECKLIST.md` | Live MCP clients | Lists the client and identity-provider combinations that an operator must run. |

## Evidence boundary

A harness run is not provider evidence unless it reaches the named provider infrastructure and records the observed result. A unit or integration test can prove that the harness routes inputs correctly. It cannot prove that a provider accepted a request.

Each probe uses a disposable state directory and closes the app, store, and directory on every exit path. Each probe validates the effective redirect allowlist before provider I/O. A probe reports `FAIL` when it cannot exercise a required check. none reports `SKIP`.

`run.sh` refuses a checkout with tracked changes unless `MCP_SSO_ALLOW_DIRTY=true` marks the run as non-evidence. It disables inherited shell tracing before it handles secrets and passes an allowlisted environment to the probe.

`serve.sh` uses `MCP_SSO_READINESS_SECONDS`, with a default of 60 seconds, as the readiness deadline. It accepts readiness only when the child it started is the sole listener on the configured port. It checks listener ownership again before exposing the tunnel.

The executable tests are `test/live-run-script.test.mjs`, `test/live-serve-script.test.mjs`, and `test/live-e2e-probe.test.mjs`. The operator record is `scripts/live/README.md`. Change the harness and that record in the same pull request.
