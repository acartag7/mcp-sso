# Provision a machine client

Use this procedure for CI jobs, schedulers, and other callers that use the `client_credentials` grant without an interactive user. It implements the MCP extension `io.modelcontextprotocol/oauth-client-credentials`.

## Before you begin

Configure `BridgeConfig.dcr.mode` as `"stored"`, set `BridgeConfig.clientCredentials` to `{ enabled: true }`, and provide a store that implements `MachineClientStore`. The shipped SQLite `ClientStore` covers user registrations from `POST /oauth/register` but does not implement the atomic `MachineClientStore` lifecycle. The MySQL adapter implements `StorePort` only. For machine clients you implement `MachineClientStore` against your own database.

Machine clients are provisioned out of band. There is no HTTP endpoint that creates one, so `POST /oauth/register` can never mint a secret-bearing client. You run `provisionMachineClient` in your own operator tooling against the same store the bridge reads.

> [!IMPORTANT]
> A custom store must meet three rules, or the bridge rejects the row before it verifies, mutates, or issues anything. `ClientStore.find(clientId)` must return the row whose embedded `clientId` equals the lookup key. The row must carry the `resource` it was provisioned for, and `rotateMachineClientSecret` and `disableMachineClient` must preserve that field. A row provisioned before resource binding existed has no `resource` and cannot authenticate; provision it again. `parseMachineClientRegistration` enforces all three and returns no row for a mismatched or malformed record.

## Provision the credential

Call `provisionMachineClient` with the same `MachineClientStore` the bridge uses and the exact `BridgeConfig.resource` value. `resource` is a required field of `MachineClientDeps`. It must be an `https://` URL, or an `http://` URL on `localhost`, `127.0.0.1`, or `[::1]` for a development bridge that sets `dev.allowInsecureLocalhost`.

```ts
import { noopAudit, provisionMachineClient } from "mcp-sso";

const { clientId, clientSecret } = await provisionMachineClient(
  {
    store: clientStore,
    catalog: config.scopeCatalog,
    resource: config.resource,
    clock: { nowMs: () => Date.now() },
    audit: noopAudit,
  },
  {
    name: "nightly-sync",
    allowedScopes: ["mcp:read"], // the scope ceiling for this client, fixed at provisioning
  },
);
```

`provisionMachineClient` returns `clientSecret` once. Put it in your secret manager now. The store receives only its SHA-256 hash, so it cannot be read back later.

## Request an access token

```bash
curl -s https://auth.example.com/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  -d scope=mcp:read
```

The response contains an access token and no refresh token. The machine client already holds a durable credential, so a refresh token would add a second long-lived secret for no gain. `client_secret_post` works as well as `client_secret_basic`.

## Apply downstream policy

Call `RequestAuthorizer.authorize()` for the protected request and read `credentialKind` from its result: `"machine"` or `"interactive"`. Use that field for downstream policy. Do not decode the JWT yourself and do not infer the kind from an `mcc_` prefix. The verifier classifies a token as machine only when the complete `mcc_` subject, `sub === client_id`, and the `gty: "client_credentials"` binding all hold. The `mcc_` namespace is kept sound at three points: `prepare` rejects any user-grant subject that starts with `mcc_`, the code-exchange and refresh handlers reject a stored record whose subject is in that namespace, and the verifier requires all three markers together.

## Rotate and disable

`rotateMachineClientSecret` issues a new secret and keeps the old one valid for `graceSeconds`. The default is 24 hours, and 24 hours is also the hard maximum, so omitting `graceSeconds` leaves the old secret valid for a full day. Pass a shorter overlap, such as 300 seconds, when the caller can switch promptly.

`disableMachineClient` writes an atomic tombstone that stops future token issuance. Create, rotate, and disable are versioned atomic mutations; each commits the row and its audit record in one store transaction.

The complete record shape, the three classification points, and the mutation rules are in [contract §17.2](contracts/17-v0-2-feature-contracts.md#172-client_credentials-grant-mcp-extension-iomodelcontextprotocoloauth-client-credentials).
