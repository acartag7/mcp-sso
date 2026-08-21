# Provision a machine client

Use this procedure for CI jobs, schedulers, and other callers that use the `client_credentials` grant without an interactive user.

## Before you begin

Configure `BridgeConfig.dcr.mode` as `"stored"`, enable `BridgeConfig.clientCredentials`, and provide a `MachineClientStore`. The SQLite `ClientStore` used for user registrations does not implement the atomic `MachineClientStore` lifecycle. The MySQL adapter implements `StorePort`, not `MachineClientStore`.

## Provision the credential

Call `provisionMachineClient` against the same `MachineClientStore` used by the bridge. Pass the exact `BridgeConfig.resource` value.

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
    allowedScopes: ["mcp:read"],
  },);
```

Store `clientSecret` in a secret manager immediately. `provisionMachineClient` returns it once. The store receives its SHA-256 hash.

## Request an access token

```bash
curl -s https://auth.example.com/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  -d scope=mcp:read
```

The response contains an access token and does not contain a refresh token. The machine client already has a durable credential.

## Apply downstream policy

Call `RequestAuthorizer.authorize()` for the protected request. Read `credentialKind` from its result. Do not decode the JWT or infer the credential type from an `mcc_` prefix.

Use `rotateMachineClientSecret` to rotate the secret. Pass an overlap shorter than the 24-hour maximum when the caller can switch promptly. Use `disableMachineClient` to stop future token issuance.

The complete record and mutation requirements are in [contract §17.2](contracts/17-v0-2-feature-contracts.md#172-client_credentials-grant-mcp-extension-iomodelcontextprotocoloauth-client-credentials).
