# Why live verification uses provisioned infrastructure

Live OAuth checks fail for reasons outside the library. A hand-built tunnel, stale provider application, or unrecorded test user can make a good build fail and can also make a bad build look tested.

The live harness therefore reads provider configuration from OpenTofu stacks in a separate private repository. Each provider has its own stack. The stacks supply the public issuer, the tunnel ingress, the identity-provider application, and the negative-test accounts. Google credentials use an owner-only data file because that provider path does not expose the same stack output.

This design keeps two kinds of data separate. Private infrastructure names and credentials stay outside this repository. Public observations such as status codes, audit reason codes, client versions, and runtime commits go into the dated verification history.

The harness passes provider values through an allowlisted environment for one run. It does not source a developer shell profile. A stale selector or `NODE_OPTIONS` value therefore cannot silently change the provider leg.

In CI the same values arrive by a different road that ends in the same place. The stacks' outputs are republished, under the same names, as secrets that one AWS role can read, and the workflow assumes that role through GitHub OIDC from the `live` environment only. `run.sh` reads them through an adapter that answers its stack-output calls from the fetched bundle and still validates every value through the shipped constructors. A scheduled run therefore needs no interactive login, and a pull request, which never runs under that environment, never holds the role.

Provisioned negative cases matter as much as the happy path. The Entra stack creates the unmapped-group, group-overage, no-group, and cross-tenant fixtures before the run. A test that invents those cases during execution cannot be reproduced later.
