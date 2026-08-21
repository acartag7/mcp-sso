# 18. Contract-change protocol

1. Update the relevant canonical contract section first (port/schema/error/endpoint/TTL).
2. If a runtime behavior changed, check the threat model and the store-conformance invariants (§12), and whether it affects memory/sqlite/mysql parity (and any further downstream SQL adapter).
3. Then change code. The conformance suite and unit tests must stay green.
4. Never weaken a fail-closed control to make a test pass. If a test and a fail-closed rule conflict, the rule wins. Change the test (and document why).
