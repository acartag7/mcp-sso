# Contract development history from 2026-07 to 2026-08

This history preserves review and development context that was removed from the current contract reference. Current requirements are in [the contract index](../contracts.md).

## 2026-07-04 initial feature-contract source review

The v0.2 feature contract was written before implementation. Its initial source review used IETF drafts and RFCs, IANA registries, the MCP specification, and vendor documentation. The final MCP Authorization `2026-07-28` artifact was checked again on 2026-08-02.

## 2026-07-10 CIMD draft `-02` review

The review checked the draft's simple-string client ID comparison, production loopback prohibition, document-contained URL restrictions, periodic metadata re-fetch, private-key restrictions, and client-authentication requirements against the existing contract. The review concluded that the public-client profile already covered those normative changes. It also recorded the section-number mapping needed for a later draft re-pin.

## 2026-07-22 and 2026-07-23 CIMD security and flow reviews

GPT-5.6 Sol, Grok 4.5, and GLM 5.2 reviewed the CIMD security and flow rules. The rules were rechecked on Node 24. The resulting acceptance work covered guarded fetching, anti-oracle behavior, cache handling, carried registration state, and direct and redirect flows.

A patched-checkout campaign later exercised CIMD-first clients with Cloudflare Access, Entra ID, and Google. Its dirty tree was not archived, so it did not qualify as release evidence. On 2026-07-28, Claude Code 2.1.220 completed CIMD authorization and protected calls through runtime commit `af2a61f` with all three providers. The official final artifact was checked on 2026-08-02. Current release evidence is in [Verification status](../verification-status.md), and older receipts are in [Verification history](verification-history.md).

## 2026-07-26 upstream-flow audience binding

The upstream flow cookie originally used one deployment-wide audience. A multi-flow deployment could therefore accept a cookie minted by another configured flow. The contract changed the audience to `"mcp-sso/upstream-flow" + callbackPath`.

The test policy distinguished contract values from implementation constants. A frozen test may assert the exact audience formula because the contract specifies it. It must not import an implementation constant merely to discover the same value. `check:seams` enforces that boundary.

## 2026-07-10 ID-JAG adjacency record

The MCP Enterprise-Managed Authorization extension defined the Identity Assertion JWT Authorization Grant, or ID-JAG. The client obtains an identity assertion through RFC 8693 token exchange and redeems it under RFC 7523. At the time of review, the relevant providers used by this project did not issue ID-JAG assertions.

No ID-JAG runtime was added. A future implementation requires a new contract section because it introduces assertion validation, audience-bound token minting, provider metadata, and a new grant profile. It does not replace the resource-server verifier, registration, machine credentials, pairing, or the gateway pattern.
