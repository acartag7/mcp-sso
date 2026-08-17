import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const RUN = readFileSync(join(ROOT, "scripts/live/run.sh"), "utf8");
const PROBE = readFileSync(join(ROOT, "scripts/live/probe-e2e.mjs"), "utf8");
const CLOUDFLARE = readFileSync(join(ROOT, "scripts/live/probe-cloudflare.mjs"), "utf8");
const ENTRA = readFileSync(join(ROOT, "scripts/live/probe-entra.mjs"), "utf8");
const GOOGLE = readFileSync(join(ROOT, "scripts/live/probe-google.mjs"), "utf8");
const README = readFileSync(join(ROOT, "scripts/live/README.md"), "utf8");

test("live identity negatives and runner preconditions cannot pass for a later reason", () => {
  const registerAt = CLOUDFLARE.indexOf("identity-negative fixture registers a valid client");
  const forgedAt = CLOUDFLARE.indexOf("const forgedRes");
  assert.ok(registerAt >= 0 && registerAt < forgedAt, "the forged-JWT probe first establishes a valid client control");
  assert.match(CLOUDFLARE, /const forgedRes[\s\S]*?url: `\/oauth\/authorize\?\$\{identityQuery\}`/,
    "the forged JWT is exercised against the registered client request");
  assert.match(CLOUDFLARE, /forgedRes\.statusCode === 401/,
    "the live-JWKS negative requires the identity-verification response");
  assert.match(RUN, /rm -rf -- "\$STATE" \|\| \{[^}]*exit 1;/,
    "prior-state cleanup is a mandatory successful precondition");
});

test("live probe labels its machine credential as process-local, not SQLite-persisted", () => {
  assert.match(PROBE, /const machineRows = new Map\(\)/, "the probe machine store is process-local");
  assert.match(PROBE, /process-local MachineClientStore/);
  assert.match(README, /process-local `MachineClientStore`/);
  assert.match(README, /SQLite store proves filesystem admission only/);
  for (const artifact of [PROBE, README]) {
    assert.doesNotMatch(artifact, /provisioned into persistent SQLite/i);
    assert.doesNotMatch(artifact, /SQLite-persisted machine credential/i);
  }
});

test("live probes cannot turn an unexercised subject into passing evidence", () => {
  assert.doesNotMatch(PROBE, /\bSKIP\b/, "a skipped probe leg must never count as evidence");
  assert.match(
    PROBE,
    /disableMachineClient\([\s\S]*?provisioned\.clientId,[\s\S]*?\);/,
    "the disable helper receives the client id string",
  );
  assert.doesNotMatch(
    PROBE,
    /disableMachineClient\([\s\S]*?\{\s*clientId:/,
    "the old object-shaped disable argument made the probe skip its subject",
  );
  assert.match(
    PROBE,
    /audit-leak check has the \$\{name\} to inspect`, false/,
    "a missing credential fails its audit-leak row",
  );
  assert.doesNotMatch(
    PROBE,
    /\["consent signing secret",\s*process\.env\.OAUTH_CONSENT_SIGNING_SECRET\]/,
    "the signing credential never enters the generic output helper's values",
  );
  assert.doesNotMatch(
    PROBE,
    /OAUTH_CONSENT_SIGNING_SECRET[^\n]*(?:slice|substring|substr)/,
    "no shortened signing-secret prefix can reach output",
  );
  assert.match(PROBE, /new StreamableHTTPClientTransport\(/);
  assert.match(PROBE, /new Client\(/);
  assert.match(PROBE, /await client\.connect\(transport\)/);
  assert.match(PROBE, /await client\.callTool\(/);
  assert.ok(
    PROBE.indexOf("await disableMachineClient(") < PROBE.indexOf("for (let i = 0; i < 12; i += 1)"),
    "disablement is proved before the shared token limiter is exhausted",
  );
  assert.match(
    PROBE,
    /const requiredFlow = \[[\s\S]*?\["oauth\.client\.provision", "success"\][\s\S]*?\["oauth\.token\.client_credentials", "success"\][\s\S]*?\["auth\.request", "success"\][\s\S]*?\["oauth\.client\.disable", "success"\][\s\S]*?hasRequiredFlow\(fileEvents\)[\s\S]*?hasRequiredFlow\(posted\)/,
    "both sinks must contain the ordered events that constitute the exercised flow",
  );
  assert.match(PROBE, /JSON\.stringify\(fileEvents\) === JSON\.stringify\(posted\)/,
    "sink parity compares event content and order, not only totals");
});

test("Entra deny evidence and Google credentials are mandatory inputs", () => {
  assert.match(
    ENTRA,
    /throw new Error\("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID"\)/,
    "a missing or malformed deny fixture aborts instead of passing an empty-string exclusion",
  );
  assert.ok(
    ENTRA.indexOf("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID") < ENTRA.indexOf("await buildExample(process.env)"),
    "the required Entra deny fixture is validated before stateful example construction",
  );
  assert.doesNotMatch(ENTRA, /ENTRA_UNMAPPED_GROUP \?\? ""/);
  assert.match(
    ENTRA,
    /new Set\(groups\.map\(\(group\) => group\.toLowerCase\(\)\)\)[\s\S]*?!normalizedGroups\.has\(unmappedGroup\.toLowerCase\(\)\)/,
    "the deny fixture is excluded with the same case-insensitive GUID semantics as production authorization",
  );
  assert.match(README, /~\/\.mcp-sso-google\.env/);
  assert.match(README, /GOOGLE_CLIENT_ID/);
  assert.match(README, /GOOGLE_CLIENT_SECRET/);
  assert.match(README, /MCP_SSO_GOOGLE_ENV/);
  assert.match(RUN, /google\)\s+:\s+;;/);
  assert.match(RUN, /\[ "\$LEG" = "google" \] && export GOOGLE_REDIRECT_URI=/);
  const permissionAt = RUN.indexOf("const { lstatSync }");
  const sourceAt = RUN.indexOf('set -a; . "$GOOGLE_ENV"; set +a');
  assert.ok(permissionAt >= 0 && permissionAt < sourceAt,
    "the credential file is ownership/type/mode checked before sourcing");
  assert.match(RUN, /!st\.isFile\(\) \|\| !ownerMatches \|\| \(st\.mode & 0o777\) !== 0o600/);
  assert.match(RUN, /try \{ st = lstatSync\(process\.argv\[1\]\); \} catch \{ process\.exit\(1\); \}/,
    "credential-file races fail with the fixed shell diagnostic, not a raw path-bearing stack");
  assert.match(RUN, /Google credential file is required/);
  assert.match(RUN, /GOOGLE_CLIENT_ID:\?Google credential file must set GOOGLE_CLIENT_ID/);
});

test("Google live metadata passes through the production preset", () => {
  assert.match(GOOGLE, /import \{ createGoogleIdentity, validateGoogleIdToken \}/);
  assert.match(
    GOOGLE,
    /createGoogleIdentity\(cfg, \{ discoveryFetch:[\s\S]*?json: async \(\) => structuredClone\(dj\)/,
    "the production Google builder parses the live document fetched by the probe",
  );
  assert.match(GOOGLE, /builderDiscoveryUrl === "https:\/\/accounts\.google\.com\/\.well-known\/openid-configuration"/,
    "the preset must request Google's canonical discovery URL");
  assert.match(GOOGLE, /liveGoogle\.getAuthorizationUrl\(/,
    "the resolved live endpoint is exercised through the production identity");
});

test("discovered JWKS URLs are trusted before either probe follows them", () => {
  assert.ok(
    GOOGLE.indexOf("await createGoogleIdentity") < GOOGLE.indexOf("await fetch(dj.jwks_uri)"),
    "Google's production discovery validator runs before the JWKS fetch",
  );
  assert.match(
    ENTRA,
    /const expectedJwks = entraJwksUrl\(tenant\);[\s\S]*?discJson\.jwks_uri !== expectedJwks[\s\S]*?await fetch\(expectedJwks\)/,
    "Entra pins the discovered JWKS URL to the production tenant endpoint before fetching",
  );
});

test("live scripts contain no private infrastructure defaults", () => {
  for (const artifact of [RUN, README]) {
    assert.doesNotMatch(artifact, /\$HOME\/project\//, "no private checkout path is embedded");
  }
  assert.match(RUN, /MCP_SSO_ENTRA_STACK:\?/);
  assert.match(RUN, /MCP_SSO_CLOUDFLARE_STACK:\?/);
});

test("the runner clears inherited identity selectors before selecting one leg", () => {
  const clearAt = RUN.indexOf("unset ENTRA_TENANT_ID CF_ACCESS_AUDIENCE GOOGLE_CLIENT_ID OIDC_ISSUER");
  const switchAt = RUN.indexOf('case "$LEG" in');
  assert.ok(clearAt >= 0 && clearAt < switchAt,
    "ambient identity selectors cannot make a requested leg boot ambiguously");
});
