import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PROBE = readFileSync(join(ROOT, "scripts/live/probe-entra.mjs"), "utf8");

test("Entra deny fixture is mandatory before the example boots", () => {
  const requiredAt = PROBE.indexOf("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID");
  const buildAt = PROBE.indexOf("await buildExample(process.env)");
  assert.ok(requiredAt >= 0 && requiredAt < buildAt);
  assert.match(PROBE, /typeof unmappedGroup !== "string" \|\| !guid\.test\(unmappedGroup\)/);
  assert.doesNotMatch(PROBE, /ENTRA_UNMAPPED_GROUP \?\?/);
});

test("Entra redirect is bound to the discovered endpoint and registered client", () => {
  assert.match(PROBE, /client_id: clientId \?\? "fixture-registration-failed"/);
  assert.match(PROBE, /advertised\.username === ""[\s\S]*?advertised\.password === ""[\s\S]*?advertised\.search === ""[\s\S]*?advertised\.hash === ""/);
  assert.match(PROBE, /targetBase\.search = "";[\s\S]*?targetBase\.hash = "";/);
  assert.match(PROBE, /advertisedIsBare && targetBase\?\.href === advertised\.href/);
  assert.doesNotMatch(PROBE, /pathname[^\n]*startsWith/);
  assert.match(PROBE, /discoveryJson\.jwks_uri !== expectedJwks[\s\S]*?await fetch\(expectedJwks\)/);
});

test("Entra synthetic denial is a non-live control excluded from live counts", () => {
  assert.match(PROBE, /This does not prove that the tenant emits the group in a real token/);
  assert.match(PROBE, /groups: \[unmappedGroup\]/);
  assert.match(PROBE, /if \(!control\("local identity control rejects the unmapped group"/);
  assert.match(PROBE, /denied\.reason === "entra_no_mapped_groups"/);
  assert.match(PROBE, /startsWith\("CONTROL"\)/);
  assert.doesNotMatch(PROBE, /ok\("identity port rejects a verified token/);
});

test("Entra probe emits no tenant identifier and drains output", () => {
  assert.doesNotMatch(PROBE, /`\$\{target\.origin\}\$\{target\.pathname\}`/);
  assert.doesNotMatch(PROBE, /console\.(?:log|warn|error)\([^\n]*(?:tenant|unmappedGroup|denyToken)/);
  assert.match(PROBE, /catch \{[\s\S]*?FAIL  probe aborted before completion[\s\S]*?finally \{/);
  assert.ok(PROBE.indexOf('finally {') < PROBE.indexOf('console.log(out.join("\\n"))'));
  assert.doesNotMatch(PROBE, /catch \([^)]*\)[\s\S]*?console\.(?:log|warn|error)\([^\n]*(?:error|message)/);
  assert.match(PROBE, /process\.exitCode = failures > 0 \? 1 : 0/);
  assert.doesNotMatch(PROBE, /process\.exit\(/);
});
