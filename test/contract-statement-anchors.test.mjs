import assert from "node:assert/strict";
import test from "node:test";
import { statementSuffix, validateContractStatements } from "../scripts/check-contract-statements.mjs";

function check(source, fixtures = []) {
  return validateContractStatements([{ path: "docs/contracts/08-example.md", source }], fixtures).errors;
}

test("statement suffixes use bijective base 26", () => {
  assert.equal(statementSuffix(1), "a");
  assert.equal(statementSuffix(26), "z");
  assert.equal(statementSuffix(27), "aa");
  assert.equal(statementSuffix(52), "az");
  assert.equal(statementSuffix(53), "ba");
});

test("marked prose requires one clause-scoped anchor", () => {
  assert.deepEqual(check("# 8. Example\n\n## 8.4 Rule\n<a id=\"8.4.aa\"></a>Consumers MUST reject it."), []);
  assert.match(check("# 8. Example\n\n## 8.4 Rule\nConsumers MUST reject it.")[0], /requires one anchor/);
  assert.match(check("# 8. Example\n\n## 8.4 Rule\n<a id=\"8.3.a\"><\/a>Consumers MUST reject it.")[0], /clause 8\.4/);
});

test("inline code stays in prose and does not open a fence", () => {
  assert.match(check("# 8. Example\n\nThe value `MUST` remain literal.")[0], /requires one anchor/);
  assert.deepEqual(check("# 8. Example\n\n<a id=\"8.a\"></a>`read(value?)` MUST run once."), []);
  assert.deepEqual(check("# 8. Example\n\nFirst sentence. <a id=\"8.a\"></a>`value` MUST remain."), []);
  assert.deepEqual(check("# 8. Example\n\nFirst sentence. <a id=\"8.a\"></a>**never accept this.**"), []);
});

test("every marker is refused inside backtick and tilde fences", () => {
  for (const marker of ["MUST", "MUST NOT", "never", "always", "cannot", "fails closed"]) {
    for (const fence of ["```ts", "~~~~ yaml"]) {
      const close = fence.startsWith("`") ? "```" : "~~~~";
      assert.match(check(`# 8. Example\n\n${fence}\n// ${marker}\n${close}`)[0], /inside fenced block/);
    }
  }
  assert.deepEqual(check("# 8. Example\n\n## 8.4 Rule\n<a id=\"8.4.a\"></a>Rule.\n\n```ts\n// see 8.4.a\n```"), []);
  assert.match(check("# 8. Example\n\n```MUST\n```yaml")[0], /inside fenced block/);
  assert.match(check("# 8. Example\n\n```ts\n// see 8.4.a\n```")[0], /unknown statement/);
});

test("an anchor cannot float away from its sentence", () => {
  assert.match(check("# 8. Example\n\n<a id=\"8.a\"></a> prefix before a sentence.")[0], /not immediately before a sentence/);
});

test("fixture statement points to its exact anchored quote", () => {
  const quote = "This input fails closed.";
  const fixture = {
    path: "fixtures/08-example/8.4-example.json",
    value: { contract: { section: "08", clause: "8.4", statement: "8.4.a", quote } },
  };
  assert.deepEqual(check(`# 8. Example\n\n## 8.4 Rule\n<a id=\"8.4.a\"></a>${quote}`, [fixture]), []);
  assert.match(check(`# 8. Example\n\n## 8.4 Rule\n<a id=\"8.4.a\"></a>Different.`, [fixture]).at(-1), /not the sentence/);
});

test("a fixture cannot omit its statement after migration", () => {
  const errors = check("# 8. Example", [{
    path: "fixtures/08-example/8.4-example.json",
    value: { contract: { clause: "8.4", quote: "Rule." } },
  }]);
  assert.match(errors[0], /requires contract\.statement/);
});
