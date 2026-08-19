/** Resolve one evidence test's outcome from a TAP stream.
 *
 *  Exported so the rule that decides whether evidence counts is testable: this
 *  function is a release gate, and both of its edges are load-bearing.
 *
 *  - It finds the test's OWN result line rather than the line after its
 *    `# Subtest:` marker. A test that declares subtests emits them in between,
 *    so a next-line read reports a green parent as failing.
 *  - It matches to END OF LINE, never up to the `#`. A TAP directive follows the
 *    description (`ok 3 - name # SKIP reason`); truncating at the `#` drops the
 *    word SKIP and a skipped test is then counted as a pass — a green receipt
 *    for evidence that never ran.
 *  - It stays end-anchored so a name that is a strict prefix of another cannot
 *    resolve against the longer test's result line.
 */
export function resolveOutcome(output, name) {
  const marker = `# Subtest: ${name}\n`;
  const start = output.indexOf(marker);
  if (start < 0) return "missing";
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const own = new RegExp(`^\\s*(not )?ok \\d+ - ${escaped}(?:\\s+#.*)?$`, "m");
  const hit = own.exec(output.slice(start + marker.length));
  if (hit === null) return "no result line";
  const line = hit[0].trim();
  return line.startsWith("ok ") && !line.includes("# SKIP") ? "pass" : line;
}
