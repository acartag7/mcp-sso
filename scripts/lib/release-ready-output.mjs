const SUMMARY_CATEGORY_LIMIT = 4;
const DIRECTORY_CATEGORIES = ["src/", "examples/", "test/", "scripts/live/"];

function inputCategory(input) {
  return DIRECTORY_CATEGORIES.find((directory) => input.startsWith(directory)) ?? input;
}

function categorySummary(inputs) {
  const categories = [...new Set(inputs.map(inputCategory))].sort((left, right) => {
    const priorities = ["src/", "examples/", "scripts/live/", "package.json:version", "test/"];
    const leftPriority = priorities.indexOf(left);
    const rightPriority = priorities.indexOf(right);
    if (leftPriority !== -1 || rightPriority !== -1) {
      return (leftPriority === -1 ? priorities.length : leftPriority)
        - (rightPriority === -1 ? priorities.length : rightPriority);
    }
    return left.localeCompare(right);
  });
  const shown = categories.slice(0, SUMMARY_CATEGORY_LIMIT).join(", ");
  return `${shown}${categories.length > SUMMARY_CATEGORY_LIMIT ? " …" : ""}`;
}

function abbreviatedCommit(commit, commits) {
  let length = 7;
  while (commits.some((other) => other !== commit && other.startsWith(commit.slice(0, length)))) length += 1;
  return commit.slice(0, length);
}

export function parseReleaseReadyArgs(args) {
  if (args.length === 0) return { verbose: false };
  if (args.length === 1 && args[0] === "--verbose") return { verbose: true };
  throw new Error("usage: pnpm run check:release-ready [--verbose]");
}

export function formatReleaseReadinessFailure({ errors, staleEvidence, releaseTarget, verbose }) {
  const lines = ["release readiness failed:"];
  if (staleEvidence.length > 0) {
    const commits = staleEvidence.map((entry) => entry.commit);
    const noun = staleEvidence.length === 1 ? "commit" : "commits";
    const verb = staleEvidence.length === 1 ? "predates" : "predate";
    lines.push(`- ${staleEvidence.length} recorded evidence ${noun} ${verb} release runtime changes`);
    for (const { commit, changedInputs } of staleEvidence) {
      const inputNoun = changedInputs.length === 1 ? "input" : "inputs";
      lines.push(
        `    ${abbreviatedCommit(commit, commits)}  ${changedInputs.length} changed ${inputNoun} (${categorySummary(changedInputs)})`,
      );
      if (verbose) lines.push(...changedInputs.map((input) => `      - ${input}`));
    }
    lines.push(
      `  Re-run live verification against ${releaseTarget} and record the new commit in`,
      "  docs/client-compatibility.md.",
    );
  }
  lines.push(...errors.map((error) => `- ${error}`));
  return lines.join("\n");
}
