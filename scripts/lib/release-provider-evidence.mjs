const PROVIDER_STATUSES = new Set(["Verified", "Verified with limit", "Not run"]);

export function parseProviderRuntimeCommits(tableRows, errors) {
  const receipts = [];
  const subjects = new Set();
  for (const line of tableRows) {
    const rawCells = line.split("|").slice(1, -1);
    if (rawCells.length !== 6) {
      errors.push("provider evidence: malformed current-matrix row");
      continue;
    }
    const cells = rawCells.map((cell) => cell.trim());
    const [provider, client, flow, status, date, limits] = cells;
    const rawStatus = rawCells[3];
    if (!status || rawStatus !== ` ${status} ` || !/^[A-Za-z]+(?: [A-Za-z]+)*$/.test(status)) {
      errors.push(`provider evidence: ${provider} / ${client} has malformed status`);
      continue;
    }
    if (!PROVIDER_STATUSES.has(status)) {
      errors.push(`provider evidence: ${provider} / ${client} has unknown status ${status}`);
      continue;
    }
    let malformedName = false;
    for (const [label, value, rawValue] of [
      ["Provider", provider, rawCells[0]], ["Client", client, rawCells[1]], ["Flow driven", flow, rawCells[2]],
    ]) {
      if (rawValue !== ` ${value} ` || !/[\p{L}\p{N}]/u.test(value)) {
        errors.push(`provider evidence: row has missing or malformed ${label} cell`);
        malformedName = true;
      }
    }
    if (malformedName) continue;
    const subject = JSON.stringify([provider, client, flow].map((value) => value.replace(/`([^`]+)`/g, "$1")));
    if (subjects.has(subject)) {
      errors.push(`provider evidence: duplicate row for ${provider} / ${client} / ${flow}`);
      continue;
    }
    subjects.add(subject);
    const limitCount = limits.split("Limit:").length - 1;
    const notRunCount = limits.split("Not run:").length - 1;
    const receiptCount = limits.split("Runtime commit").length - 1
      + limits.split("Runtime evidence digest").length - 1;
    const verifiedStatus = status === "Verified" || status === "Verified with limit";
    if (!verifiedStatus) {
      if (limitCount !== 0 || notRunCount !== 1 || receiptCount !== 0 || rawCells[4] !== "  "
        || !/^Not run: (?=[^|]*[\p{L}\p{N}])\S(?:.*\S)?\.$/u.test(limits)) {
        errors.push(`provider evidence: ${provider} / ${client} has malformed Not run evidence`);
      }
      continue;
    }
    const dateMatch = date.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    const parsedDate = dateMatch
      ? new Date(Date.UTC(Number(dateMatch[1]), Number(dateMatch[2]) - 1, Number(dateMatch[3])))
      : undefined;
    if (!dateMatch || rawCells[4] !== ` ${date} ` || parsedDate.toISOString().slice(0, 10) !== date) {
      errors.push(`provider evidence: ${provider} / ${client} has missing or malformed date`);
      continue;
    }
    const directMatch = limits.match(/^Runtime commit `([0-9a-f]{7,40})`\./);
    const squashMatch = limits.match(
      /^Runtime evidence digest `sha256:([0-9a-f]{64})`, merged as `([0-9a-f]{7,40})`\./,
    );
    if (receiptCount !== 1 || (directMatch === null) === (squashMatch === null)) {
      errors.push(`provider evidence: ${provider} / ${client} has malformed runtime evidence receipt`);
      continue;
    }
    if (status === "Verified" && (limitCount !== 0 || notRunCount !== 0)) {
      errors.push(`provider evidence: ${provider} / ${client} has contradictory Verified evidence`);
      continue;
    }
    if (status === "Verified with limit") {
      const remainder = limits.slice((directMatch ?? squashMatch)[0].length);
      if (limitCount !== 1 || notRunCount !== 0
        || !/^ Limit: (?=[^|]*[\p{L}\p{N}])\S(?:.*\S)?\.(?: |$)/u.test(remainder)) {
        errors.push(`provider evidence: ${provider} / ${client} has missing or malformed limitation`);
        continue;
      }
    }
    receipts.push(directMatch
      ? { provider, client, runtimeCommit: directMatch[1] }
      : { provider, client, evidenceDigest: squashMatch[1], mergeCommit: squashMatch[2] });
  }
  return receipts;
}
