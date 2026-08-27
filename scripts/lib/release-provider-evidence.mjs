const PROVIDER_STATUSES = new Set(["Verified", "Verified with limit", "Not run"]);
const RECORDED_BY = new Set(["rehearsal", "operator"]);

function renderedSubjectCell(value) {
  return value.replace(/`([^`\r\n]+)`/g, "$1").replace(/\s+/gu, " ").trim();
}

export function parseProviderRuntimeCommits(tableRows, errors) {
  const receipts = [];
  const subjects = new Set();
  for (const line of tableRows) {
    const rawCells = line.split("|").slice(1, -1);
    if (rawCells.length !== 7) {
      errors.push("provider evidence: malformed current-matrix row");
      continue;
    }
    const cells = rawCells.map((cell) => cell.trim());
    const [provider, client, flow, recordedBy, status, date, limits] = cells;
    const rawStatus = rawCells[4];
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
    const subject = JSON.stringify([provider, client, flow].map(renderedSubjectCell));
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
      if (limitCount !== 0 || notRunCount !== 1 || receiptCount !== 0 || rawCells[5] !== "  "
        || !/^Not run: (?=[^|]*[\p{L}\p{N}])\S(?:.*\S)?\.$/u.test(limits)) {
        errors.push(`provider evidence: ${provider} / ${client} has malformed Not run evidence`);
      }
      continue;
    }
    const dateMatch = date.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    const parsedDate = dateMatch
      ? new Date(Date.UTC(Number(dateMatch[1]), Number(dateMatch[2]) - 1, Number(dateMatch[3])))
      : undefined;
    if (!dateMatch || rawCells[5] !== ` ${date} ` || parsedDate.toISOString().slice(0, 10) !== date) {
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
    // Provenance is recorded, never inferred from display text: a rendered
    // row's wording can change, and a row that stopped matching would have been
    // reclassified as an operator's. Anything but an explicit `operator` ages
    // strictly, so an unreadable or absent value cannot loosen the rule.
    if (rawCells[3] !== ` ${recordedBy} ` || !RECORDED_BY.has(recordedBy)) {
      errors.push(`provider evidence: ${provider} / ${client} has unknown "Recorded by" value ${recordedBy}`);
      continue;
    }
    const harnessDriven = recordedBy !== "operator";
    receipts.push(directMatch
      ? { provider, client, harnessDriven, runtimeCommit: directMatch[1] }
      : { provider, client, harnessDriven, evidenceDigest: squashMatch[1], mergeCommit: squashMatch[2] });
  }
  return receipts;
}
