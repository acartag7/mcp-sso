import { readdirSync, readFileSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CONTRACT_DIR = resolve(ROOT, "docs/contracts");
const FIXTURE_DIR = resolve(ROOT, "fixtures");
const CONTRACT_FILE = /^(0[5-9]|1[0-7])-.+\.md$/;
const MARKER = /\b(?:must(?:\s+not)?|never|always|cannot)\b|fails\s+closed/i;
const ANCHOR = /<a id="([0-9]+(?:\.[0-9]+){0,2}\.[a-z]+)"><\/a>/g;
const HEADING = /^#{1,6}\s+([0-9]+(?:\.[0-9]+){0,2})\b/;
const segmenter = new Intl.Segmenter("en", { granularity: "sentence" });

function fenceStart(line) {
  const match = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
  if (!match || (match[1][0] === "`" && match[2].includes("`"))) return undefined;
  return { character: match[1][0], length: match[1].length };
}

function fenceEnd(line, fence) {
  const match = line.match(/^ {0,3}(`+|~+)\s*$/);
  return Boolean(match && match[1][0] === fence.character && match[1].length >= fence.length);
}

function withoutAnchors(line) {
  const anchors = [];
  let text = "";
  let cursor = 0;
  for (const match of line.matchAll(ANCHOR)) {
    text += line.slice(cursor, match.index);
    anchors.push({ id: match[1], offset: text.length });
    cursor = match.index + match[0].length;
  }
  return { text: text + line.slice(cursor), anchors };
}

function protectInlineCode(text) {
  const characters = [...text];
  for (const match of text.matchAll(/(`+)([\s\S]*?)\1/g)) {
    const delimiterLength = match[1].length;
    for (let index = match.index; index < match.index + delimiterLength; index += 1) characters[index] = "X";
    const start = match.index + match[1].length;
    const end = start + match[2].length;
    if (start < end) characters[start] = "A";
    for (let index = start + 1; index < end; index += 1) {
      if (/[.!?]/.test(characters[index])) characters[index] = "x";
    }
    for (let index = end; index < end + delimiterLength; index += 1) characters[index] = "X";
  }
  for (const match of text.matchAll(/((?<!\*)\*{1,3}(?!\*)|(?<!_)_{1,3}(?!_))(?=\S)/g)) {
    const end = match.index + match[1].length;
    for (let index = match.index; index < end; index += 1) characters[index] = "X";
    if (/[a-z]/.test(characters[end] ?? "")) characters[end] = characters[end].toUpperCase();
  }
  return characters.join("");
}

function skipMarkdownPrefix(text, offset) {
  let cursor = offset;
  while (/\s/.test(text[cursor] ?? "")) cursor += 1;
  let changed = true;
  while (changed) {
    changed = false;
    const rest = text.slice(cursor);
    const prefix = rest.match(/^(?:>\s*|#{1,6}\s+|(?:[-+*]|[0-9]+[.)])\s+|\|\s*)/);
    if (prefix) {
      cursor += prefix[0].length;
      while (/\s/.test(text[cursor] ?? "")) cursor += 1;
      changed = true;
    }
  }
  if (offset > 0) {
    const closing = text.slice(cursor).match(/^(?:\*{1,3}|_{1,3})\s+/);
    if (closing) cursor += closing[0].length;
  }
  return cursor;
}

export function statementSuffix(index) {
  if (!Number.isSafeInteger(index) || index < 1) throw new TypeError("statement index must be a positive safe integer");
  let value = index;
  let result = "";
  while (value > 0) {
    value -= 1;
    result = String.fromCharCode(97 + (value % 26)) + result;
    value = Math.floor(value / 26);
  }
  return result;
}

export function inspectContractSource(path, source) {
  const errors = [];
  const statements = [];
  const anchors = [];
  const references = [];
  const seen = new Set();
  let clause;
  let fence;

  for (const [lineIndex, line] of source.split("\n").entries()) {
    const lineNumber = lineIndex + 1;
    if (fence) {
      if (MARKER.test(line)) errors.push(`${path}:${lineNumber}: normative marker inside fenced block`);
      if (/\bsee\b/i.test(line)) {
        for (const match of line.matchAll(/\b[0-9]+(?:\.[0-9]+){0,2}\.[a-z]+\b/g)) references.push({ id: match[0], path, line: lineNumber });
      }
      if (fenceEnd(line, fence)) fence = undefined;
      continue;
    }
    const opened = fenceStart(line);
    if (opened) {
      fence = opened;
      if (MARKER.test(line)) errors.push(`${path}:${lineNumber}: normative marker inside fenced block`);
      continue;
    }

    const heading = line.match(HEADING);
    if (heading) clause = heading[1];
    const stripped = withoutAnchors(line);
    for (const anchor of stripped.anchors) {
      if (seen.has(anchor.id)) errors.push(`${path}:${lineNumber}: duplicate statement anchor ${anchor.id}`);
      seen.add(anchor.id);
      anchors.push({ ...anchor, path, line: lineNumber });
    }
    const protectedText = protectInlineCode(stripped.text);
    const sentenceStarts = new Set([...segmenter.segment(protectedText)]
      .filter((part) => stripped.text.slice(part.index, part.index + part.segment.length).trim().length > 0)
      .map((part) => skipMarkdownPrefix(stripped.text, part.index)));
    for (const anchor of stripped.anchors) {
      if (!sentenceStarts.has(anchor.offset)) errors.push(`${path}:${lineNumber}: ${anchor.id} is not immediately before a sentence`);
    }
    for (const part of segmenter.segment(protectedText)) {
      const sourcePart = stripped.text.slice(part.index, part.index + part.segment.length);
      if (!MARKER.test(sourcePart)) continue;
      const offset = skipMarkdownPrefix(stripped.text, part.index);
      const matching = stripped.anchors.filter((anchor) => anchor.offset === offset);
      const sentence = sourcePart.trim();
      if (!clause) {
        errors.push(`${path}:${lineNumber}: normative sentence has no numbered clause`);
      } else if (matching.length !== 1) {
        errors.push(`${path}:${lineNumber}: normative sentence requires one anchor immediately before it: ${sentence}`);
      } else if (!matching[0].id.startsWith(`${clause}.`)) {
        errors.push(`${path}:${lineNumber}: ${matching[0].id} does not belong to clause ${clause}`);
      }
      statements.push({
        path,
        line: lineNumber,
        clause,
        sentence,
        offset,
        statement: matching.length === 1 ? matching[0].id : undefined,
      });
    }
  }
  return { anchors, errors, references, statements };
}

function fixtureFiles(directory) {
  const found = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory() && !["keys", "schema"].includes(entry.name)) found.push(...fixtureFiles(path));
    if (entry.isFile() && entry.name.endsWith(".json")) found.push(path);
  }
  return found;
}

export function validateContractStatements(contractSources, fixtures = []) {
  const errors = [];
  const anchors = new Map();
  const references = [];
  let statementCount = 0;
  for (const { path, source } of contractSources) {
    const result = inspectContractSource(path, source);
    errors.push(...result.errors);
    references.push(...result.references);
    statementCount += result.statements.length;
    for (const anchor of result.anchors) {
      if (anchors.has(anchor.id)) errors.push(`${path}:${anchor.line}: statement anchor ${anchor.id} also exists in ${anchors.get(anchor.id).path}`);
      else anchors.set(anchor.id, anchor);
    }
  }
  for (const reference of references) {
    if (!anchors.has(reference.id)) errors.push(`${reference.path}:${reference.line}: fenced pointer names unknown statement ${reference.id}`);
  }
  for (const { path, value } of fixtures) {
    const statement = value?.contract?.statement;
    const quote = value?.contract?.quote;
    if (typeof statement !== "string") {
      errors.push(`${path}: fixture requires contract.statement after the anchor migration`);
      continue;
    }
    const anchor = anchors.get(statement);
    if (!anchor) errors.push(`${path}: contract.statement ${statement} has no contract anchor`);
    if (typeof quote !== "string" || !contractSources.some(({ source }) => source.includes(`<a id="${statement}"></a>${quote}`))) {
      errors.push(`${path}: contract.quote is not the sentence immediately following ${statement}`);
    }
    if (statement.split(".").slice(0, -1).join(".") !== value.contract.clause) {
      errors.push(`${path}: contract.statement ${statement} does not belong to clause ${value.contract.clause}`);
    }
    if (String(Number(value.contract.section)) !== value.contract.clause.split(".")[0]) {
      errors.push(`${path}: contract.clause ${value.contract.clause} does not belong to section ${value.contract.section}`);
    }
  }
  return { anchorCount: anchors.size, errors, statementCount };
}

function main() {
  const contractSources = readdirSync(CONTRACT_DIR)
    .filter((name) => CONTRACT_FILE.test(name))
    .sort()
    .map((name) => ({ path: `docs/contracts/${name}`, source: readFileSync(join(CONTRACT_DIR, name), "utf8") }));
  const fixtures = fixtureFiles(FIXTURE_DIR).sort().map((path) => ({
    path: relative(ROOT, path),
    value: JSON.parse(readFileSync(path, "utf8")),
  }));
  const result = validateContractStatements(contractSources, fixtures);
  if (result.errors.length > 0) {
    console.error("contract statement integrity failed:");
    for (const error of result.errors) console.error(`- ${error}`);
    process.exitCode = 1;
    return;
  }
  console.log(`contract statement integrity: ${result.statementCount} marked sentences, ${result.anchorCount} anchors, ${fixtures.length} fixtures`);
}

if (process.argv[1] && basename(process.argv[1]) === basename(fileURLToPath(import.meta.url))) main();
