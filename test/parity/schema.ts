import { readFile, readdir } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { type Ajv2020 as Ajv2020Class, type ValidateFunction } from "ajv/dist/2020.js";
import type { FormatsPlugin } from "ajv-formats";
import type { ParityFixture } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";

export const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const FIXTURES_ROOT = resolve(PROJECT_ROOT, "fixtures");
const SCHEMA_PATH = resolve(FIXTURES_ROOT, "schema/fixture.schema.json");
const require = createRequire(import.meta.url);
const Ajv2020 = (require("ajv/dist/2020.js") as { default: typeof Ajv2020Class }).default;
const addFormats = (require("ajv-formats") as { default: FormatsPlugin }).default;
const ajv = createAjv();
let fixtureValidator: ValidateFunction | undefined;

export function compileJsonSchema(schema: Record<string, unknown>): ValidateFunction {
  return createAjv().compile(schema);
}

function createAjv(): InstanceType<typeof Ajv2020Class> {
  const instance = new Ajv2020({ allErrors: true, strict: true }); addFormats(instance); return instance;
}

export async function loadCorpus(root = FIXTURES_ROOT): Promise<ParityFixture[]> {
  const validate = await validator();
  const paths = await fixturePaths(root);
  const fixtures: ParityFixture[] = [];
  const ids = new Set<string>();
  for (const path of paths) {
    const fixture = await loadFixture(path, root, validate);
    if (ids.has(fixture.id)) throw new FixtureRunnerError(`duplicate fixture id: ${fixture.id}`);
    ids.add(fixture.id);
    fixtures.push(fixture);
  }
  validateChains(fixtures);
  return fixtures;
}

async function validator(): Promise<ValidateFunction> {
  if (fixtureValidator) return fixtureValidator;
  const schema = JSON.parse(await readFile(SCHEMA_PATH, "utf8")) as Record<string, unknown>;
  fixtureValidator = ajv.compile(schema);
  return fixtureValidator as ValidateFunction;
}

async function fixturePaths(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const paths: string[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || !/^(0[1-9]|1[0-9])-/.test(entry.name)) continue;
    const directory = resolve(root, entry.name);
    for (const file of await readdir(directory, { withFileTypes: true })) {
      if (file.isFile() && file.name.endsWith(".json")) paths.push(resolve(directory, file.name));
    }
  }
  return paths.sort();
}

async function loadFixture(path: string, root: string, validate: ValidateFunction): Promise<ParityFixture> {
  let raw: unknown;
  try { raw = JSON.parse(await readFile(path, "utf8")); }
  catch (error) { throw new FixtureRunnerError(`${path}: invalid JSON`, { cause: error }); }
  if (!validate(raw)) {
    const detail = ajv.errorsText(validate.errors, { separator: "; ", dataVar: "fixture" });
    throw new FixtureRunnerError(`${path}: schema validation failed: ${detail}`);
  }
  const fixture = raw as ParityFixture;
  const expectedId = relative(root, path).split(sep).join("/").replace(/\.json$/u, "");
  if (fixture.id !== expectedId) {
    throw new FixtureRunnerError(`${path}: id ${fixture.id} does not match path ${expectedId}`);
  }
  await validateQuote(fixture);
  return fixture;
}

async function validateQuote(fixture: ParityFixture): Promise<void> {
  const entries = await readdir(resolve(PROJECT_ROOT, "docs/contracts"));
  const prefix = `${fixture.contract.section}-`;
  const names = entries.filter((name) => name.startsWith(prefix) && name.endsWith(".md"));
  if (names.length !== 1) throw new FixtureRunnerError(`${fixture.id}: contract section file is ambiguous`);
  const source = await readFile(resolve(PROJECT_ROOT, "docs/contracts", names[0]!), "utf8");
  const clause = clauseSource(source, fixture.contract.clause);
  if (!clause.includes(fixture.contract.quote)) {
    throw new FixtureRunnerError(`${fixture.id}: contract quote is stale in clause ${fixture.contract.clause}`);
  }
}

function clauseSource(source: string, clause: string): string {
  const escaped = clause.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const heading = new RegExp(`^(#{2,6})\\s+${escaped}(?:\\s|$)`, "mu").exec(source);
  if (heading === null || !heading[1]) throw new FixtureRunnerError(`contract clause ${clause} was not found`);
  const level = heading[1].length;
  const rest = source.slice(heading.index + heading[0].length);
  const next = new RegExp(`^#{2,${level}}\\s+`, "mu").exec(rest);
  return rest.slice(0, next?.index ?? rest.length);
}

function validateChains(fixtures: ParityFixture[]): void {
  const byId = new Map(fixtures.map((fixture) => [fixture.id, fixture]));
  const chains = new Map<string, ParityFixture[]>();
  for (const fixture of fixtures) {
    if (!fixture.chain) continue;
    const members = chains.get(fixture.chain.id) ?? [];
    members.push(fixture); chains.set(fixture.chain.id, members);
  }
  for (const [chainId, members] of chains) {
    const ordered = members.toSorted((a, b) => a.chain!.step - b.chain!.step);
    for (let index = 0; index < ordered.length; index += 1) {
      const fixture = ordered[index]!;
      if (fixture.chain!.step !== index + 1) throw new FixtureRunnerError(`${chainId}: chain steps must be contiguous`);
      const expected = index === 0 ? undefined : ordered[index - 1]!.id;
      if (fixture.chain!.previous !== expected) throw new FixtureRunnerError(`${fixture.id}: wrong chain predecessor`);
      if (fixture.chain!.previous && byId.get(fixture.chain!.previous)?.chain?.id !== chainId) {
        throw new FixtureRunnerError(`${fixture.id}: predecessor belongs to another chain`);
      }
    }
  }
}
