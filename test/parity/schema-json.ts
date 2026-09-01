import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { type Ajv2020 as Ajv2020Class, type ValidateFunction } from "ajv/dist/2020.js";
import type { FormatsPlugin } from "ajv-formats";
import type { ParityFixture } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const SCHEMA_PATH = resolve(PROJECT_ROOT, "fixtures/schema/fixture.schema.json");
const require = createRequire(import.meta.url);
const Ajv2020 = (require("ajv/dist/2020.js") as { default: typeof Ajv2020Class }).default;
const addFormats = (require("ajv-formats") as { default: FormatsPlugin }).default;
const ajv = createAjv();
let fixtureValidator: Promise<ValidateFunction> | undefined;

export function compileJsonSchema(schema: Record<string, unknown>): ValidateFunction {
  return createAjv().compile(schema);
}

function createAjv(): InstanceType<typeof Ajv2020Class> {
  const instance = new Ajv2020({ allErrors: true, strict: true });
  addFormats(instance);
  return instance;
}

function fixedSchemaValidator(): Promise<ValidateFunction> {
  fixtureValidator ??= readFile(SCHEMA_PATH, "utf8").then((source) => {
    const schema = JSON.parse(source) as Record<string, unknown>;
    return ajv.compile(schema);
  });
  return fixtureValidator;
}

export async function loadFixture(path: string): Promise<ParityFixture> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    throw new FixtureRunnerError(`${path}: invalid JSON`, { cause: error });
  }
  const validate = await fixedSchemaValidator();
  if (!validate(raw)) {
    const detail = ajv.errorsText(validate.errors, { separator: "; ", dataVar: "fixture" });
    throw new FixtureRunnerError(`${path}: schema validation failed: ${detail}`);
  }
  return raw as ParityFixture;
}
