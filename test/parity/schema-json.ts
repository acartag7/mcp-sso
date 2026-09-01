import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { type Ajv2020 as Ajv2020Class, type ValidateFunction } from "ajv/dist/2020.js";
import type { FormatsPlugin } from "ajv-formats";
import type { ParityFixture } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";
import { parseStrictJson } from "./strict-json.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const SCHEMA_PATH = resolve(PROJECT_ROOT, "fixtures/schema/fixture.schema.json");
const require = createRequire(import.meta.url);
const Ajv2020 = (require("ajv/dist/2020.js") as { default: typeof Ajv2020Class }).default;
const addFormats = (require("ajv-formats") as { default: FormatsPlugin }).default;
const ajv = createAjv();
let schemaDocument: Promise<Record<string, unknown>> | undefined;
let fixtureValidator: Promise<ValidateFunction> | undefined;
let stateValidator: Promise<ValidateFunction> | undefined;

export function compileJsonSchema(schema: Record<string, unknown>): ValidateFunction {
  return createAjv().compile(schema);
}

function createAjv(): InstanceType<typeof Ajv2020Class> {
  const instance = new Ajv2020({ allErrors: true, strict: true });
  addFormats(instance);
  return instance;
}

function fixedSchemaDocument(): Promise<Record<string, unknown>> {
  schemaDocument ??= readFile(SCHEMA_PATH, "utf8").then((source) => {
    try {
      const schema = parseStrictJson(source);
      if (schema === null || typeof schema !== "object" || Array.isArray(schema)) {
        throw new SyntaxError("invalid JSON");
      }
      return schema as Record<string, unknown>;
    } catch (error) {
      throw new FixtureRunnerError(`${SCHEMA_PATH}: invalid JSON`, { cause: error });
    }
  });
  return schemaDocument;
}

function compileFixedSchema(
  select: (schema: Record<string, unknown>) => Record<string, unknown>,
): Promise<ValidateFunction> {
  return fixedSchemaDocument().then((schema) => {
    try {
      return ajv.compile(select(schema));
    } catch (error) {
      throw new FixtureRunnerError(`${SCHEMA_PATH}: invalid JSON`, { cause: error });
    }
  });
}

function fixedSchemaValidator(): Promise<ValidateFunction> {
  fixtureValidator ??= compileFixedSchema((schema) => schema);
  return fixtureValidator;
}

export async function logicalStateValidator(): Promise<ValidateFunction> {
  stateValidator ??= compileFixedSchema((schema) => ({
    $ref: "#/$defs/logicalState", $defs: schema["$defs"],
  }));
  return stateValidator;
}

export function schemaErrorsText(errors: ValidateFunction["errors"], dataVar: string): string {
  return ajv.errorsText(errors, { separator: "; ", dataVar });
}

export async function loadFixture(path: string): Promise<ParityFixture> {
  let raw: unknown;
  try {
    raw = parseStrictJson(await readFile(path, "utf8"));
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
