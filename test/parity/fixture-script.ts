import { FixtureRunnerError } from "./error.ts";

export type FixtureScriptMatcher<Input, Entry> = (
  actual: Input,
  expected: Readonly<Entry>,
) => boolean;

const NO_EXPECTED_ENTRY = "fixture script call has no expected entry";
const INPUT_MISMATCH = "fixture script call does not match the next entry";
const UNCONSUMED_ENTRIES = "fixture script has unconsumed entries";
const STICKY_FAILURE = "fixture script call accounting previously failed";

export class OrderedFixtureScript<Entry extends object, Input> {
  readonly #entries: Entry[];
  readonly #matches: FixtureScriptMatcher<Input, Entry>;
  #index = 0;
  #failed = false;

  constructor(entries: readonly Entry[], matches: FixtureScriptMatcher<Input, Entry>) {
    this.#entries = structuredClone(entries) as Entry[];
    this.#matches = matches;
  }

  consume(actual: Input): Entry {
    const expected = this.#entries[this.#index];
    if (expected === undefined) {
      this.#failed = true;
      throw new FixtureRunnerError(NO_EXPECTED_ENTRY);
    }

    const matcherCopy = structuredClone(expected) as Entry;
    let matched: boolean;
    try {
      matched = this.#matches(actual, matcherCopy);
    } catch {
      this.#failed = true;
      throw new FixtureRunnerError(INPUT_MISMATCH);
    }
    if (!matched) {
      this.#failed = true;
      throw new FixtureRunnerError(INPUT_MISMATCH);
    }

    this.#index += 1;
    return structuredClone(expected) as Entry;
  }

  assertConsumed(): void {
    if (this.#failed) throw new FixtureRunnerError(STICKY_FAILURE);
    if (this.#index !== this.#entries.length) {
      throw new FixtureRunnerError(UNCONSUMED_ENTRIES);
    }
  }
}
