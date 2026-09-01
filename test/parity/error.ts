export class FixtureRunnerError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "FixtureRunnerError";
  }
}

export function fixtureFailure(fixtureId: string, message: string, cause?: unknown): FixtureRunnerError {
  return new FixtureRunnerError(`${fixtureId}: ${message}`, cause === undefined ? undefined : { cause });
}
