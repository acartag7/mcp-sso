// URL shape helpers shared across the config, metadata, challenge and adapter
// surfaces. They live outside config.ts because they are not configuration
// logic — config.ts re-exports them so existing importers (including the frozen
// acceptance suite, which imports `originOf` from "../../../src/config.ts")
// keep working unchanged.

/** Origin (scheme://host[:port]) of a URL. */
export function originOf(value: string): string {
  const u = new URL(value);
  return `${u.protocol}//${u.host}`;
}

/** Pathname of a URL (e.g. "/mcp" or "/"); used for the path-inserted PRM route. */
export function pathAfterOrigin(value: string): string {
  return new URL(value).pathname;
}
