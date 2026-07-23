/** Deployer mapping from Entra group object IDs to scope ceilings. */
export interface GroupAuthorization {
  mapping: Record<string, string[]>;
  baseScopes?: string[];
}

/** Overage-related subset of a verified Entra token payload. Source URLs are
 * accepted as data for typing but are never read or dereferenced. */
export interface GroupClaimSource {
  groups?: unknown;
  hasgroups?: unknown;
  _claim_names?: unknown;
  _claim_sources?: unknown;
}
