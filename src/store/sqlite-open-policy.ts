const GROUP_OR_OTHER_WRITE = 0o022n;
const STICKY_BIT = 0o1000n;

interface SqliteAncestorTrust {
  parentUid: bigint;
  parentMode: bigint;
  entryUid: bigint;
  effectiveUid: bigint;
}

/** Internal POSIX policy seam; this module is not a package export. */
export function isSqliteAncestorReplaceable(input: SqliteAncestorTrust): boolean {
  const { parentUid, parentMode, entryUid, effectiveUid } = input;
  if (parentUid !== 0n && parentUid !== effectiveUid) return true;
  if ((parentMode & GROUP_OR_OTHER_WRITE) === 0n) return false;
  return (parentMode & STICKY_BIT) === 0n || entryUid !== effectiveUid;
}
