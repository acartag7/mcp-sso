// Windows has no POSIX mode/UID admission in this library. Keep the warning
// fixed and one-shot per loaded Node worker/runtime instance: paths are
// deployer-controlled input and must not enter a security diagnostic, while
// repeated opens through this package instance must not flood stderr. Worker
// threads have isolated module state and therefore each emit their own warning.

const WINDOWS_PERMISSION_WARNING =
  "[mcp-sso] Windows filesystem permissions are not verified: quickstart secrets, "
  + "managed state directories, and persistent SQLite state all skip POSIX "
  + "mode/ownership gates, and mcp-sso does not inspect DACLs. Use a private "
  + "ACL-controlled directory; use environment variables or a secret manager for "
  + "signing keys.";

let warned = false;

export function warnWindowsPermissionGap(): void {
  if (process.platform !== "win32" || warned) return;
  warned = true;
  try {
    console.warn(WINDOWS_PERMISSION_WARNING);
  } catch {
    // A broken logging transport cannot replace the boot result.
  }
}
