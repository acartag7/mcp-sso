#!/usr/bin/env bash
# Live-verification runner. Pulls every provider value from the OpenTofu stacks
# into the environment for the duration of one probe, then runs it.
#
#   scripts/live/run.sh <probe.mjs> [leg]
#
# leg = entra | cloudflare_access | google   (default: entra)
#
# Nothing here hardcodes a repository path, stack handle, hostname, tenant, or
# credential. No secret is printed. Requires an authenticated cloud session —
# run `aws sso login` first if the wrapper complains.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA="${MCP_SSO_INFRA_DIR:?set MCP_SSO_INFRA_DIR to the private infrastructure checkout}"
ENTRA_STACK="${MCP_SSO_ENTRA_STACK:?set MCP_SSO_ENTRA_STACK to the Entra stack handle}"
CLOUDFLARE_STACK="${MCP_SSO_CLOUDFLARE_STACK:?set MCP_SSO_CLOUDFLARE_STACK to the Cloudflare stack handle}"
PROBE="${1:?usage: scripts/live/run.sh <probe.mjs> [leg]}"
LEG="${2:-entra}"

[ -d "$INFRA" ] || { echo "infra repo not found: $INFRA (set MCP_SSO_INFRA_DIR)"; exit 1; }
cd "$INFRA" || exit 1
E() { ./scripts/tofu-run.sh "$ENTRA_STACK" output -raw "$1" 2>/dev/null; }
C() { ./scripts/tofu-run.sh "$CLOUDFLARE_STACK" output -raw "$1" 2>/dev/null; }
J() { ./scripts/tofu-run.sh "$1" output -json "$2" 2>/dev/null; }

export ENTRA_CLIENT_ID="$(E entra_client_id)"
export ENTRA_CLIENT_SECRET="$(E entra_client_secret)"
export ENTRA_REDIRECT_URI="$(E entra_redirect_uri)"
export ENTRA_UNMAPPED_GROUP="$(E unmapped_group_object_id_do_not_map)"
# The env var carries the whole GroupAuthorization object; the stack output is
# only its `mapping`. No baseScopes: a user in zero mapped groups must fail
# entra_no_groups rather than inherit a floor.
export ENTRA_GROUP_AUTHORIZATION_JSON="$(J "$ENTRA_STACK" group_authorization_mapping | python3 -c 'import json,sys;print(json.dumps({"mapping": json.load(sys.stdin)}))')"

export CF_ACCESS_ISSUER="$(C cf_access_issuer)"
export CF_ACCESS_CERTS_URL="$(C cf_access_certs_url)"
export PROBE_CF_ACCESS_AUDIENCE="$(C cf_access_audience)"

# The example boot-refuses more than one identity selector (a real fail-closed
# gate). Clear inherited shell state first, then export exactly the chosen leg's
# selector. Provider credentials that are not selectors may remain populated;
# they cannot activate a second identity path.
unset ENTRA_TENANT_ID CF_ACCESS_AUDIENCE GOOGLE_CLIENT_ID OIDC_ISSUER
case "$LEG" in
  cloudflare_access) export CF_ACCESS_AUDIENCE="$PROBE_CF_ACCESS_AUDIENCE" ;;
  entra)             export ENTRA_TENANT_ID="$(E entra_tenant_id)" ;;
  google)            : ;;   # GOOGLE_CLIENT_ID comes from the private env file
  *) echo "unknown leg: $LEG (expected cloudflare_access | entra | google)"; exit 1 ;;
esac

# Google credentials are NOT provisioned by the stacks (they live in Google
# Cloud Console). Supply them as JSON data in a private file outside the
# repository, mode 0600; it is never executed, printed, or committed.
GOOGLE_ENV="${MCP_SSO_GOOGLE_ENV:-$HOME/.mcp-sso-google.env}"
if [ "$LEG" = "google" ]; then
  [ -f "$GOOGLE_ENV" ] || { echo "Google credential file is required" >&2; exit 1; }
  GOOGLE_CONFIG_JSON="$(node -e '
const { constants, closeSync, fstatSync, openSync, readFileSync } = require("node:fs");
if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) process.exit(1);
let fd;
try { fd = openSync(process.argv[1], constants.O_RDONLY | constants.O_NOFOLLOW); } catch { process.exit(1); }
let st;
try { st = fstatSync(fd); } catch {
  closeSync(fd);
  process.exit(1);
}
const ownerMatches = typeof process.getuid !== "function" || st.uid === process.getuid();
if (!st.isFile() || !ownerMatches || (st.mode & 0o777) !== 0o600 || st.size > 16 * 1024) {
  closeSync(fd);
  process.exit(1);
}
let parsed;
try { parsed = JSON.parse(readFileSync(fd, "utf8")); } catch {
  closeSync(fd);
  process.exit(1);
}
closeSync(fd);
if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
  || Object.getPrototypeOf(parsed) !== Object.prototype
  || Object.keys(parsed).sort().join(",") !== "GOOGLE_CLIENT_ID,GOOGLE_CLIENT_SECRET"
  || typeof parsed.GOOGLE_CLIENT_ID !== "string" || parsed.GOOGLE_CLIENT_ID.length === 0 || parsed.GOOGLE_CLIENT_ID.length > 4096
  || typeof parsed.GOOGLE_CLIENT_SECRET !== "string" || parsed.GOOGLE_CLIENT_SECRET.length === 0 || parsed.GOOGLE_CLIENT_SECRET.length > 4096
  || /[\u0000-\u001f\u007f]/.test(parsed.GOOGLE_CLIENT_ID)
  || /[\u0000-\u001f\u007f]/.test(parsed.GOOGLE_CLIENT_SECRET)) process.exit(1);
process.stdout.write(JSON.stringify(parsed));
' "$GOOGLE_ENV")" || { echo "Google credential file must be owner-held mode-0600 JSON with the required fields" >&2; exit 1; }
  GOOGLE_CLIENT_ID="$(printf '%s' "$GOOGLE_CONFIG_JSON" | node -e 'const v=JSON.parse(require("node:fs").readFileSync(0,"utf8"));process.stdout.write(v.GOOGLE_CLIENT_ID)')"
  GOOGLE_CLIENT_SECRET="$(printf '%s' "$GOOGLE_CONFIG_JSON" | node -e 'const v=JSON.parse(require("node:fs").readFileSync(0,"utf8"));process.stdout.write(v.GOOGLE_CLIENT_SECRET)')"
  unset GOOGLE_CONFIG_JSON ENTRA_TENANT_ID CF_ACCESS_AUDIENCE OIDC_ISSUER
  export GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET
fi

export OAUTH_ISSUER="$(J "$CLOUDFLARE_STACK" issuer_origins | python3 -c "import json,sys;print(json.load(sys.stdin)['$LEG'])")"
export OAUTH_RESOURCE="${OAUTH_ISSUER}/mcp"
export OAUTH_ALLOWED_ORIGINS="$OAUTH_ISSUER"
export PROBE_CLIENT_REDIRECT="https://claude.ai/api/mcp/auth_callback"
# The deployment guard refuses stateless DCR whose only redirects are starter
# origins. A real deployment allowlists its OWN callback, so do that rather than
# acknowledge the starter risk (that acknowledgement is loopback-only anyway).
export PROBE_APP_CALLBACK="${OAUTH_ISSUER}/app/callback"
[ "$LEG" = "google" ] && export GOOGLE_REDIRECT_URI="${OAUTH_ISSUER}/oauth/callback"
# CLI MCP clients (Codex CLI, and any DCR-based local client) register a
# loopback callback. Loopback is deliberately NOT a built-in default any more
# (4793e63), so a deployment that wants to serve CLI clients must allowlist it
# explicitly. Opt in for the live rig via MCP_SSO_ALLOW_LOOPBACK=true.
export OAUTH_REDIRECT_ALLOWLIST="$PROBE_APP_CALLBACK"
if [ "${MCP_SSO_ALLOW_LOOPBACK:-true}" = "true" ]; then
  export OAUTH_REDIRECT_ALLOWLIST="${OAUTH_REDIRECT_ALLOWLIST},http://localhost,http://127.0.0.1"
fi

export OAUTH_CONSENT_SIGNING_SECRET="$(head -c 32 /dev/urandom | base64 | tr -d '\n=')padding-for-length"
export OAUTH_SIGNING_PRIVATE_JWK="$(node -e '
const {generateKeyPairSync}=require("node:crypto");
const {privateKey}=generateKeyPairSync("ec",{namedCurve:"P-256"});
process.stdout.write(JSON.stringify({...privateKey.export({format:"jwk"}),alg:"ES256",kid:"live"}));')"
export OAUTH_SIGNING_KEY_ID="live"
# Stored DCR so a CLI client's loopback registration persists, plus explicit
# loopback entries: #252 made this the supported shape for Codex-style clients.
# The example's own register limiter bounds it (registration-rate-limit.ts).
# Stored DCR requires a bounded limiter since #253 (B1). The shipped example
# wires its own finite registration port, so nothing extra is needed here — but
# if a leg ever fails to boot with an unbounded-registration error, that guard is
# the reason, not a regression.
export OAUTH_DCR_MODE="${MCP_SSO_DCR_MODE:-stored}"
export OAUTH_SCOPE_CATALOG="mcp:read,mcp:write"
export OAUTH_DEFAULT_SCOPES="mcp:read"

# Do NOT pre-create: the library creates the dir 0700 atomically and refuses to
# drop a `*` .gitignore into a directory it did not make.
# Per-LEG state. A shared directory means starting one leg deletes the SQLite
# file and audit sink of any leg already running, and every later store write
# throws — surfacing as a generic internal_error that looks like a product bug.
STATE="$REPO/.live-state/$LEG"
rm -rf -- "$STATE" || { echo "failed to remove prior live state" >&2; exit 1; }
export MCP_SSO_DIR="$STATE"
export OAUTH_SQLITE_FILE="$STATE/auth.db"

cd "$REPO" || exit 1
exec node "$PROBE"
