#!/usr/bin/env bash
# Owner-run live-provider entry point. It reads opaque infrastructure handles
# from the environment, validates every required output, and executes one
# allowlisted probe. No secret value is printed.
set -uo pipefail

fail() { echo "$1" >&2; exit 1; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA="${MCP_SSO_INFRA_DIR:?set MCP_SSO_INFRA_DIR to the private infrastructure checkout}"
CLOUDFLARE_STACK="${MCP_SSO_CLOUDFLARE_STACK:?set MCP_SSO_CLOUDFLARE_STACK to the Cloudflare stack handle}"
PROBE="${1:?usage: scripts/live/run.sh <probe.mjs> <leg>}"
LEG="${2:?usage: scripts/live/run.sh <probe.mjs> <leg>}"

case "$PROBE:$LEG" in
  scripts/live/probe-entra.mjs:entra|\
  scripts/live/probe-cloudflare.mjs:cloudflare_access|\
  scripts/live/probe-google.mjs:google) ;;
  *) fail "unsupported live probe/leg pair" ;;
esac

[ -d "$INFRA" ] || fail "infrastructure checkout is unavailable"
[ -x "$INFRA/scripts/tofu-run.sh" ] || fail "infrastructure output wrapper is unavailable"
cd "$INFRA" || fail "cannot enter infrastructure checkout"

required_raw() {
  local stack="$1" name="$2" value
  if ! value="$(./scripts/tofu-run.sh "$stack" output -raw "$name" 2>/dev/null)"; then
    echo "required stack output unavailable: $name" >&2
    return 1
  fi
  [ -n "$value" ] || { echo "required stack output empty: $name" >&2; return 1; }
  printf '%s' "$value"
}

required_json() {
  local stack="$1" name="$2" value
  if ! value="$(./scripts/tofu-run.sh "$stack" output -json "$name" 2>/dev/null)"; then
    echo "required stack output unavailable: $name" >&2
    return 1
  fi
  [ -n "$value" ] || { echo "required stack output empty: $name" >&2; return 1; }
  printf '%s' "$value"
}

unset ENTRA_TENANT_ID CF_ACCESS_AUDIENCE GOOGLE_CLIENT_ID OIDC_ISSUER

case "$LEG" in
  entra)
    ENTRA_STACK="${MCP_SSO_ENTRA_STACK:?set MCP_SSO_ENTRA_STACK to the Entra stack handle}"
    ENTRA_CLIENT_ID="$(required_raw "$ENTRA_STACK" entra_client_id)" || exit 1
    ENTRA_CLIENT_SECRET="$(required_raw "$ENTRA_STACK" entra_client_secret)" || exit 1
    ENTRA_REDIRECT_URI="$(required_raw "$ENTRA_STACK" entra_redirect_uri)" || exit 1
    ENTRA_UNMAPPED_GROUP="$(required_raw "$ENTRA_STACK" unmapped_group_object_id_do_not_map)" || exit 1
    ENTRA_TENANT_ID="$(required_raw "$ENTRA_STACK" entra_tenant_id)" || exit 1
    ENTRA_MAPPING_JSON="$(required_json "$ENTRA_STACK" group_authorization_mapping)" || exit 1
    ENTRA_GROUP_AUTHORIZATION_JSON="$(printf '%s' "$ENTRA_MAPPING_JSON" | python3 -c '
import json,sys
mapping=json.load(sys.stdin)
if not isinstance(mapping,dict): raise SystemExit(1)
print(json.dumps({"mapping":mapping},separators=(",",":")))
')" || fail "group authorization output is invalid"
    unset ENTRA_MAPPING_JSON
    export ENTRA_CLIENT_ID ENTRA_CLIENT_SECRET ENTRA_REDIRECT_URI
    export ENTRA_UNMAPPED_GROUP ENTRA_TENANT_ID ENTRA_GROUP_AUTHORIZATION_JSON
    ;;
  cloudflare_access)
    CF_ACCESS_ISSUER="$(required_raw "$CLOUDFLARE_STACK" cf_access_issuer)" || exit 1
    CF_ACCESS_CERTS_URL="$(required_raw "$CLOUDFLARE_STACK" cf_access_certs_url)" || exit 1
    CF_ACCESS_AUDIENCE="$(required_raw "$CLOUDFLARE_STACK" cf_access_audience)" || exit 1
    export CF_ACCESS_ISSUER CF_ACCESS_CERTS_URL CF_ACCESS_AUDIENCE
    ;;
  google)
    GOOGLE_ENV="${MCP_SSO_GOOGLE_ENV:-$HOME/.mcp-sso-google.env}"
    [ -f "$GOOGLE_ENV" ] || fail "Google credential file is required"
    GOOGLE_CONFIG_JSON="$(node -e '
const { constants, closeSync, fstatSync, openSync, readFileSync } = require("node:fs");
if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) process.exit(1);
let fd;
try { fd = openSync(process.argv[1], constants.O_RDONLY | constants.O_NOFOLLOW); } catch { process.exit(1); }
let st;
try { st = fstatSync(fd); } catch { closeSync(fd); process.exit(1); }
const ownerMatches = typeof process.getuid !== "function" || st.uid === process.getuid();
if (!st.isFile() || !ownerMatches || (st.mode & 0o777) !== 0o600 || st.size > 16 * 1024) {
  closeSync(fd); process.exit(1);
}
let parsed;
try { parsed = JSON.parse(readFileSync(fd, "utf8")); } catch { closeSync(fd); process.exit(1); }
closeSync(fd);
if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
  || Object.getPrototypeOf(parsed) !== Object.prototype
  || Object.keys(parsed).sort().join(",") !== "GOOGLE_CLIENT_ID,GOOGLE_CLIENT_SECRET"
  || typeof parsed.GOOGLE_CLIENT_ID !== "string" || parsed.GOOGLE_CLIENT_ID.length === 0 || parsed.GOOGLE_CLIENT_ID.length > 4096
  || typeof parsed.GOOGLE_CLIENT_SECRET !== "string" || parsed.GOOGLE_CLIENT_SECRET.length === 0 || parsed.GOOGLE_CLIENT_SECRET.length > 4096
  || /[\u0000-\u001f\u007f]/.test(parsed.GOOGLE_CLIENT_ID)
  || /[\u0000-\u001f\u007f]/.test(parsed.GOOGLE_CLIENT_SECRET)) process.exit(1);
process.stdout.write(JSON.stringify(parsed));
' "$GOOGLE_ENV")" || fail "Google credential file must be owner-held mode-0600 JSON with the required fields"
    GOOGLE_CLIENT_ID="$(printf '%s' "$GOOGLE_CONFIG_JSON" | node -e 'const v=JSON.parse(require("node:fs").readFileSync(0,"utf8"));process.stdout.write(v.GOOGLE_CLIENT_ID)')" || fail "Google client id is unavailable"
    GOOGLE_CLIENT_SECRET="$(printf '%s' "$GOOGLE_CONFIG_JSON" | node -e 'const v=JSON.parse(require("node:fs").readFileSync(0,"utf8"));process.stdout.write(v.GOOGLE_CLIENT_SECRET)')" || fail "Google client secret is unavailable"
    unset GOOGLE_CONFIG_JSON
    export GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET
    ;;
esac

ISSUER_ORIGINS_JSON="$(required_json "$CLOUDFLARE_STACK" issuer_origins)" || exit 1
OAUTH_ISSUER="$(printf '%s' "$ISSUER_ORIGINS_JSON" | node -e '
const fs=require("node:fs");
let parsed;
try { parsed=JSON.parse(fs.readFileSync(0,"utf8")); } catch { process.exit(1); }
const value=parsed?.[process.argv[1]];
if (typeof value!=="string" || value.length===0) process.exit(1);
let url;
try { url=new URL(value); } catch { process.exit(1); }
if (url.protocol!=="https:" || url.username || url.password || url.origin!==value) process.exit(1);
process.stdout.write(value);
' "$LEG")" || fail "issuer origin output is missing or invalid for the selected leg"
unset ISSUER_ORIGINS_JSON
export OAUTH_ISSUER
export OAUTH_RESOURCE="${OAUTH_ISSUER}/mcp"
export OAUTH_ALLOWED_ORIGINS="$OAUTH_ISSUER"
export PROBE_CLIENT_REDIRECT="https://claude.ai/api/mcp/auth_callback"
export PROBE_APP_CALLBACK="${OAUTH_ISSUER}/app/callback"
[ "$LEG" = "google" ] && export GOOGLE_REDIRECT_URI="${OAUTH_ISSUER}/oauth/callback"
export OAUTH_REDIRECT_ALLOWLIST="$PROBE_APP_CALLBACK"
if [ "${MCP_SSO_ALLOW_LOOPBACK:-true}" = "true" ]; then
  export OAUTH_REDIRECT_ALLOWLIST="${OAUTH_REDIRECT_ALLOWLIST},http://localhost,http://127.0.0.1"
fi

OAUTH_CONSENT_SIGNING_SECRET="$(head -c 32 /dev/urandom | base64 | tr -d '\n=')padding-for-length" || fail "consent signing credential generation failed"
[ -n "$OAUTH_CONSENT_SIGNING_SECRET" ] || fail "consent signing credential generation returned empty"
OAUTH_SIGNING_PRIVATE_JWK="$(node -e '
const {generateKeyPairSync}=require("node:crypto");
const {privateKey}=generateKeyPairSync("ec",{namedCurve:"P-256"});
process.stdout.write(JSON.stringify({...privateKey.export({format:"jwk"}),alg:"ES256",kid:"live"}));')" || fail "signing key generation failed"
[ -n "$OAUTH_SIGNING_PRIVATE_JWK" ] || fail "signing key generation returned empty"
export OAUTH_CONSENT_SIGNING_SECRET OAUTH_SIGNING_PRIVATE_JWK
export OAUTH_SIGNING_KEY_ID="live"
export OAUTH_DCR_MODE="${MCP_SSO_DCR_MODE:-stored}"
export OAUTH_SCOPE_CATALOG="mcp:read,mcp:write"
export OAUTH_DEFAULT_SCOPES="mcp:read"

STATE="$REPO/.live-state/$LEG"
rm -rf -- "$STATE" || fail "failed to remove prior live state"
export MCP_SSO_DIR="$STATE"
export OAUTH_SQLITE_FILE="$STATE/auth.db"

cd "$REPO" || fail "cannot return to repository checkout"
exec node "$PROBE"
