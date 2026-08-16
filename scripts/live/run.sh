#!/usr/bin/env bash
# Live-verification runner. Pulls every provider value from the OpenTofu stacks
# into the environment for the duration of one probe, then runs it.
#
#   scripts/live/run.sh <probe.mjs> [leg]
#
# leg = entra | cloudflare_access | google   (default: entra)
#
# Nothing here hardcodes a hostname, tenant, or credential: the stacks are the
# only source. No secret is printed. Requires an authenticated cloud session —
# run `aws sso login` first if the wrapper complains.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA="${MCP_SSO_INFRA_DIR:-$HOME/project/personal-memory/personal-memory-infra}"
PROBE="${1:?usage: scripts/live/run.sh <probe.mjs> [leg]}"
LEG="${2:-entra}"

[ -d "$INFRA" ] || { echo "infra repo not found: $INFRA (set MCP_SSO_INFRA_DIR)"; exit 1; }
cd "$INFRA" || exit 1
E() { ./scripts/tofu-run.sh mcp-sso-entra output -raw "$1" 2>/dev/null; }
C() { ./scripts/tofu-run.sh mcp-sso-cloudflare output -raw "$1" 2>/dev/null; }
J() { ./scripts/tofu-run.sh "mcp-sso-$1" output -json "$2" 2>/dev/null; }

export ENTRA_CLIENT_ID="$(E entra_client_id)"
export ENTRA_CLIENT_SECRET="$(E entra_client_secret)"
export ENTRA_REDIRECT_URI="$(E entra_redirect_uri)"
export ENTRA_UNMAPPED_GROUP="$(E unmapped_group_object_id_do_not_map)"
# The env var carries the whole GroupAuthorization object; the stack output is
# only its `mapping`. No baseScopes: a user in zero mapped groups must fail
# entra_no_groups rather than inherit a floor.
export ENTRA_GROUP_AUTHORIZATION_JSON="$(J entra group_authorization_mapping | python3 -c 'import json,sys;print(json.dumps({"mapping": json.load(sys.stdin)}))')"

export CF_ACCESS_ISSUER="$(C cf_access_issuer)"
export CF_ACCESS_CERTS_URL="$(C cf_access_certs_url)"
export PROBE_CF_ACCESS_AUDIENCE="$(C cf_access_audience)"

# The example boot-refuses more than one identity selector (a real fail-closed
# gate), so export exactly the chosen leg's selector.
if [ "$LEG" = "cloudflare_access" ]; then
  export CF_ACCESS_AUDIENCE="$PROBE_CF_ACCESS_AUDIENCE"
else
  export ENTRA_TENANT_ID="$(E entra_tenant_id)"
fi

export OAUTH_ISSUER="$(J cloudflare issuer_origins | python3 -c "import json,sys;print(json.load(sys.stdin)['$LEG'])")"
export OAUTH_RESOURCE="${OAUTH_ISSUER}/mcp"
export OAUTH_ALLOWED_ORIGINS="$OAUTH_ISSUER"
export PROBE_CLIENT_REDIRECT="https://claude.ai/api/mcp/auth_callback"
# The deployment guard refuses stateless DCR whose only redirects are starter
# origins. A real deployment allowlists its OWN callback, so do that rather than
# acknowledge the starter risk (that acknowledgement is loopback-only anyway).
export PROBE_APP_CALLBACK="${OAUTH_ISSUER}/app/callback"
export OAUTH_REDIRECT_ALLOWLIST="$PROBE_APP_CALLBACK"

export OAUTH_CONSENT_SIGNING_SECRET="$(head -c 32 /dev/urandom | base64 | tr -d '\n=')padding-for-length"
export OAUTH_SIGNING_PRIVATE_JWK="$(node -e '
const {generateKeyPairSync}=require("node:crypto");
const {privateKey}=generateKeyPairSync("ec",{namedCurve:"P-256"});
process.stdout.write(JSON.stringify({...privateKey.export({format:"jwk"}),alg:"ES256",kid:"live"}));')"
export OAUTH_SIGNING_KEY_ID="live"
export OAUTH_SCOPE_CATALOG="mcp:read,mcp:write"
export OAUTH_DEFAULT_SCOPES="mcp:read"

# Do NOT pre-create: the library creates the dir 0700 atomically and refuses to
# drop a `*` .gitignore into a directory it did not make.
STATE="$REPO/.live-state"
rm -rf "$STATE"
export MCP_SSO_DIR="$STATE"
export OAUTH_SQLITE_FILE="$STATE/auth.db"

cd "$REPO" || exit 1
exec node "$PROBE"
