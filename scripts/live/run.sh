#!/usr/bin/env bash
# Live-verification runner. Reads every provider value from the OpenTofu stacks
# for the duration of ONE allowlisted entry point, validates all of it through
# the shipped constructors, and only then executes the entry — with an
# environment that contains exactly what this script assembled.
#
#   scripts/live/run.sh <entry> <leg>
#
#   entry = scripts/live/probe-cloudflare.mjs     leg = cloudflare_access
#           scripts/live/probe-entra.mjs                entra
#           scripts/live/probe-google.mjs               google
#           scripts/live/probe-e2e.mjs                  any leg   (needs REDIS_URL)
#           examples/fastify-sqlite/index.ts            any leg   (used by serve.sh)
#
# Nothing here hardcodes a repository path, stack handle, hostname, tenant, or
# credential, and no secret is printed. Requires an authenticated cloud session
# for the infrastructure wrapper (`aws sso login`; the Entra stack also needs
# `az login`). Every parse and every destructive step goes through
# scripts/live/run-support.mjs, never through this shell.
set -euo pipefail
# Tracing inherited through SHELLOPTS=xtrace (or verbose) would write every
# assignment below — provider secrets included — to stderr. Off, first.
set +xv

fail() { echo "run.sh: $1" >&2; exit 1; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Live evidence must name the exact runtime commit, and a tree with uncommitted
# tracked changes cannot (docs/live-verification.md). Refuse it unless the
# operator says explicitly that this run is not evidence.
RUNTIME_COMMIT="$(git -C "$REPO" rev-parse HEAD 2>/dev/null)" || fail "the checkout is not a git repository; live evidence must name a commit"
if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no 2>/dev/null)" ]; then
  if [ "${MCP_SSO_ALLOW_DIRTY:-false}" = "true" ]; then
    echo "run.sh: runtime commit ${RUNTIME_COMMIT} with UNCOMMITTED tracked changes — this run is not release evidence" >&2
  else
    fail "the checkout has uncommitted tracked changes; commit them, or set MCP_SSO_ALLOW_DIRTY=true for a run that is not evidence"
  fi
else
  echo "run.sh: runtime commit ${RUNTIME_COMMIT}" >&2
fi
SUPPORT="$REPO/scripts/live/run-support.mjs"
NODE_BIN="$(command -v node)" || fail "node is required on PATH"
# Every node this script starts — helpers, preflight, and the entry — runs under
# a minimal environment, never this shell's: an inherited NODE_OPTIONS or
# NODE_TLS_REJECT_UNAUTHORIZED must not reach the code that validates or
# executes a live run.
BASE_ENV=("PATH=$PATH" "HOME=$HOME")
if [ -n "${TMPDIR+x}" ]; then BASE_ENV+=("TMPDIR=$TMPDIR"); fi
node_clean() { env -i "${BASE_ENV[@]}" "$NODE_BIN" "$@"; }
ENTRY="${1:?usage: scripts/live/run.sh <entry> <leg>}"
LEG="${2:?usage: scripts/live/run.sh <entry> <leg>}"

# Fail closed on the entry × leg pair: stack credentials are handed to an
# allowlisted script only, never to an arbitrary path.
case "$ENTRY:$LEG" in
  scripts/live/probe-cloudflare.mjs:cloudflare_access) KIND=probe ;;
  scripts/live/probe-entra.mjs:entra) KIND=probe ;;
  scripts/live/probe-google.mjs:google) KIND=probe ;;
  scripts/live/probe-e2e.mjs:cloudflare_access|scripts/live/probe-e2e.mjs:entra|scripts/live/probe-e2e.mjs:google) KIND=e2e ;;
  examples/fastify-sqlite/index.ts:cloudflare_access|examples/fastify-sqlite/index.ts:entra|examples/fastify-sqlite/index.ts:google) KIND=server ;;
  *) fail "unsupported entry/leg pair: $ENTRY $LEG" ;;
esac
[ -f "$REPO/$ENTRY" ] || fail "entry does not exist: $ENTRY"
if [ "$KIND" = "e2e" ] && [ -z "${REDIS_URL:-}" ]; then
  fail "REDIS_URL is required for probe-e2e.mjs"
fi

INFRA="${MCP_SSO_INFRA_DIR:?set MCP_SSO_INFRA_DIR to the private infrastructure checkout}"
CLOUDFLARE_STACK="${MCP_SSO_CLOUDFLARE_STACK:?set MCP_SSO_CLOUDFLARE_STACK to the Cloudflare stack handle}"
[ -d "$INFRA" ] || fail "infrastructure checkout is unavailable (MCP_SSO_INFRA_DIR)"
[ -x "$INFRA/scripts/tofu-run.sh" ] || fail "infrastructure output wrapper is unavailable"

# The entry's environment is an ALLOWLIST built here, not this shell's
# environment minus a blocklist. Nothing inherited reaches the entry — not a
# stale identity selector, not an OAuth override, not HOST, PORT (except for
# the server entry), MCP_SSO_TRUSTED_PROXIES, or a NODE_* setting that would
# widen TLS trust or inject code. The same environment is what the preflight
# validates, so preflight and entry see identical bytes.
ENTRY_ENV=()
pass() {
  local name
  for name in "$@"; do
    if [ -n "${!name+x}" ]; then ENTRY_ENV+=("$name=${!name}"); fi
  done
}
pass PATH HOME TMPDIR LANG LC_ALL

# Fresh signing material for this run, generated BEFORE any stack secret is
# read so the generating processes never hold one.
OAUTH_CONSENT_SIGNING_SECRET="$(head -c 32 /dev/urandom | base64 | tr -d '\n=')" \
  || fail "consent signing credential generation failed"
[ -n "$OAUTH_CONSENT_SIGNING_SECRET" ] || fail "consent signing credential generation returned empty"
OAUTH_SIGNING_PRIVATE_JWK="$(node_clean -e '
const { generateKeyPairSync } = require("node:crypto");
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
process.stdout.write(JSON.stringify({ ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "live" }));')" \
  || fail "signing key generation failed"
[ -n "$OAUTH_SIGNING_PRIVATE_JWK" ] || fail "signing key generation returned empty"
OAUTH_SIGNING_KEY_ID="live"

# Stack reads. Every value is captured and validated; nothing is passed on
# until the whole leg has been read, and no state is touched until it passes.
output_raw() {
  local value
  value="$(cd "$INFRA" && ./scripts/tofu-run.sh "$1" output -raw "$2" 2>/dev/null)" \
    || fail "required stack output unavailable: $2"
  [ -n "$value" ] || fail "required stack output empty: $2"
  printf '%s' "$value"
}
output_json() {
  local value
  value="$(cd "$INFRA" && ./scripts/tofu-run.sh "$1" output -json "$2" 2>/dev/null)" \
    || fail "required stack output unavailable: $2"
  [ -n "$value" ] || fail "required stack output empty: $2"
  printf '%s' "$value"
}
support() { node_clean "$SUPPORT" "$@"; }

OAUTH_ISSUER="$(output_json "$CLOUDFLARE_STACK" issuer_origins | support issuer-origin "$LEG")" \
  || fail "issuer origin output is missing or invalid for the selected leg"

# The end-to-end probe composes its own app and never touches a provider, so it
# receives no provider credential at all; only the provider probes and the
# example server read the leg's stack outputs.
if [ "$KIND" != "e2e" ]; then
  case "$LEG" in
    entra)
      ENTRA_STACK="${MCP_SSO_ENTRA_STACK:?set MCP_SSO_ENTRA_STACK to the Entra stack handle}"
      ENTRA_TENANT_ID="$(output_raw "$ENTRA_STACK" entra_tenant_id)"
      ENTRA_CLIENT_ID="$(output_raw "$ENTRA_STACK" entra_client_id)"
      ENTRA_CLIENT_SECRET="$(output_raw "$ENTRA_STACK" entra_client_secret)"
      ENTRA_REDIRECT_URI="$(output_raw "$ENTRA_STACK" entra_redirect_uri)"
      ENTRA_UNMAPPED_GROUP="$(output_raw "$ENTRA_STACK" unmapped_group_object_id_do_not_map)"
      # The env var carries the whole GroupAuthorization object; the stack output
      # is only its mapping. No baseScopes: a user in zero mapped groups is denied.
      ENTRA_GROUP_AUTHORIZATION_JSON="$(output_json "$ENTRA_STACK" group_authorization_mapping | support group-authorization)" \
        || fail "group authorization output is invalid"
      pass ENTRA_TENANT_ID ENTRA_CLIENT_ID ENTRA_CLIENT_SECRET ENTRA_REDIRECT_URI
      pass ENTRA_UNMAPPED_GROUP ENTRA_GROUP_AUTHORIZATION_JSON
      # Negative-leg configuration (#279): deliberately-wrong OPERATOR-supplied
      # values for the wrong-tenant and subject-allowlist deny legs. Every other
      # Entra value here is a stack output (a real infrastructure value); these
      # two are wrong by design, so they arrive through their own clearly-marked
      # MCP_SSO_ channel instead — the example's bare ENTRA_* names stay
      # un-allowlisted from the ambient shell. Unset means the positive-only
      # configuration and the example's defaults apply.
      if [ -n "${MCP_SSO_ENTRA_ALLOWED_TENANT_IDS:-}" ]; then
        ENTRA_ALLOWED_TENANT_IDS="$MCP_SSO_ENTRA_ALLOWED_TENANT_IDS"
        pass ENTRA_ALLOWED_TENANT_IDS
      fi
      if [ -n "${MCP_SSO_ENTRA_SUBJECT_ALLOWLIST:-}" ]; then
        ENTRA_SUBJECT_ALLOWLIST="$MCP_SSO_ENTRA_SUBJECT_ALLOWLIST"
        pass ENTRA_SUBJECT_ALLOWLIST
      fi
      ;;
    cloudflare_access)
      CF_ACCESS_ISSUER="$(output_raw "$CLOUDFLARE_STACK" cf_access_issuer)"
      CF_ACCESS_CERTS_URL="$(output_raw "$CLOUDFLARE_STACK" cf_access_certs_url)"
      CF_ACCESS_AUDIENCE="$(output_raw "$CLOUDFLARE_STACK" cf_access_audience)"
      pass CF_ACCESS_ISSUER CF_ACCESS_CERTS_URL CF_ACCESS_AUDIENCE
      if [ "$ENTRY" = "scripts/live/probe-cloudflare.mjs" ]; then
        # The identity proof needs a CURRENT provider-signed assertion for the
        # Access application in front of /oauth/authorize. cloudflared mints one
        # from the operator's own Access login (once, in a browser:
        # `cloudflared access login <issuer>/oauth/authorize`); the value never
        # enters this repository or the terminal.
        command -v cloudflared >/dev/null 2>&1 || fail "cloudflared is required to mint the Access assertion"
        CF_ACCESS_ASSERTION="$(cloudflared access token -app="${OAUTH_ISSUER}/oauth/authorize" 2>/dev/null)" \
          || fail "cloudflared could not mint an Access assertion; run: cloudflared access login ${OAUTH_ISSUER}/oauth/authorize"
        [ -n "$CF_ACCESS_ASSERTION" ] || fail "cloudflared returned an empty Access assertion"
        pass CF_ACCESS_ASSERTION
      fi
      ;;
    google)
      # Google credentials are NOT provisioned by the stacks. They come from a
      # private KEY=VALUE file (GOOGLE_CLIENT_ID plus GOOGLE_CLIENT_SECRET or
      # OIDC_CLIENT_SECRET) that run-support opens once without following
      # symlinks, checks for owner-only permissions on that descriptor, and parses
      # as data. It is never sourced and never printed.
      GOOGLE_ENV="${MCP_SSO_GOOGLE_ENV:-$HOME/.mcp-sso-google.env}"
      GOOGLE_CREDENTIALS="$(support google-credential-file "$GOOGLE_ENV")" \
        || fail "Google credential file must be an owner-only KEY=VALUE file with the required keys"
      GOOGLE_CLIENT_ID="${GOOGLE_CREDENTIALS%%$'\n'*}"
      GOOGLE_CLIENT_SECRET="${GOOGLE_CREDENTIALS#*$'\n'}"
      unset GOOGLE_CREDENTIALS
      GOOGLE_REDIRECT_URI="${OAUTH_ISSUER}/oauth/callback"
      pass GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET GOOGLE_REDIRECT_URI
      ;;
  esac
fi

OAUTH_RESOURCE="${OAUTH_ISSUER}/mcp"
OAUTH_ALLOWED_ORIGINS="$OAUTH_ISSUER"
PROBE_CLIENT_REDIRECT="https://claude.ai/api/mcp/auth_callback"
# A real deployment allowlists its OWN web callback; the probes register it.
PROBE_APP_CALLBACK="${OAUTH_ISSUER}/app/callback"
# CLI MCP clients register loopback callbacks, which are no longer a built-in
# default; the live rig opts in unless MCP_SSO_ALLOW_LOOPBACK=false.
OAUTH_REDIRECT_ALLOWLIST="$PROBE_APP_CALLBACK"
if [ "${MCP_SSO_ALLOW_LOOPBACK:-true}" = "true" ]; then
  OAUTH_REDIRECT_ALLOWLIST="${OAUTH_REDIRECT_ALLOWLIST},http://localhost,http://127.0.0.1"
fi
# Stored DCR so a CLI client's loopback registration persists; the shipped
# example wires the bounded registration limiter stored mode requires.
OAUTH_DCR_MODE="${MCP_SSO_DCR_MODE:-stored}"
OAUTH_SCOPE_CATALOG="mcp:read,mcp:write"
OAUTH_DEFAULT_SCOPES="mcp:read"
pass OAUTH_ISSUER OAUTH_RESOURCE OAUTH_ALLOWED_ORIGINS OAUTH_REDIRECT_ALLOWLIST
pass OAUTH_CONSENT_SIGNING_SECRET OAUTH_SIGNING_PRIVATE_JWK OAUTH_SIGNING_KEY_ID
pass OAUTH_DCR_MODE OAUTH_SCOPE_CATALOG OAUTH_DEFAULT_SCOPES PROBE_CLIENT_REDIRECT PROBE_APP_CALLBACK
if [ "$KIND" = "e2e" ]; then pass REDIS_URL; fi

# Preflight over the exact environment the entry will receive: every pre-state
# gate the example itself runs (selector cardinality, DCR mode, proxy trust,
# config parse, deployment combination) plus the leg's shipped identity
# constructor. This runs BEFORE any prior state is cleared, so a bad output or
# a bad runner knob cannot cost the previous run's evidence.
if [ "$KIND" = "e2e" ]; then
  env -i "${ENTRY_ENV[@]}" "$NODE_BIN" "$SUPPORT" preflight-base || fail "assembled configuration failed the preflight"
else
  env -i "${ENTRY_ENV[@]}" "$NODE_BIN" "$SUPPORT" preflight "$LEG" || fail "stack outputs failed the provider preflight for leg $LEG"
fi

if [ "$KIND" = "server" ]; then
  # Per-leg state for the long-running example server only — the probes build
  # from disposable temp directories and never touch this. A shared directory
  # would let one leg delete another's database while it is serving.
  # run-support refuses a symlinked or shared parent and stops when prior
  # state cannot be removed; the library then creates the leaf 0700 itself.
  STATE="$(support state-dir "$REPO/.live-state" "$LEG")" || fail "live state directory could not be prepared"
  MCP_SSO_DIR="$STATE"
  OAUTH_SQLITE_FILE="$STATE/auth.db"
  # The tunnel connects over loopback; a server bound to every interface would
  # let LAN peers reach the OAuth endpoints around the tunnel edge.
  HOST="127.0.0.1"
  pass MCP_SSO_DIR OAUTH_SQLITE_FILE HOST PORT
fi

cd "$REPO" || fail "cannot enter the repository checkout"
# `env` execs node in place (no fork), so the started PID stays the entry —
# serve.sh binds readiness and cleanup to that PID.
exec env -i "${ENTRY_ENV[@]}" "$NODE_BIN" "$ENTRY"
