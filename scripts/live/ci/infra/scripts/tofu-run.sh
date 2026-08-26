#!/usr/bin/env bash
# The infrastructure wrapper run.sh calls when MCP_SSO_INFRA_DIR points at
# scripts/live/ci/infra. It answers `<stack> output -raw|-json <name>` from the
# Secrets Manager bundle fetch-bundle.mjs wrote to $MCP_SSO_BUNDLE_DIR, so a
# GitHub Actions job needs one OIDC-assumed role and no OpenTofu, no state
# access, no Azure session, and no Cloudflare token. Nothing else is accepted.
set -euo pipefail
set +xv
exec node "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/bundle-output.mjs" "$@"
