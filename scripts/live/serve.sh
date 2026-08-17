#!/usr/bin/env bash
# Bring one leg up PUBLICLY so a real MCP client (Claude Code, Codex CLI, Claude
# Desktop, claude.ai / ChatGPT custom connectors) can be pointed at it.
#
#   scripts/live/serve.sh [leg]        leg = cloudflare_access | entra | google
#
# Starts the shipped example on the leg's gateway port and runs the named
# Cloudflare tunnel with an ingress generated from the stack outputs, so no
# hostname is ever written into this repository. Ctrl-C stops both.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA="${MCP_SSO_INFRA_DIR:?set MCP_SSO_INFRA_DIR to the private infrastructure checkout}"
CLOUDFLARE_STACK="${MCP_SSO_CLOUDFLARE_STACK:?set MCP_SSO_CLOUDFLARE_STACK to the Cloudflare stack handle}"
LEG="${1:-cloudflare_access}"
TUNNEL="${MCP_SSO_TUNNEL:?set MCP_SSO_TUNNEL to the named tunnel handle}"

cd "$INFRA" || { echo "infra repo not found: $INFRA"; exit 1; }
ORIGINS="$(./scripts/tofu-run.sh "$CLOUDFLARE_STACK" output -json issuer_origins 2>/dev/null)"
PORTS="$(./scripts/tofu-run.sh "$CLOUDFLARE_STACK" output -json tunnel_ingress_ports 2>/dev/null)"
HOST="$(echo "$ORIGINS" | python3 -c "import json,sys;print(json.load(sys.stdin)['$LEG'].split('://')[1])")"
PORT="$(echo "$PORTS" | python3 -c "import json,sys;print(json.load(sys.stdin)['$LEG']['gateway'])")"

CONF=""
SERVER_PID=""

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$CONF" ]]; then
    rm -f -- "$CONF"
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

CONF="$(mktemp -t mcp-sso-tunnel-XXXX)" || exit 1
cat > "$CONF" <<YAML
tunnel: ${TUNNEL}
credentials-file: ${HOME}/.cloudflared/$(cloudflared tunnel info "$TUNNEL" 2>/dev/null | awk '/^ID/{print $2}').json
ingress:
  - hostname: ${HOST}
    service: http://localhost:${PORT}
  - service: http_status:404
YAML

echo "leg=${LEG}  host=${HOST}  port=${PORT}"
echo "tunnel config: ${CONF}"
echo
echo "Point a client at:  https://${HOST}/mcp"
echo "  Claude Code:  claude mcp add --transport http mcp-sso https://${HOST}/mcp"
echo "  Codex CLI:    add the same URL as an HTTP MCP server"
echo
PORT="$PORT" "$REPO/scripts/live/run.sh" "$REPO/examples/fastify-sqlite/index.ts" "$LEG" &
SERVER_PID=$!
SERVER_READY=false
for _ in {1..50}; do
  if curl --fail --silent --output /dev/null "http://127.0.0.1:${PORT}/.well-known/oauth-protected-resource"; then
    SERVER_READY=true
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
  sleep 0.1
done
if [[ "$SERVER_READY" != true ]]; then
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_STATUS=1
  else
    wait "$SERVER_PID"
    SERVER_STATUS=$?
    if [[ "$SERVER_STATUS" -eq 0 ]]; then SERVER_STATUS=1; fi
  fi
  echo "example server failed readiness before tunnel startup" >&2
  exit "$SERVER_STATUS"
fi
cloudflared tunnel --config "$CONF" run "$TUNNEL"
