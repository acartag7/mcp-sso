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
INFRA="${MCP_SSO_INFRA_DIR:-$HOME/project/personal-memory/personal-memory-infra}"
LEG="${1:-cloudflare_access}"
TUNNEL="${MCP_SSO_TUNNEL:-mcp-sso}"

cd "$INFRA" || { echo "infra repo not found: $INFRA"; exit 1; }
ORIGINS="$(./scripts/tofu-run.sh mcp-sso-cloudflare output -json issuer_origins 2>/dev/null)"
PORTS="$(./scripts/tofu-run.sh mcp-sso-cloudflare output -json tunnel_ingress_ports 2>/dev/null)"
HOST="$(echo "$ORIGINS" | python3 -c "import json,sys;print(json.load(sys.stdin)['$LEG'].split('://')[1])")"
PORT="$(echo "$PORTS" | python3 -c "import json,sys;print(json.load(sys.stdin)['$LEG']['gateway'])")"

CONF="$(mktemp -t mcp-sso-tunnel-XXXX).yml"
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
trap 'kill 0' EXIT INT TERM
PORT="$PORT" "$REPO/scripts/live/run.sh" "$REPO/examples/fastify-sqlite/index.ts" "$LEG" &
sleep 3
cloudflared tunnel --config "$CONF" run "$TUNNEL"
