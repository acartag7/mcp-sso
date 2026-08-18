#!/usr/bin/env bash
# Bring one or more legs up PUBLICLY so a real MCP client (Claude Code, Codex
# CLI, Claude Desktop, claude.ai / ChatGPT custom connectors) can be pointed at
# them.
#
#   scripts/live/serve.sh <leg> [leg ...]     leg = cloudflare_access | entra | google
#
# Starts the shipped example once per leg on that leg's gateway port (through
# run.sh, so every provider value comes from the stack outputs) and runs the
# named Cloudflare tunnel with an ingress generated for exactly those
# hostnames. One tunnel carries all requested legs; a second connector with a
# different ingress would receive some of the traffic, so start every leg you
# want served in ONE invocation. Ctrl-C stops the tunnel and the servers.
#
# Requires cloudflared, curl, and lsof on PATH. MCP_SSO_TUNNEL is the tunnel
# UUID whose credentials file lives at ~/.cloudflared/<uuid>.json.
set -uo pipefail

fail() { echo "serve.sh: $1" >&2; exit 1; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUPPORT="$REPO/scripts/live/run-support.mjs"
INFRA="${MCP_SSO_INFRA_DIR:?set MCP_SSO_INFRA_DIR to the private infrastructure checkout}"
CLOUDFLARE_STACK="${MCP_SSO_CLOUDFLARE_STACK:?set MCP_SSO_CLOUDFLARE_STACK to the Cloudflare stack handle}"
TUNNEL="${MCP_SSO_TUNNEL:?set MCP_SSO_TUNNEL to the tunnel UUID}"
[ $# -ge 1 ] || fail "usage: scripts/live/serve.sh <leg> [leg ...]"
LEGS=("$@")
READINESS_POLLS="${MCP_SSO_READINESS_POLLS:-120}"   # × 0.5 s; provider discovery can take a while

for tool in cloudflared curl lsof; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required on PATH"
done
[[ "$TUNNEL" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
  || fail "MCP_SSO_TUNNEL must be the tunnel UUID"
CREDENTIALS="$HOME/.cloudflared/$TUNNEL.json"
[ -f "$CREDENTIALS" ] || fail "tunnel credentials file is missing for the given tunnel UUID"
[ -d "$INFRA" ] || fail "infrastructure checkout is unavailable (MCP_SSO_INFRA_DIR)"
[ -x "$INFRA/scripts/tofu-run.sh" ] || fail "infrastructure output wrapper is unavailable"

ORIGINS="$(cd "$INFRA" && ./scripts/tofu-run.sh "$CLOUDFLARE_STACK" output -json issuer_origins 2>/dev/null)" \
  || fail "issuer_origins output is unavailable"
PORTS="$(cd "$INFRA" && ./scripts/tofu-run.sh "$CLOUDFLARE_STACK" output -json tunnel_ingress_ports 2>/dev/null)" \
  || fail "tunnel_ingress_ports output is unavailable"
HOSTS=()
GATEWAY_PORTS=()
for leg in "${LEGS[@]}"; do
  origin="$(printf '%s' "$ORIGINS" | node "$SUPPORT" issuer-origin "$leg")" || fail "issuer origin is missing or invalid for leg $leg"
  port="$(printf '%s' "$PORTS" | node "$SUPPORT" gateway-port "$leg")" || fail "gateway port is missing or invalid for leg $leg"
  HOSTS+=("${origin#https://}")
  GATEWAY_PORTS+=("$port")
done

listener_pids() { lsof -nP -t -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | sort -u | tr '\n' ' '; }
for port in "${GATEWAY_PORTS[@]}"; do
  [ -z "$(listener_pids "$port")" ] || fail "port $port already has a listener; stop it before serving"
done

CONF=""
SERVER_PIDS=()
TUNNEL_PID=""

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  # Signal only the processes this script started — never the process group,
  # which would include the invoking shell and any sibling job.
  if [[ -n "$TUNNEL_PID" ]]; then
    kill "$TUNNEL_PID" 2>/dev/null || true
    wait "$TUNNEL_PID" 2>/dev/null || true
  fi
  for pid in ${SERVER_PIDS[@]+"${SERVER_PIDS[@]}"}; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ -n "$CONF" ]]; then
    rm -f -- "$CONF"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

CONF="$(mktemp -t mcp-sso-tunnel-XXXX)" || exit 1
{
  printf 'tunnel: %s\n' "$TUNNEL"
  printf 'credentials-file: %s\n' "$CREDENTIALS"
  printf 'ingress:\n'
  for i in "${!LEGS[@]}"; do
    printf '  - hostname: %s\n    service: http://127.0.0.1:%s\n' "${HOSTS[$i]}" "${GATEWAY_PORTS[$i]}"
  done
  printf '  - service: http_status:404\n'
} > "$CONF" || fail "cannot write the tunnel config"

echo "tunnel config: ${CONF}"
for i in "${!LEGS[@]}"; do
  echo "leg=${LEGS[$i]}  host=${HOSTS[$i]}  port=${GATEWAY_PORTS[$i]}"
  echo "  Point a client at:  https://${HOSTS[$i]}/mcp"
  echo "  Claude Code:  claude mcp add --transport http live-${LEGS[$i]} https://${HOSTS[$i]}/mcp"
  echo "  Codex CLI:    codex mcp add live-${LEGS[$i]} --url https://${HOSTS[$i]}/mcp"
done
echo

# Start every leg's server, then prove readiness of THAT process: the leg's
# port answers, the child is still alive, and lsof shows the child — and only
# the child — as the listener. A stale process on the port would otherwise be
# exposed as the build under test.
for i in "${!LEGS[@]}"; do
  PORT="${GATEWAY_PORTS[$i]}" "$REPO/scripts/live/run.sh" examples/fastify-sqlite/index.ts "${LEGS[$i]}" &
  SERVER_PIDS+=("$!")
done
for i in "${!LEGS[@]}"; do
  pid="${SERVER_PIDS[$i]}"
  port="${GATEWAY_PORTS[$i]}"
  ready=false
  polls=0
  while [ "$polls" -lt "$READINESS_POLLS" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    if curl --fail --silent --noproxy '*' --max-time 5 --output /dev/null "http://127.0.0.1:${port}/.well-known/oauth-protected-resource"; then
      ready=true
      break
    fi
    sleep 0.5
    polls=$((polls + 1))
  done
  if [[ "$ready" == true ]] && { ! kill -0 "$pid" 2>/dev/null || [[ "$(listener_pids "$port")" != "$pid " ]]; }; then
    ready=false
    echo "the listener on port $port is not the server just started for leg ${LEGS[$i]}" >&2
  fi
  if [[ "$ready" != true ]]; then
    if kill -0 "$pid" 2>/dev/null; then
      status=1
    else
      wait "$pid"
      status=$?
      if [[ "$status" -eq 0 ]]; then status=1; fi
    fi
    echo "example server for leg ${LEGS[$i]} failed readiness before tunnel startup" >&2
    exit "$status"
  fi
done
# The tunnel runs in the background and this script waits on it: `wait` is
# interruptible, so a signal delivered to this script alone (not through the
# terminal's process group) still runs cleanup and takes the tunnel and the
# servers down with it. A foreground tunnel would defer the trap until it
# exited on its own.
cloudflared tunnel --config "$CONF" run "$TUNNEL" &
TUNNEL_PID=$!
wait "$TUNNEL_PID"
status=$?
TUNNEL_PID=""
exit "$status"
