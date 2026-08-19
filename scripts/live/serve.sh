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
set +xv

fail() { echo "serve.sh: $1" >&2; exit 1; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUPPORT="$REPO/scripts/live/run-support.mjs"
INFRA="${MCP_SSO_INFRA_DIR:?set MCP_SSO_INFRA_DIR to the private infrastructure checkout}"
CLOUDFLARE_STACK="${MCP_SSO_CLOUDFLARE_STACK:?set MCP_SSO_CLOUDFLARE_STACK to the Cloudflare stack handle}"
TUNNEL="${MCP_SSO_TUNNEL:?set MCP_SSO_TUNNEL to the tunnel UUID}"
[ $# -ge 1 ] || fail "usage: scripts/live/serve.sh <leg> [leg ...]"
LEGS=("$@")
# Wall-clock budget per leg, not a poll count: a server that accepts the
# connection and then stalls would otherwise stretch each poll by the request
# timeout and blow far past the advertised wait.
READINESS_SECONDS="${MCP_SSO_READINESS_SECONDS:-60}"
# Validated as a bounded decimal integer BEFORE it is ever used in arithmetic:
# `$(( ))` evaluates its operand as an expression, so an unvalidated value
# could fail mid-run — after every server had started — or, with an array
# subscript, evaluate a command substitution.
case "$READINESS_SECONDS" in
  ""|*[!0-9]*) fail "MCP_SSO_READINESS_SECONDS must be a whole number of seconds" ;;
esac
if [ "$READINESS_SECONDS" -lt 1 ] || [ "$READINESS_SECONDS" -gt 3600 ]; then
  fail "MCP_SSO_READINESS_SECONDS must be between 1 and 3600 seconds"
fi
# × 0.1 s: how long a child gets to exit on TERM before cleanup kills it.
REAP_GRACE_TICKS=50

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
# One ingress route per leg: a repeated leg, or two legs the stack maps to the
# same hostname or port, would leave one server unreachable or bind-racing —
# and its rows attributed to the wrong leg. Refuse before anything starts.
for i in "${!LEGS[@]}"; do
  for j in "${!LEGS[@]}"; do
    [ "$i" -lt "$j" ] || continue
    [ "${LEGS[$i]}" != "${LEGS[$j]}" ] || fail "leg ${LEGS[$i]} is named twice"
    [ "${HOSTS[$i]}" != "${HOSTS[$j]}" ] || fail "legs ${LEGS[$i]} and ${LEGS[$j]} resolve to the same hostname"
    [ "${GATEWAY_PORTS[$i]}" != "${GATEWAY_PORTS[$j]}" ] || fail "legs ${LEGS[$i]} and ${LEGS[$j]} resolve to the same port"
  done
done

listener_pids() { lsof -nP -t -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | sort -u | tr '\n' ' '; }
for port in "${GATEWAY_PORTS[@]}"; do
  [ -z "$(listener_pids "$port")" ] || fail "port $port already has a listener; stop it before serving"
done

CONF=""
SERVER_PIDS=()
TUNNEL_PID=""

# Terminate one child this script started, bounded: TERM, a grace period, then
# KILL. An unbounded `wait` would let one child that ignores TERM — cloudflared
# has — stall cleanup before it reaches the servers or removes the config,
# leaving the tunnel publicly routed after the operator asked it to stop.
reap() {
  local pid="$1" waited=0
  kill "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$REAP_GRACE_TICKS" ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "child $pid ignored termination; killing" >&2
    kill -9 "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  # Signal only the processes this script started — never the process group,
  # which would include the invoking shell and any sibling job.
  if [[ -n "$TUNNEL_PID" ]]; then
    reap "$TUNNEL_PID"
  fi
  for pid in ${SERVER_PIDS[@]+"${SERVER_PIDS[@]}"}; do
    reap "$pid"
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
  deadline=$((SECONDS + READINESS_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    # Each request is bounded well inside the polling interval, so a stalled
    # response costs one interval rather than the whole budget.
    if curl --fail --silent --noproxy '*' --max-time 2 --output /dev/null "http://127.0.0.1:${port}/.well-known/oauth-protected-resource"; then
      ready=true
      break
    fi
    sleep 0.5
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
# Every server proved ready above; re-prove it immediately before exposure. A
# later leg's readiness wait can outlive an earlier leg's process, and an
# earlier server can stop listening while still alive — letting another process
# bind its port — so the liveness check and the ownership proof are both redone
# here rather than trusting the per-leg proof from minutes ago.
for i in "${!LEGS[@]}"; do
  kill -0 "${SERVER_PIDS[$i]}" 2>/dev/null || fail "example server for leg ${LEGS[$i]} exited before the tunnel started"
  [ "$(listener_pids "${GATEWAY_PORTS[$i]}")" = "${SERVER_PIDS[$i]} " ] \
    || fail "port ${GATEWAY_PORTS[$i]} is no longer held solely by the server started for leg ${LEGS[$i]}"
done

# The tunnel runs in the background and this script supervises it and every
# server: a signal delivered to this script alone (not through the terminal's
# process group) still runs cleanup and takes them all down, and a server that
# dies while serving stops the run instead of leaving the tunnel exposing a
# dead backend. A foreground tunnel would defer the trap until it exited.
cloudflared tunnel --config "$CONF" run "$TUNNEL" &
TUNNEL_PID=$!
while kill -0 "$TUNNEL_PID" 2>/dev/null; do
  # Interval first: the gate above proved every leg a moment ago, so the next
  # meaningful check is one interval later.
  sleep 1
  kill -0 "$TUNNEL_PID" 2>/dev/null || break
  for i in "${!LEGS[@]}"; do
    if ! kill -0 "${SERVER_PIDS[$i]}" 2>/dev/null; then
      echo "example server for leg ${LEGS[$i]} exited while serving; stopping" >&2
      exit 1
    fi
    # Liveness is not ownership: a server can close its listening socket
    # without exiting and another process can take the port, and the public
    # tunnel would keep routing to that replacement. Re-prove ownership here,
    # the same way the pre-tunnel gate does.
    if [ "$(listener_pids "${GATEWAY_PORTS[$i]}")" != "${SERVER_PIDS[$i]} " ]; then
      echo "port ${GATEWAY_PORTS[$i]} changed hands while serving leg ${LEGS[$i]}; stopping" >&2
      exit 1
    fi
  done
done
wait "$TUNNEL_PID"
status=$?
TUNNEL_PID=""
exit "$status"
