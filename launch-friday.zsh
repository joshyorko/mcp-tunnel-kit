#!/usr/bin/env zsh
set -euo pipefail

typeset -r SCRIPT_DIR="${0:A:h}"
typeset -r DEFAULT_TUNNEL_CLIENT="$HOME/.local/bin/tunnel-client"
typeset -r DEFAULT_BRIDGE_PYTHON="$SCRIPT_DIR/.venv/bin/python"
typeset -r ADAPTER="$SCRIPT_DIR/friday_mcp_adapter.py"
typeset TUNNEL_CLIENT="${TUNNEL_CLIENT_BIN:-$DEFAULT_TUNNEL_CLIENT}"
typeset BRIDGE_PYTHON="${FRIDAY_BRIDGE_PYTHON:-$DEFAULT_BRIDGE_PYTHON}"

: ${CONTROL_PLANE_API_KEY:?Export CONTROL_PLANE_API_KEY in this shell first}
: ${CONTROL_PLANE_TUNNEL_ID:?Export CONTROL_PLANE_TUNNEL_ID in this shell first}

[[ -x "$TUNNEL_CLIENT" ]] || { print -u2 -- "tunnel-client executable not found: $TUNNEL_CLIENT"; exit 2; }
[[ -x "$BRIDGE_PYTHON" ]] || { print -u2 -- "Friday bridge Python executable not found: $BRIDGE_PYTHON"; exit 2; }
[[ -f "$ADAPTER" ]] || { print -u2 -- "Friday MCP adapter not found: $ADAPTER"; exit 2; }

export FRIDAY_API_BASE_URL="${FRIDAY_API_BASE_URL:-http://127.0.0.1:8642/p/friday}"
export FRIDAY_API_ENV_FILE="${FRIDAY_API_ENV_FILE:-$HOME/.hermes/profiles/friday/.env}"
unset FRIDAY_API_KEY
"$BRIDGE_PYTHON" "$ADAPTER" --check-config

if [[ "${1:-}" == "--check" && $# == 1 ]]; then
  print -- "Friday bridge prerequisites are valid; no API request or tunnel was started."
  print -- "tunnel-client: $TUNNEL_CLIENT"
  print -- "MCP Python: $BRIDGE_PYTHON"
  exit 0
fi
if [[ $# -ne 0 ]]; then
  print -u2 -- "usage: ./launch-friday.zsh [--check]"
  exit 2
fi

exec "$TUNNEL_CLIENT" run \
  --control-plane.api-key env:CONTROL_PLANE_API_KEY \
  --control-plane.tunnel-id "$CONTROL_PLANE_TUNNEL_ID" \
  --health.listen-addr 127.0.0.1:0 \
  --mcp.command "command=$BRIDGE_PYTHON $ADAPTER,channel=main"
