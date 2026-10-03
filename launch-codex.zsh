#!/usr/bin/env zsh
# Inactive direct Codex break-glass path. Stop the Executor-facing tunnel first.
unsetopt XTRACE VERBOSE
set -euo pipefail

typeset -r SCRIPT_DIR="${0:A:h}"
typeset -r DEFAULT_TUNNEL_CLIENT="$HOME/.local/bin/tunnel-client"
typeset -r DEFAULT_CHECK_PYTHON="$SCRIPT_DIR/.venv/bin/python"
typeset -r CHECK_SCRIPT="$SCRIPT_DIR/codex_mcp_check.py"
typeset TUNNEL_CLIENT="${TUNNEL_CLIENT_BIN:-$DEFAULT_TUNNEL_CLIENT}"
typeset CHECK_PYTHON="${CODEX_CHECK_PYTHON:-$DEFAULT_CHECK_PYTHON}"

if [[ $# -ne 0 && ! ( $# == 1 && "$1" == "--check" ) ]]; then
  print -u2 -- "usage: ./launch-codex.zsh [--check]"
  exit 2
fi

: ${CONTROL_PLANE_API_KEY:?Export CONTROL_PLANE_API_KEY in this shell first}
: ${CONTROL_PLANE_TUNNEL_ID:?Export CONTROL_PLANE_TUNNEL_ID in this shell first}

[[ -x "$TUNNEL_CLIENT" ]] || { print -u2 -- "tunnel-client executable not found: $TUNNEL_CLIENT"; exit 2; }
[[ -x "$CHECK_PYTHON" ]] || { print -u2 -- "MCP check Python executable not found"; exit 2; }
[[ -f "$CHECK_SCRIPT" ]] || { print -u2 -- "MCP check script not found"; exit 2; }

typeset CLIENT_HELP
if ! CLIENT_HELP=$("$TUNNEL_CLIENT" run --help 2>&1); then
  print -u2 -- "Cannot inspect tunnel-client HTTP support"
  exit 2
fi
[[ "$CLIENT_HELP" == *--mcp.server-url* ]] || {
  print -u2 -- "tunnel-client requires native --mcp.server-url support"
  exit 2
}

export CODEX_MCP_URL="${CODEX_MCP_URL:-http://127.0.0.1:8088/mcp}"
"$CHECK_PYTHON" "$CHECK_SCRIPT" --check-config

if [[ "${1:-}" == "--check" && $# == 1 ]]; then
  print -- "Codex tunnel prerequisites are valid; no MCP request or tunnel was started."
  exit 0
fi

"$CHECK_PYTHON" "$SCRIPT_DIR/executor_mcp.py" --check-tunnel-ownership

exec "$TUNNEL_CLIENT" run \
  --control-plane.api-key env:CONTROL_PLANE_API_KEY \
  --health.listen-addr 127.0.0.1:0 \
  --mcp.server-url "url=$CODEX_MCP_URL,channel=main"
