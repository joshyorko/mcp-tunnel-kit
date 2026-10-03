#!/usr/bin/env zsh
unsetopt XTRACE VERBOSE
set -euo pipefail

typeset -r SCRIPT_DIR="${0:A:h}"
typeset -r TUNNEL_CLIENT="${TUNNEL_CLIENT_BIN:-$HOME/.local/bin/tunnel-client}"
typeset -r CHECK_PYTHON="${CODEX_CHECK_PYTHON:-$SCRIPT_DIR/.venv/bin/python}"

if [[ $# -ne 0 && ! ( $# == 1 && "$1" == "--check" ) ]]; then
  print -u2 -- "usage: ./launch-executor-tunnel.zsh [--check]"
  exit 2
fi
: ${CONTROL_PLANE_API_KEY:?Export the existing CONTROL_PLANE_API_KEY privately}
: ${CONTROL_PLANE_TUNNEL_ID:?Export the existing CONTROL_PLANE_TUNNEL_ID privately}
[[ -x "$TUNNEL_CLIENT" && -x "$CHECK_PYTHON" ]] || {
  print -u2 -- "tunnel-client or check Python executable unavailable"
  exit 2
}
typeset CLIENT_HELP
CLIENT_HELP=$("$TUNNEL_CLIENT" run --help 2>&1)
[[ "$CLIENT_HELP" == *--mcp.server-url* && "$CLIENT_HELP" == *--mcp.extra-headers* ]] || {
  print -u2 -- "tunnel-client requires native HTTP and MCP static-header support"
  exit 2
}

export EXECUTOR_DATA_DIR="${EXECUTOR_DATA_DIR:-$HOME/.local/share/executor}"
export EXECUTOR_MCP_URL="${EXECUTOR_MCP_URL:-http://127.0.0.1:4312/mcp}"
"$CHECK_PYTHON" "$SCRIPT_DIR/executor_mcp.py" --check-config
"$CHECK_PYTHON" "$SCRIPT_DIR/executor_mcp.py" --write-auth-header
IFS= read -r EXECUTOR_AUTH_HEADER < "$EXECUTOR_DATA_DIR/tunnel-auth-header"
export EXECUTOR_AUTH_HEADER
if [[ "${1:-}" == "--check" ]]; then
  print -- "Executor tunnel prerequisites valid; no MCP request or tunnel was started."
  exit 0
fi
"$CHECK_PYTHON" "$SCRIPT_DIR/executor_mcp.py" --check-tunnel-ownership

# Values are private environment references. The tunnel ID also stays out of argv.
exec "$TUNNEL_CLIENT" run \
  --config "$SCRIPT_DIR/config/executor-tunnel.yaml" \
  --mcp.server-url "url=$EXECUTOR_MCP_URL,channel=main" \
  --log.http-raw-unsafe=false
