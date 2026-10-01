#!/usr/bin/env zsh
set -euo pipefail

: ${CONTROL_PLANE_API_KEY:?Export CONTROL_PLANE_API_KEY in this shell first}
: ${CONTROL_PLANE_TUNNEL_ID:?Export CONTROL_PLANE_TUNNEL_ID in this shell first}

typeset -r TUNNEL_CLIENT="${TUNNEL_CLIENT_BIN:-$HOME/.local/bin/tunnel-client}"

if (( $# > 0 )); then
  if (( $# != 1 )) || [[ "$1" != "--check" ]]; then
    print -u2 -- "usage: launch-stateless-stub.zsh [--check]"
    exit 2
  fi
fi

if [[ ! -x "$TUNNEL_CLIENT" ]]; then
  print -u2 -- "tunnel-client executable not found: $TUNNEL_CLIENT"
  exit 1
fi

if [[ "${1:-}" == "--check" ]]; then
  print -- "Stateless stub launcher checks passed; no tunnel was started."
  exit 0
fi

exec "$TUNNEL_CLIENT" run \
  --control-plane.api-key env:CONTROL_PLANE_API_KEY \
  --control-plane.tunnel-id "$CONTROL_PLANE_TUNNEL_ID" \
  --embedded-stateless-mcp-stub \
  --health.listen-addr 127.0.0.1:0
