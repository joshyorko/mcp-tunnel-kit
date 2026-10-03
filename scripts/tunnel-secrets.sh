#!/bin/sh
set +x
set -eu
# The stock CLI supports file references for keys/headers, but not the tunnel ID.
# Read only the ID into the supported environment; never put it in argv or logs.
if ! IFS= read -r CONTROL_PLANE_TUNNEL_ID < /run/secrets/control-plane-tunnel-id; then
  [ -n "${CONTROL_PLANE_TUNNEL_ID:-}" ] || exit 2
fi
export CONTROL_PLANE_TUNNEL_ID
exec /usr/bin/tunnel-client run --config /etc/tunnel-client/config.yaml --log.http-raw-unsafe=false
