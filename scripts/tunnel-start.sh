#!/bin/sh
# Docker restarts containers independently at boot. Do not let the tunnel cache
# an initial OAuth-discovery failure while its private upstream is still down.
set +x
set -eu
[ "$#" -gt 0 ] || exit 2
until wget -q -T 5 -O /dev/null http://executor-schema-proxy:4313/healthz; do
  sleep 2
done
exec "$@"
