#!/usr/bin/env zsh
unsetopt XTRACE VERBOSE
set -euo pipefail

if [[ $# -ne 0 && ! ( $# == 1 && "$1" == "--check" ) ]]; then
  print -u2 -- "usage: ./launch-executor.zsh [--check]"
  exit 2
fi

typeset -r EXECUTOR="${EXECUTOR_BIN:-executor}"
node -e 'const [a,b] = process.versions.node.split(".").map(Number); process.exit(a > 24 || a === 24 && b >= 14 ? 0 : 2)' || {
  print -u2 -- "Executor requires Node >=24.14.0"
  exit 2
}
[[ "$("$EXECUTOR" --version)" == "executor v2.0.0-beta.8" ]] || {
  print -u2 -- "Install the pinned executor@2.0.0-beta.8 package"
  exit 2
}

export EXECUTOR_DATA_DIR="${EXECUTOR_DATA_DIR:-$HOME/.local/share/executor}"
export EXECUTOR_KEY_STORAGE=file EXECUTOR_PORT=4312 EXECUTOR_NO_UPDATE_CHECK=1
# This installation uses upstream's persistent file keystore, not supplied keys.
unset EXECUTOR_API_KEY EXECUTOR_ENCRYPTION_KEY
umask 077
if [[ -e "$EXECUTOR_DATA_DIR" ]]; then
  [[ -d "$EXECUTOR_DATA_DIR" && ! -L "$EXECUTOR_DATA_DIR" &&
     "$(stat -c %a "$EXECUTOR_DATA_DIR")" == 700 &&
     "$(stat -c %u "$EXECUTOR_DATA_DIR")" == "$(id -u)" ]] || {
    print -u2 -- "Executor data directory must be owned by you with mode 0700"
    exit 2
  }
fi
if [[ "${1:-}" == "--check" ]]; then
  print -- "Pinned Executor prerequisites valid; no server was started."
  exit 0
fi
mkdir -p -m 700 -- "$EXECUTOR_DATA_DIR"
# beta.8 prints a secret one-use pairing URL even with serve. Never log it.
"$EXECUTOR" serve 2>&1 | sed -u '/#pair=/d'
