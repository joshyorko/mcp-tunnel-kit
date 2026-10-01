# PLACEHOLDERS ONLY. Copy to launcher.local.zsh (ignored), chmod 600,
# and edit locally. Do not launch with these unmodified values.
# Use existing credentials; this file does not create or rotate them.

export CONTROL_PLANE_API_KEY='REPLACE_WITH_EXISTING_CONTROL_PLANE_API_KEY'
export CONTROL_PLANE_TUNNEL_ID='REPLACE_WITH_EXISTING_TUNNEL_ID'
export TUNNEL_CLIENT_BIN='/absolute/path/to/tunnel-client'

# Default profile file: $HOME/.hermes/profiles/friday/.env
# Prefer the existing protected profile file, or select a protected local copy.
export FRIDAY_API_ENV_FILE="$HOME/.hermes/profiles/friday/.env"

# Numeric loopback and the Friday profile route are mandatory.
export FRIDAY_API_BASE_URL='http://127.0.0.1:8642/p/friday'
export FRIDAY_HTTP_TIMEOUT_SECONDS='30'

# Optional overrides; defaults use the checkout .venv and XDG state directory.
# export FRIDAY_BRIDGE_PYTHON='/absolute/path/to/dependency-installed/python'
# export FRIDAY_RUN_REGISTRY="$HOME/.local/state/friday-chatgpt-tunnel/runs.json"
