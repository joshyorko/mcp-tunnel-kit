# PLACEHOLDERS ONLY. Optional ignored local configuration; chmod 600.
# If your shell already exports these values, keep using it. Do not duplicate,
# rotate or print credentials, and do not create another tunnel registration.
export CONTROL_PLANE_API_KEY='REPLACE_WITH_EXISTING_CONTROL_PLANE_API_KEY'
export CONTROL_PLANE_TUNNEL_ID='REPLACE_WITH_EXISTING_TUNNEL_ID'
export TUNNEL_CLIENT_BIN='/absolute/path/to/tunnel-client'

# Normal foreground path: launch-executor.zsh, then launch-executor-tunnel.zsh.
# Upstream file keystore and generated private tunnel-auth-header live here.
export EXECUTOR_DATA_DIR="$HOME/.local/share/executor"
export EXECUTOR_MCP_URL='http://127.0.0.1:4312/mcp'

# Inactive direct break-glass only. Stop the normal tunnel before using it.
export CODEX_MCP_URL='http://127.0.0.1:8088/mcp'

# Optional readiness-check interpreter; defaults to this checkout's .venv.
# export CODEX_CHECK_PYTHON='/absolute/path/to/dependency-installed/python'

# No Hermes profile API key, /p/friday URL, or FRIDAY target changes required.
# Tool calls use payload.target = "local". Native forwarding keeps upstream
# schemas intact, including any other operator-configured target enum members.
