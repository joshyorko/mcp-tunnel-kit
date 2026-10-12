# Run the locked Kamal CLI with an anonymous Docker config on its SSH hosts.
require "sshkit"

PUBLIC_DOCKER_CONFIG = "/home/kdlocpanda/.local/share/codex-control-plane/deployment/anonymous-docker-config"
config = ENV.fetch("KAMAL_PUBLIC_DOCKER_CONFIG")
abort "Unapproved anonymous Docker config path" unless config == PUBLIC_DOCKER_CONFIG

SSHKit.config.default_env = (SSHKit.config.default_env || {}).merge("DOCKER_CONFIG" => config)
load Gem.bin_path("kamal", "kamal")
