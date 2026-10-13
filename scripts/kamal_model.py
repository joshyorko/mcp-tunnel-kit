"""Render the checked-in, accessory-only Kamal 2.12 deployment model."""

import json
import re
import sys
from pathlib import PurePosixPath

_REPOSITORIES = {
    "cas": "ghcr.io/joshyorko/codex-action-server",
    "executor": "ghcr.io/usefulsoftwareco/executor-selfhost:2.0.0-beta.12",
    "schema_proxy": "ghcr.io/joshyorko/codex-action-server",
    "tunnel": "ghcr.io/openai/tunnel-client:v0.0.15",
}
_PROFILE_KEYS = {
    "host",
    "network",
    "ssh_user",
    "ssh_key",
    "ssh_known_hosts",
    "ssh_config",
    "state_dir",
    "repo_dir",
    "cas_ssh_config_source",
    "cas_ssh_known_hosts_source",
    "cas_identity_source",
    "devsy",
}


def _invalid():
    raise ValueError("invalid_kamal_deploy_model")


def _keys(value, expected):
    return isinstance(value, dict) and set(value) == set(expected)


def _path(value):
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or ":" in value
        or any(ord(char) < 32 for char in value)
    ):
        _invalid()
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        _invalid()
    return value


def validate_manifest(manifest):
    """Validate pinned public image metadata and return its canonical image refs."""
    if (
        not _keys(manifest, {"version", "images"})
        or type(manifest.get("version")) is not int
        or manifest["version"] != 1
    ):
        _invalid()
    images = manifest["images"]
    if not _keys(images, _REPOSITORIES):
        _invalid()
    references = {}
    for name, repository in _REPOSITORIES.items():
        image = images[name]
        fields = (
            {"repository", "digest", "revision"}
            if name in {"cas", "schema_proxy"}
            else {"repository", "digest"}
        )
        if not _keys(image, fields) or image.get("repository") != repository:
            _invalid()
        digest = image.get("digest")
        if not isinstance(digest, str) or not re.fullmatch(
            r"sha256:[a-f0-9]{64}", digest
        ):
            _invalid()
        if name in {"cas", "schema_proxy"}:
            revision = image.get("revision")
            if not isinstance(revision, str) or not re.fullmatch(
                r"[a-f0-9]{40}", revision
            ):
                _invalid()
        references[name] = repository + "@" + digest
    return references


def _validate_profile(profile):
    if not _keys(profile, _PROFILE_KEYS):
        _invalid()
    if not isinstance(profile.get("host"), str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", profile["host"]):
        _invalid()
    if not isinstance(profile.get("ssh_user"), str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", profile["ssh_user"]):
        _invalid()
    network = profile.get("network")
    if not _keys(network, {"name", "subnet", "gateway"}) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", str(network.get("name", ""))):
        _invalid()
    try:
        import ipaddress
        subnet = ipaddress.ip_network(network["subnet"], strict=True)
        gateway = ipaddress.ip_address(network["gateway"])
    except (ValueError, TypeError):
        _invalid()
    if subnet.version != 4 or gateway.version != 4 or gateway not in subnet or gateway in (subnet.network_address, subnet.broadcast_address):
        _invalid()
    for key in (
        "ssh_key",
        "ssh_known_hosts",
        "ssh_config",
        "state_dir",
        "repo_dir",
        "cas_ssh_config_source",
        "cas_ssh_known_hosts_source",
    ):
        _path(profile.get(key))
    identity = profile.get("cas_identity_source")
    if identity is not None:
        _path(identity)
    devsy = profile.get("devsy")
    if devsy is not None:
        allowed = {"config_source", "context_dir", "kubeconfig_source", "context"}
        if not _keys(devsy, allowed):
            _invalid()
        for key in ("config_source", "context_dir", "kubeconfig_source"):
            _path(devsy.get(key))
        if not isinstance(devsy.get("context"), str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,128}", devsy["context"]
        ):
            _invalid()
    return profile


def _accessory(service, image, host, network, *, options=None, **values):
    result = {
        "service": service,
        "image": image,
        "host": host,
        "network": network,
        "options": {"restart": "unless-stopped", **(options or {})},
    }
    result.update(values)
    return result


def render(profile, manifest):
    """Return a Kamal config as JSON (valid YAML), with no secret contents."""
    profile = _validate_profile(profile)
    images = validate_manifest(manifest)
    host = profile["host"]
    state = profile["state_dir"]
    secret_dir = state + "/secrets"
    repo = profile["repo_dir"]
    network = profile["network"]["name"]
    gateway = profile["network"]["gateway"]

    executor = _accessory(
        "mcp-control-plane-executor",
        images["executor"],
        host,
        network,
        options={
            "user": "1000:1000",
            "network-alias": "executor",
            "log-opt": "max-size=10m",
            "health-cmd": "executor-host health",
            "health-interval": "10s",
            "health-timeout": "5s",
            "health-start-period": "30s",
            "health-retries": 12,
        },
        port="127.0.0.1:4312:4312",
        env={
            "clear": {
                "DO_NOT_TRACK": "1",
                "EXECUTOR_DISABLE_ANALYTICS": "1",
                "HOST": "0.0.0.0",
                "PORT": "4312",
                "BETTER_AUTH_URL": "http://127.0.0.1:4312",
                "EXECUTOR_DATA_DIR": "/app/data",
                "EXECUTOR_APPS_ALLOW_PRIVATE_FETCH": "true",
                "EXECUTOR_URL_ALLOW_HTTP_ORIGINS": json.dumps(
                    [f"http://{gateway}:8088", f"http://{gateway}:8089"],
                    separators=(",", ":"),
                ),
            }
        },
        volumes=["codex-control-plane_executor-data:/app/data"],
    )

    schema_proxy = _accessory(
        "mcp-control-plane-schema-proxy",
        images["schema_proxy"],
        host,
        network,
        options={
            "entrypoint": "python3",
            "user": "1000:1000",
            "network-alias": "executor-schema-proxy",
            "read-only": True,
            "cap-drop": ["ALL"],
            "security-opt": "no-new-privileges:true",
            "log-driver": "none",
            "health-cmd": "python3 -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:4313/healthz', timeout=2).read()\"",
            "health-interval": "10s",
            "health-timeout": "3s",
            "health-retries": 3,
        },
        cmd="/opt/tunnel-kit/executor_schema_proxy.py",
        volumes=[
            f"{repo}/scripts/executor_schema_proxy.py:/opt/tunnel-kit/executor_schema_proxy.py:ro"
        ],
    )

    cas_volumes = [
        f"{state}/cas-targets.json:/run/codex-action-server/targets.json:ro",
        f"{state}/cas:/var/lib/codex-action-server",
        f"{state}/cas/runtime:/var/lib/codex-action-server/runtime",
        f"{state}/cas/receipts:/var/lib/codex-action-server/receipts",
        f"{profile['cas_ssh_config_source']}:/run/codex-ssh/ssh_config:ro",
        f"{profile['cas_ssh_known_hosts_source']}:/run/codex-ssh/known_hosts:ro",
    ]
    if profile["cas_identity_source"] is not None:
        cas_volumes.append(
            f"{profile['cas_identity_source']}:/run/codex-ssh/identity:ro"
        )

    devsy = profile["devsy"]
    devsy_home = "/run/operator-devsy"
    if devsy is not None:
        devsy_home = "/tmp"
        cas_volumes.extend(
            [
                f"{devsy['config_source']}:{devsy_home}/config.yaml:ro",
                f"{devsy['context_dir']}:{devsy_home}/contexts/{devsy['context']}:ro",
                f"{devsy['kubeconfig_source']}:{devsy['kubeconfig_source']}:ro",
            ]
        )

    cas = _accessory(
        "mcp-control-plane-cas",
        images["cas"],
        host,
        "host",
        options={
            "user": "1000:1000",
            "read-only": True,
            "log-opt": "max-size=10m",
            "cap-drop": ["ALL"],
            "security-opt": "no-new-privileges:true",
            "tmpfs": "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
            "health-cmd": "python3 /opt/codex-action-server/scripts/container_health.py",
            "health-interval": "10s",
            "health-timeout": "20s",
            "health-start-period": "90s",
            "health-retries": 18,
        },
        env={
            "clear": {
                "CODEX_ACTION_BRIDGE_GATEWAY": gateway,
                "CODEX_ACTION_PORT": "8088",
                "CODEX_ACTION_TARGETS": "/run/codex-action-server/targets.json",
                "CODEX_ACTION_DYNAMIC_TARGETS": "/var/lib/codex-action-server/dynamic-targets.json",
                "CODEX_ACTION_WORKER_AUTHORITY": f"http://{gateway}:8089/worker-authorized",
                "CODEX_ACTION_DATA": "/var/lib/codex-action-server/runtime",
                "CODEX_ACTION_RECEIPTS": "/var/lib/codex-action-server/receipts",
                "ACTIONS_HOME": "/var/lib/codex-action-server/actions",
                "DEVSY_HOME": devsy_home,
            }
        },
        volumes=cas_volumes,
    )

    tunnel = _accessory(
        "mcp-control-plane-tunnel",
        images["tunnel"],
        host,
        network,
        options={
            "entrypoint": "/bin/sh",
            "log-driver": "none",
            "health-cmd": "/usr/bin/tunnel-client health --url http://127.0.0.1:8080 --require-control-plane-poll",
            "health-interval": "10s",
            "health-timeout": "10s",
            "health-start-period": "15s",
            "health-retries": 9,
        },
        cmd="/opt/tunnel-kit/tunnel-start.sh /bin/sh /opt/tunnel-kit/tunnel-secrets.sh",
        volumes=[
            f"{repo}/config/compose-tunnel.yaml:/etc/tunnel-client/config.yaml:ro",
            f"{repo}/scripts/tunnel-start.sh:/opt/tunnel-kit/tunnel-start.sh:ro",
            f"{repo}/scripts/tunnel-secrets.sh:/opt/tunnel-kit/tunnel-secrets.sh:ro",
            f"{secret_dir}/control-plane-api-key:/run/secrets/control-plane-api-key:ro",
            f"{secret_dir}/control-plane-tunnel-id:/run/secrets/control-plane-tunnel-id:ro",
            f"{secret_dir}/executor-auth-header:/run/secrets/executor-auth-header:ro",
        ],
    )

    config = {
        "service": "mcp-control-plane",
        "image": images["cas"],
        "builder": {"arch": "amd64"},
        # Suppress Kamal's implicit max-size for driver=none accessories.
        # Executor/CAS retain bounded json-file logs through their own options.
        "logging": {"driver": "json-file"},
        "servers": {"web": {"hosts": [host], "proxy": False}},
        # Kamal 2.12 matches local registries with /^localhost[:$]/, so a port
        # is required. Accessory prepare skips login; no registry is started.
        "registry": {
            "server": "localhost:5555",
            "username": "unused",
            "password": "unused",
        },
        "ssh": {
            "user": profile["ssh_user"],
            "keys": [profile["ssh_key"]],
            "keys_only": True,
            "forward_agent": False,
            "config": profile["ssh_config"],
        },
        # Preserve dependency order for the workflow that boots accessories individually.
        "accessories": {
            "executor": executor,
            "schema-proxy": schema_proxy,
            "cas": cas,
            "tunnel": tunnel,
        },
    }
    return json.dumps(config, indent=2) + "\n"


def main():
    try:
        request = json.load(sys.stdin)
        if not _keys(request, {"profile", "manifest"}):
            _invalid()
        sys.stdout.write(render(request["profile"], request["manifest"]))
        return 0
    except (OSError, TypeError, ValueError):
        print("invalid_kamal_deploy_model", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
