"""Load the private, per-instance control-plane deployment profile."""
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


DEFAULT_PATH = Path.home() / ".config/mcp-control-plane/instance.json"
MAX_BYTES = 32768


def _keys(value, expected):
    return isinstance(value, dict) and set(value) == set(expected)


def _path(value):
    if (not isinstance(value, str) or not value.startswith("/")
            or any(ord(char) < 32 for char in value)):
        raise ValueError("Instance profile contains an invalid path")
    parsed = PurePosixPath(value)
    if not parsed.is_absolute() or ".." in parsed.parts or str(parsed) != value:
        raise ValueError("Instance profile contains an invalid path")
    return value


def validate(value):
    """Validate and return the exact supported schema without reading host files."""
    if not _keys(value, {"schema_version", "deploy_host", "vm"}) or type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("Instance profile schema is unsupported")
    host = value["deploy_host"]
    if not _keys(host, {"alias", "address", "user", "host_key_fingerprint"}):
        raise ValueError("Instance profile deploy host is incomplete")
    if not isinstance(host["alias"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", host["alias"]):
        raise ValueError("Instance profile deploy host alias is invalid")
    try:
        ipaddress.IPv4Address(host["address"])
    except (ValueError, TypeError):
        raise ValueError("Instance profile deploy host address is invalid") from None
    if not isinstance(host["user"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", host["user"]):
        raise ValueError("Instance profile deploy host user is invalid")
    if not isinstance(host["host_key_fingerprint"], str) or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", host["host_key_fingerprint"]):
        raise ValueError("Instance profile host-key fingerprint is invalid")

    vm = value["vm"]
    if not _keys(vm, {"repo_dir", "state_dir", "network", "native_ssh_dir", "devsy"}):
        raise ValueError("Instance profile VM configuration is incomplete")
    for key in ("repo_dir", "state_dir", "native_ssh_dir"):
        _path(vm[key])
    network = vm["network"]
    if not _keys(network, {"name", "subnet", "gateway"}) or not isinstance(network["name"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", network["name"]):
        raise ValueError("Instance profile network is invalid")
    try:
        subnet = ipaddress.ip_network(network["subnet"], strict=True)
        gateway = ipaddress.ip_address(network["gateway"])
    except (ValueError, TypeError):
        raise ValueError("Instance profile network is invalid") from None
    if subnet.version != 4 or gateway.version != 4 or gateway not in subnet or gateway in (subnet.network_address, subnet.broadcast_address):
        raise ValueError("Instance profile network is invalid")
    devsy = vm["devsy"]
    if not _keys(devsy, {"config_source", "context_dir", "kubeconfig_source", "context"}):
        raise ValueError("Instance profile Devsy paths are incomplete")
    for key in ("config_source", "context_dir", "kubeconfig_source"):
        _path(devsy[key])
    if not isinstance(devsy["context"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", devsy["context"]):
        raise ValueError("Instance profile Devsy context is invalid")
    return value


def load(path=None):
    """Read a caller-owned mode-0600 profile, rejecting symlinks and oversized files."""
    path = Path(path) if path is not None else DEFAULT_PATH
    if not path.is_absolute():
        raise ValueError("Instance profile path must be absolute")
    try:
        metadata = path.lstat()
        if (path.is_symlink() or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid() or metadata.st_mode & 0o777 != 0o600):
            raise ValueError("Instance profile must be an owned, mode-0600 regular file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                or opened.st_mode & 0o777 != 0o600):
            os.close(fd)
            raise ValueError("Instance profile must be an owned, mode-0600 regular file")
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Instance profile is too large")
        return validate(json.loads(raw))
    except FileNotFoundError:
        raise ValueError("Private instance profile is missing; install it at " + str(path) + " before deployment") from None
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Private instance profile is unavailable or invalid") from None


def encode(value):
    """Serialize validated non-secret instance settings for the private VM boundary."""
    import base64
    return base64.b64encode(json.dumps(validate(value), separators=(",", ":")).encode()).decode()


def decode(value):
    """Decode and validate a profile argument sent over the pinned SSH connection."""
    import base64
    try:
        return validate(json.loads(base64.b64decode(value, validate=True)))
    except (ValueError, TypeError, json.JSONDecodeError):
        raise ValueError("Remote instance profile is invalid") from None
