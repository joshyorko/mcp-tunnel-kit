#!/usr/bin/env python3
"""Idempotent VM-host Devsy installation and drift checks."""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.request


class BootstrapError(ValueError):
    """Fixed, credential-free failure raised at the VM bootstrap boundary."""


POLICY_PATH = Path(__file__).resolve().parents[1] / "config/devsy-vm-bootstrap.json"
UNIT_TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "config/codex-control-plane-devsy.service.in"
UNIT_PATH = Path("/etc/systemd/system/codex-control-plane-devsy.service")
MISSING_KUBECTL_REASON = "pinned kubectl is missing; ROR admission preflight was not run"
KUBECTL_CONFLICT_REASON = "kubectl candidate failed pinned source/hash validation"
MAX_TAP_RECONCILIATION_BYTES = 512 * 1024 * 1024
ISSUE27_TAP_RECONCILIATION = {
    "case_id": "issue-27-tap-523d-to-141f",
    "failed_run_id": "38586057895",
    "prior_backup_directory": "1791990283017830779",
    "prior_backup_manifest_sha256": "8e2c329a6a593fa807e22115db2e937ac227becf979242f2ab4898bf533362e9",
    "prior_backup_signed": False,
    "observed_tap_revision": "523d8a0b85db367c34af749eefba81a25dd26768",
    "upstream_main_revision": "523d8a0b85db367c34af749eefba81a25dd26768",
    "target_tap_revision": "141faa0977de2c2d840ee847ddfec08da9d5a974",
    "current_vm_source_sha": "510444adbfec4645d24c7b681b0faa7e1d965d3e",
}


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def classify_bridge_health_response(value: object, expected_instance: object) -> str:
    if not isinstance(value, dict):
        return "invalid-response"
    if value.get("ready") is not True:
        return "not-ready"
    if value.get("instance") != expected_instance:
        return "instance-mismatch"
    if set(value) != {"ready", "instance"}:
        return "unexpected-response-fields"
    return "healthy"


def host_bridge_health_opener():
    from http.client import HTTPConnection
    from urllib.request import HTTPHandler, HTTPRedirectHandler, ProxyHandler, build_opener

    class HostHTTP(HTTPHandler):
        def http_open(self, request):
            return self.do_open(HTTPConnection, request,
                                source_address=("127.0.0.1", 0))

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *_args):
            return None

    # Match devsy_bridge.host_opener for Docker gateway-to-host traffic.
    return build_opener(ProxyHandler({}), HostHTTP(), NoRedirect())


def validate_tap_reconciliation_case(policy: dict) -> dict:
    if (not isinstance(policy, dict)
            or ISSUE27_TAP_RECONCILIATION["target_tap_revision"]
            != policy.get("devsy", {}).get("tap_revision")):
        raise BootstrapError("incident reconciliation policy mismatch")
    return dict(ISSUE27_TAP_RECONCILIATION)


def validate_tap_reconciliation_source(source_sha: str, dirty: str, case: dict) -> str:
    if (source_sha != case.get("current_vm_source_sha")
            or not re.fullmatch(r"[a-f0-9]{40}", source_sha or "") or dirty):
        raise BootstrapError("VM source checkout differs from the verified incident baseline")
    return source_sha


def validate_tap_reconciliation_manifest(manifest: dict, case: dict, policy: dict) -> dict:
    files = manifest.get("files") if isinstance(manifest, dict) else None
    expected_files = {"unit", "starter", "bridge_config", "receipt", "devsy_config", "kubectl"}
    if (not isinstance(files, dict) or set(files) != expected_files
            or any(type(present) is not bool for present in files.values())
            or manifest.get("schema_version") != 1
            or not re.fullmatch(r"[a-f0-9]{40}", str(manifest.get("source_sha", "")))
            or manifest.get("tap_was_present") is not False
            or manifest.get("tap_revision") is not None
            or manifest.get("provider_was_verified") is not True
            or files.get("kubectl") is not False
            or manifest.get("kubectl_version") is not None
            or manifest.get("kubectl_sha256") is not None
            or manifest.get("devsy_version") != policy["devsy"]["legacy_version"]
            or manifest.get("devsy_sha256") != policy["devsy"]["legacy_sha256"]
            or case.get("prior_backup_signed") is not False):
        raise BootstrapError("prior backup is not the expected baseline")
    return {"source_sha": manifest["source_sha"],
            "devsy_version": manifest["devsy_version"],
            "tap_was_present": False,
            "prior_backup_authenticated": False}


def tap_tree_manifest(root: Path, owner_uid: int,
                      max_bytes: int = MAX_TAP_RECONCILIATION_BYTES) -> dict:
    root = Path(root)
    try:
        root_info = root.lstat()
    except OSError:
        raise BootstrapError("tap snapshot root is unavailable") from None
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != owner_uid):
        raise BootstrapError("unsafe tap snapshot root")

    entries = [{"path": ".", "kind": "directory",
                "mode": stat.S_IMODE(root_info.st_mode)}]
    pending = [root]
    total_bytes = 0
    file_count = 0
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda path: path.name)
        except OSError:
            raise BootstrapError("tap snapshot tree changed during inspection") from None
        for path in children:
            relative = path.relative_to(root).as_posix()
            try:
                before = path.lstat()
            except OSError:
                raise BootstrapError("tap snapshot tree changed during inspection") from None
            if before.st_uid != owner_uid or stat.S_ISLNK(before.st_mode):
                raise BootstrapError("unsafe tap snapshot path")
            if stat.S_ISDIR(before.st_mode):
                entries.append({"path": relative, "kind": "directory",
                                "mode": stat.S_IMODE(before.st_mode)})
                pending.append(path)
                continue
            if not stat.S_ISREG(before.st_mode):
                raise BootstrapError("unsupported file in tap snapshot")
            if total_bytes + before.st_size > max_bytes:
                raise BootstrapError("tap snapshot exceeds its size limit")
            digest = hashlib.sha256()
            size = 0
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "rb") as stream:
                    opened = os.fstat(stream.fileno())
                    if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != owner_uid
                            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
                        raise BootstrapError("tap snapshot path changed during inspection")
                    while chunk := stream.read(1024 * 1024):
                        size += len(chunk)
                        if total_bytes + size > max_bytes:
                            raise BootstrapError("tap snapshot exceeds its size limit")
                        digest.update(chunk)
                    after = os.fstat(stream.fileno())
            except BootstrapError:
                raise
            except OSError:
                raise BootstrapError("tap snapshot file is unavailable") from None
            if (size != before.st_size
                    or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)):
                raise BootstrapError("tap snapshot file changed during inspection")
            total_bytes += size
            file_count += 1
            entries.append({"path": relative, "kind": "file",
                            "mode": stat.S_IMODE(before.st_mode),
                            "size": size, "sha256": digest.hexdigest()})

    entries.sort(key=lambda entry: entry["path"])
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": sha256(encoded), "bytes": total_bytes,
            "files": file_count, "entries": entries}


def copy_tap_tree(source: Path, destination: Path, owner_uid: int,
                  max_bytes: int = MAX_TAP_RECONCILIATION_BYTES) -> dict:
    source = Path(source)
    destination = Path(destination)
    before = tap_tree_manifest(source, owner_uid, max_bytes)
    temporary = destination.with_name(destination.name + ".new-" + str(os.getpid()))
    created = False
    try:
        if destination.exists() or destination.is_symlink():
            raise BootstrapError("tap snapshot destination already exists")
        parent = destination.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode) or parent.st_uid != owner_uid:
            raise BootstrapError("tap snapshot destination directory is unsafe")
        if temporary.exists() or temporary.is_symlink():
            raise BootstrapError("tap snapshot temporary path already exists")
        created = True
        shutil.copytree(source, temporary, copy_function=shutil.copy2, symlinks=True)
        copied = tap_tree_manifest(temporary, owner_uid, max_bytes)
        if copied["sha256"] != before["sha256"]:
            raise BootstrapError("tap snapshot copy did not match its source")
        os.replace(temporary, destination)
        return before
    except BootstrapError:
        if created and temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        raise
    except OSError:
        if created and temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        raise BootstrapError("tap snapshot copy failed") from None


def restore_tap_tree(snapshot: Path, destination: Path, failed_snapshot: Path,
                     expected_sha256: str, owner_uid: int,
                     max_bytes: int = MAX_TAP_RECONCILIATION_BYTES) -> dict:
    snapshot = Path(snapshot)
    destination = Path(destination)
    failed_snapshot = Path(failed_snapshot)
    saved = tap_tree_manifest(snapshot, owner_uid, max_bytes)
    if saved["sha256"] != expected_sha256:
        raise BootstrapError("tap recovery snapshot checksum mismatch")
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise BootstrapError("tap recovery destination is unsafe")
    if destination.exists():
        failed = copy_tap_tree(destination, failed_snapshot, owner_uid, max_bytes)
    else:
        failed = {"sha256": None, "bytes": 0, "files": 0, "entries": []}

    parent = destination.parent
    staging = parent / ("." + destination.name + ".restore-" + str(os.getpid()))
    old = parent / ("." + destination.name + ".old-" + str(os.getpid()))
    try:
        if staging.exists() or staging.is_symlink() or old.exists() or old.is_symlink():
            raise BootstrapError("tap recovery staging path already exists")
        shutil.copytree(snapshot, staging, copy_function=shutil.copy2, symlinks=True)
        if tap_tree_manifest(staging, owner_uid, max_bytes)["sha256"] != expected_sha256:
            raise BootstrapError("tap recovery staging copy checksum mismatch")
        if destination.exists():
            os.replace(destination, old)
        try:
            os.replace(staging, destination)
        except OSError:
            if old.exists() and not destination.exists():
                os.replace(old, destination)
            raise
        restored = tap_tree_manifest(destination, owner_uid, max_bytes)
        if restored["sha256"] != expected_sha256:
            bad = parent / ("." + destination.name + ".bad-" + str(os.getpid()))
            if bad.exists() or bad.is_symlink():
                raise BootstrapError("tap recovery failed and preserved both trees")
            os.replace(destination, bad)
            if old.exists():
                os.replace(old, destination)
            raise BootstrapError("tap recovery did not restore the saved tree")
        if old.exists():
            shutil.rmtree(old)
        return {"restored_sha256": restored["sha256"],
                "failed_sha256": failed["sha256"],
                "failed_bytes": failed["bytes"], "failed_files": failed["files"]}
    except BootstrapError:
        raise
    except OSError:
        if old.exists() and not destination.exists():
            try:
                os.replace(old, destination)
            except OSError:
                pass
        raise BootstrapError("tap recovery replacement failed") from None
    finally:
        if staging.exists() and not staging.is_symlink():
            shutil.rmtree(staging, ignore_errors=True)


def load_policy(path: Path = POLICY_PATH) -> dict:
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise BootstrapError("VM Devsy bootstrap policy is unavailable or invalid") from None
    if (not isinstance(value, dict) or value.get("schema_version") != 1
            or not isinstance(value.get("homebrew"), dict)
            or not isinstance(value.get("devsy"), dict)
            or not isinstance(value.get("kubectl"), dict)
            or not isinstance(value.get("provider"), dict)):
        raise BootstrapError("VM Devsy bootstrap policy schema is unsupported")
    validate_kubectl_policy(value["kubectl"])
    return value


def validate_kubectl_policy(value: dict) -> None:
    version = value.get("version")
    architecture = value.get("architecture")
    artifacts = value.get("artifact_sha256")
    expected_architecture = {"x86_64": "amd64", "aarch64": "arm64"}
    if (not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version)
            or value.get("source_url") !=
            f"https://dl.k8s.io/release/v{version}/bin/linux/{{arch}}/kubectl"
            or architecture != expected_architecture or not isinstance(artifacts, dict)
            or set(artifacts) != set(expected_architecture)
            or any(not isinstance(artifacts.get(arch), str)
                   or not re.fullmatch(r"[a-f0-9]{64}", artifacts[arch])
                   for arch in expected_architecture)
            or type(value.get("max_bytes")) is not int
            or not 1 <= value["max_bytes"] <= 256 * 1024 * 1024
            or value.get("install_location") != "private-devsy-state/bin/kubectl"):
        raise BootstrapError("pinned kubectl policy is invalid")


def canonical_architecture(machine: str) -> str | None:
    return {
        "aarch64": "aarch64",
        "arm64": "aarch64",
        "x86_64": "x86_64",
        "amd64": "x86_64",
    }.get(machine.lower())


def validate_platform(system: str, machine: str) -> None:
    if system != "Linux" or canonical_architecture(machine) is None:
        raise BootstrapError("unsupported host platform; expected Linux AMD64 or ARM64")


def _resource_pairs(resources: dict) -> list[str]:
    return [f"{scope}.{name}={value}"
            for scope in ("requests", "limits")
            for name, value in resources[scope].items()]


def provider_options(policy: dict, kubeconfig: str) -> dict[str, str]:
    provider = policy["provider"]
    if (provider.get("name") != "kubernetes" or provider.get("default") is not True
            or provider.get("kubernetes_context") != "ror"
            or provider.get("namespace") != "devsy"
            or provider.get("create_namespace") is not False):
        raise BootstrapError("VM provider policy must bind the existing ROR Kubernetes namespace")
    selector = ",".join(f"{key}={value}" for key, value in sorted(provider["node_selector"].items()))
    init = provider["init_resources"]
    template = "\n".join((
        "spec:",
        f"  automountServiceAccountToken: {'true' if provider['automount_service_account_token'] else 'false'}",
        "  initContainers:",
        f"    - name: {provider['init_container']}",
        "      resources:",
        "        requests:",
        f"          cpu: \"{init['requests']['cpu']}\"",
        f"          memory: \"{init['requests']['memory']}\"",
        "        limits:",
        f"          cpu: \"{init['limits']['cpu']}\"",
        f"          memory: \"{init['limits']['memory']}\"",
    ))
    return {
        "KUBERNETES_CONFIG": kubeconfig,
        "KUBERNETES_CONTEXT": provider["kubernetes_context"],
        "KUBERNETES_NAMESPACE": provider["namespace"],
        "CREATE_NAMESPACE": "false",
        "NODE_SELECTOR": selector,
        "RESOURCES": ",".join(_resource_pairs(provider["resources"])),
        "POD_MANIFEST_TEMPLATE": template,
    }


def inspect_provider_state(listing: dict, policy: dict, kubeconfig: str) -> dict:
    """Accept the selected Kubernetes provider and only the issue's known baseline drift."""
    if not isinstance(listing, dict):
        raise BootstrapError("Devsy provider inventory is invalid")
    defaults = [name for name, row in listing.items()
                if isinstance(row, dict) and row.get("default") is True]
    row = listing.get("kubernetes")
    if row is None or not isinstance(row, dict) or defaults != ["kubernetes"]:
        raise BootstrapError("provider identity drift; preserving the existing default provider")
    option_rows = row.get("state", {}).get("options", {})
    if not isinstance(option_rows, dict):
        raise BootstrapError("Devsy Kubernetes provider options are unavailable")
    current = {}
    for name, value in option_rows.items():
        if isinstance(value, dict):
            current[name] = str(value.get("value", value.get("default", "")))
    desired = provider_options(policy, kubeconfig)
    legacy = policy["provider"].get("legacy_options", {})
    for name in ("CREATE_NAMESPACE", "KUBERNETES_CONTEXT", "KUBERNETES_NAMESPACE"):
        if current.get(name, "") != desired[name]:
            raise BootstrapError("provider identity drift; preserving the existing Kubernetes binding")
    changes = []
    for name, target in desired.items():
        observed = current.get(name, "")
        allowed = {target}
        if name in legacy:
            allowed.add(str(legacy[name]))
        if name == "KUBERNETES_CONFIG":
            allowed.add("")
        if observed not in allowed:
            raise BootstrapError("provider resource or credential drift; preserving the existing configuration")
        if observed != target:
            changes.append(name)
    return {"name": "kubernetes", "default": True,
            "options": current, "changes": sorted(changes)}


def verify_formula(formula: bytes, policy: dict) -> str:
    devsy = policy["devsy"]
    if sha256(formula) != devsy["formula_sha256"]:
        raise BootstrapError("pinned Josh tap formula checksum mismatch")
    try:
        source = formula.decode("utf-8")
    except UnicodeError:
        raise BootstrapError("pinned Josh tap formula is not valid UTF-8") from None
    version = re.search(r'(?m)^[ \t]*version[ \t]+"([^"]+)"', source)
    artifacts = devsy.get("artifact_sha256")
    if not version or version.group(1) != devsy["version"]:
        raise BootstrapError("pinned Josh tap formula version drifted")
    if not isinstance(artifacts, dict):
        raise BootstrapError("pinned Devsy architecture checksums are unavailable")

    release_base = (devsy["tap_repository"].removesuffix(".git")
                    + "/releases/download/" + devsy["release_tag"])
    for architecture, selector, artifact, label in (
            ("x86_64", "on_intel", "devsy-linux-amd64", "AMD64"),
            ("aarch64", "on_arm", "devsy-linux-arm64", "ARM64")):
        block = re.search(
            rf"(?ms)^[ \t]*{selector}[ \t]+do[ \t]*\n(.*?)(?=^[ \t]*end\b)", source)
        expected_url = f"{release_base}/{artifact}"
        url = (re.search(r'(?m)^[ \t]*url[ \t]+"([^"\n]+)"[ \t]*$', block.group(1))
               if block else None)
        checksum = (re.search(r'(?m)^[ \t]*sha256[ \t]+"([a-f0-9]{64})"[ \t]*$', block.group(1))
                    if block else None)
        expected_checksum = artifacts.get(architecture)
        if (not url or url.group(1) != expected_url or not checksum
                or not isinstance(expected_checksum, str)
                or checksum.group(1) != expected_checksum):
            raise BootstrapError(f"pinned Josh tap formula version or {label} checksum drifted")
    return source


def tap_origin_matches(actual: str, expected: str) -> bool:
    def normalized(origin: str) -> str:
        origin = origin.rstrip("/")
        return origin[:-4] if origin.endswith(".git") else origin

    return normalized(actual) == normalized(expected)


def _cpu_millicores(value: str) -> int:
    try:
        return int(value[:-1]) if value.endswith("m") else int(float(value) * 1000)
    except (TypeError, ValueError, OverflowError):
        raise BootstrapError("ROR returned an invalid CPU quantity") from None


def _memory_bytes(value: str) -> int:
    factors = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3,
               "Ti": 1024**4, "K": 1000, "M": 1000**2,
               "G": 1000**3, "T": 1000**4}
    try:
        for suffix, factor in factors.items():
            if value.endswith(suffix):
                return int(float(value[:-len(suffix)]) * factor)
        return int(value)
    except (TypeError, ValueError, OverflowError):
        raise BootstrapError("ROR returned an invalid memory quantity") from None


def _request_for_pod(pod: dict) -> dict[str, int]:
    spec = pod.get("spec", {})
    app = {"cpu": 0, "memory": 0}
    for container in spec.get("containers", []):
        requests = container.get("resources", {}).get("requests", {})
        app["cpu"] += _cpu_millicores(requests.get("cpu", "0"))
        app["memory"] += _memory_bytes(requests.get("memory", "0"))
    init = {"cpu": 0, "memory": 0}
    for container in spec.get("initContainers", []):
        if container.get("restartPolicy") == "Always":
            raise BootstrapError("ROR pod uses restartable init containers; capacity cannot be bounded")
        requests = container.get("resources", {}).get("requests", {})
        init["cpu"] = max(init["cpu"], _cpu_millicores(requests.get("cpu", "0")))
        init["memory"] = max(init["memory"], _memory_bytes(requests.get("memory", "0")))
    overhead = spec.get("overhead", {})
    return {
        "cpu": max(app["cpu"], init["cpu"]) + _cpu_millicores(overhead.get("cpu", "0")),
        "memory": max(app["memory"], init["memory"]) + _memory_bytes(overhead.get("memory", "0")),
    }


def _unit_value(value: str) -> str:
    if (not isinstance(value, str) or not value or any(ord(c) < 32 for c in value)
            or any(c in value for c in ('"', "'", "%"))):
        raise BootstrapError("systemd bootstrap input contains an unsafe value")
    return value


def render_unit(*, user: str, group: str, repo_dir: str, state_dir: str,
                devsy_bin: str, devsy_home: str, config_source: str,
                context_dir: str, kubeconfig: str,
                template_path: Path = UNIT_TEMPLATE_PATH,
                template_text: str | None = None) -> bytes:
    values = {
        "SERVICE_USER": user,
        "SERVICE_GROUP": group,
        "REPO_DIR": repo_dir,
        "STATE_DIR": state_dir,
        "DEVSY_BIN": devsy_bin,
        "DEVSY_HOME": devsy_home,
        "DEVSY_CONFIG": config_source,
        "DEVSY_CONTEXT_DIR": context_dir,
        "KUBECONFIG": kubeconfig,
    }
    if template_text is None:
        try:
            template_text = Path(template_path).read_text()
        except (OSError, UnicodeError):
            raise BootstrapError("managed Devsy systemd template is unavailable") from None
    result = template_text
    for name, value in values.items():
        result = result.replace("@" + name + "@", _unit_value(value))
    if re.search(r"@[A-Z_]+@", result):
        raise BootstrapError("managed Devsy systemd template has an unresolved input")
    return result.encode()


def classify_unit(current: bytes | None, desired: bytes, legacy_sha256: str) -> str:
    if current is None:
        return "absent"
    digest = sha256(current)
    if digest == sha256(desired):
        return "managed"
    if digest == legacy_sha256:
        return "legacy"
    raise BootstrapError("conflicting systemd unit; preserving the existing unit")


def validate_private_file(path: Path, uid: int) -> None:
    try:
        metadata = Path(path).lstat()
    except OSError:
        raise BootstrapError("required private Devsy credential/config file is missing") from None
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise BootstrapError("private Devsy credential/config file ownership or mode mismatch")


def validate_private_directory(path: Path, uid: int) -> None:
    try:
        metadata = Path(path).lstat()
    except OSError:
        raise BootstrapError("required private Devsy directory is missing") from None
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise BootstrapError("private Devsy directory ownership or mode mismatch")


def _run(arguments: list[str], *, env: dict | None = None,
         timeout: int = 60, input_data: str | None = None) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(arguments, capture_output=True, text=True,
                                timeout=timeout, env=env, input=input_data)
    except (OSError, subprocess.TimeoutExpired):
        raise BootstrapError("VM Devsy bootstrap command failed or timed out") from None
    if result.returncode:
        raise BootstrapError("VM Devsy bootstrap command failed; raw output withheld")
    return result


def _fetch(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.read(2_000_001)
    except (OSError, TimeoutError):
        raise BootstrapError("pinned Homebrew or Josh tap source is unavailable") from None


def _fetch_bounded(url: str, max_bytes: int) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) > max_bytes:
                raise BootstrapError("pinned Kubernetes kubectl exceeds its size limit")
            content = response.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise BootstrapError("pinned Kubernetes kubectl exceeds its size limit")
        return content
    except BootstrapError:
        raise
    except (OSError, TimeoutError) as error:
        reason = getattr(error, "reason", error)
        if (isinstance(reason, TimeoutError)
                or getattr(reason, "errno", None) == errno.ETIMEDOUT):
            raise BootstrapError("pinned Kubernetes kubectl download timed out") from None
        raise BootstrapError("pinned Kubernetes kubectl source is unavailable") from None
    except ValueError:
        raise BootstrapError("pinned Kubernetes kubectl source is unavailable") from None


def validate_platform_current() -> None:
    validate_platform(platform.system(), platform.machine())


class VMDevsyBootstrap:
    """Plan or apply the host-only Devsy CLI, provider and systemd state."""

    def __init__(self, profile: dict, policy: dict | None = None, *,
                 unit_template: str | None = None, runner=None, fetcher=None,
                 system: str | None = None, machine: str | None = None,
                 unit_path: Path = UNIT_PATH, env: dict | None = None,
                 health_probe=None, process_probe=None,
                 starter_source: str | None = None):
        self.profile = profile
        self.policy = policy if policy is not None else load_policy(
            Path(profile["repo_dir"]) / "config/devsy-vm-bootstrap.json")
        validate_kubectl_policy(self.policy.get("kubectl", {}))
        self.unit_template = unit_template
        if self.unit_template is None:
            template = Path(profile["repo_dir"]) / "config/codex-control-plane-devsy.service.in"
            try:
                self.unit_template = template.read_text()
            except (OSError, UnicodeError):
                raise BootstrapError("managed Devsy systemd template is unavailable") from None
        self.runner = runner or subprocess.run
        self.fetcher = fetcher or _fetch
        self.system = system or platform.system()
        host_machine = machine or platform.machine()
        self.machine = canonical_architecture(host_machine) or host_machine
        self.unit_path = Path(unit_path)
        self.env = dict(os.environ if env is None else env)
        self.health_probe = health_probe or self._probe_bridge
        self.process_probe = process_probe or self._process_matches
        self._last_bridge_health_status = "unknown"
        if starter_source is None:
            scripts = Path(profile["repo_dir"]) / "scripts"
            starter_source = (
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "sys.path.insert(0, " + repr(str(scripts)) + ")\n"
                "from host_devsy_service import main\n"
                "raise SystemExit(main())\n"
            )
        self.starter_source = starter_source

    def _command(self, arguments: list[str], *, timeout: int = 60,
                 env: dict | None = None, allow_failure: bool = False,
                 kubectl_preflight: bool = False) -> subprocess.CompletedProcess:
        try:
            result = self.runner(arguments, capture_output=True, text=True,
                                 timeout=timeout, env=env or self.env)
        except subprocess.TimeoutExpired:
            if kubectl_preflight:
                raise BootstrapError("ROR Kubernetes connection timed out") from None
            raise BootstrapError("VM Devsy bootstrap command failed or timed out") from None
        except OSError:
            if kubectl_preflight:
                raise BootstrapError("ROR Kubernetes connection failed") from None
            raise BootstrapError("VM Devsy bootstrap command failed or timed out") from None
        if result.returncode and not allow_failure:
            if kubectl_preflight:
                stderr = result.stderr if isinstance(result.stderr, str) else ""
                detail = stderr.casefold()
                if (("admission webhook" in detail or "admission controller" in detail)
                        and ("denied" in detail or "reject" in detail)):
                    raise BootstrapError("ROR Kubernetes admission request rejected") from None
                if any(marker in detail for marker in (
                        "unauthorized", "authentication required", "provide credentials",
                        "you must be logged in", "invalid bearer token")):
                    raise BootstrapError("ROR Kubernetes authentication failed") from None
                if any(marker in detail for marker in (
                        "forbidden", "cannot get ", "cannot list ", "cannot watch ")):
                    raise BootstrapError("ROR Kubernetes authorization failed") from None
                if any(marker in detail for marker in (
                        "unable to connect", "connection refused", "no route to host",
                        "i/o timeout", "context deadline exceeded", "tls handshake timeout")):
                    raise BootstrapError("ROR Kubernetes connection failed") from None
                raise BootstrapError("ROR Kubernetes command failed; raw output withheld") from None
            raise BootstrapError("VM Devsy bootstrap command failed; raw output withheld")
        return result

    def _validate_inputs(self) -> tuple[Path, Path, Path, Path]:
        validate_platform(self.system, self.machine)
        try:
            devsy = self.profile["devsy"]
            uid = int(self.profile["uid"])
            home = Path(devsy["config_source"]).parent
            state = Path(self.profile["state_dir"])
            repo = Path(self.profile["repo_dir"])
            config = Path(devsy["config_source"])
            context = Path(devsy["context_dir"])
            kubeconfig = Path(devsy["kubeconfig_source"])
        except (KeyError, TypeError, ValueError, IndexError):
            raise BootstrapError("VM Devsy bootstrap profile is incomplete") from None
        if (not repo.is_absolute() or not repo.is_dir() or repo.is_symlink()
                or repo.stat().st_uid != uid):
            raise BootstrapError("VM source checkout is unavailable or unsafe")
        bridge_module = repo / "scripts/host_devsy_service.py"
        try:
            bridge_metadata = bridge_module.lstat()
        except OSError:
            raise BootstrapError("managed Host Devsy service source is unavailable") from None
        if (not stat.S_ISREG(bridge_metadata.st_mode) or bridge_module.is_symlink()
                or bridge_metadata.st_uid != uid):
            raise BootstrapError("managed Host Devsy service source is unsafe")
        validate_private_file(config, uid)
        validate_private_file(kubeconfig, uid)
        validate_private_directory(context, uid)
        validate_private_directory(config.parent, uid)
        if state.exists():
            validate_private_directory(state, uid)
        return home, state, repo, kubeconfig

    def _read_json_private(self, path: Path, *, required: bool = False) -> dict | None:
        if not path.exists() and not path.is_symlink():
            if required:
                raise BootstrapError("required private Devsy state is missing")
            return None
        validate_private_file(path, int(self.profile["uid"]))
        try:
            value = json.loads(path.read_text())
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise BootstrapError("private Devsy state is invalid") from None
        if not isinstance(value, dict):
            raise BootstrapError("private Devsy state is invalid")
        return value

    def _write_private(self, path: Path, payload: bytes, mode: int = 0o600) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != int(self.profile["uid"])
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise BootstrapError("VM Devsy state directory ownership or mode mismatch")
        temporary = path.with_name(path.name + ".new-" + str(os.getpid()))
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise BootstrapError("VM Devsy state write failed") from None

    def _store(self, *, create: bool = True) -> Path:
        state = Path(self.profile["state_dir"])
        store = state / "deployment"
        if not store.exists():
            if not create:
                return store
            store.mkdir(mode=0o700, parents=True)
        validate_private_directory(store, int(self.profile["uid"]))
        return store

    def _receipt(self) -> dict | None:
        store = self._store(create=False)
        if not store.exists():
            return None
        return self._read_json_private(store / "devsy-host-current.json")

    def _binary_from_bridge(self, state: Path) -> Path | None:
        config = self._read_json_private(state / "devsy-bridge/config.json")
        if config is None:
            candidate = Path(self.profile.get("home", "/nonexistent")) / ".local/bin/devsy"
            return candidate if candidate.is_file() else None
        value = config.get("binary")
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise BootstrapError("existing Host Devsy binary binding is invalid")
        candidate = Path(value).resolve()
        return candidate if candidate.is_file() else None

    def _brew_path(self) -> Path | None:
        prefix = Path(self.policy["homebrew"]["prefix"])
        if not prefix.is_absolute():
            raise BootstrapError("pinned Homebrew prefix is not absolute")
        resolved_prefix = prefix.resolve()
        candidates = []
        if self.profile.get("brew_path"):
            candidates.append(Path(self.profile["brew_path"]))
        found = shutil.which("brew", path=self.env.get("PATH"))
        if found:
            candidates.append(Path(found))
        candidates.extend((prefix / "bin/brew", prefix / "Homebrew/bin/brew",
                           Path(self.profile.get("home", "/nonexistent")) / ".linuxbrew/bin/brew"))
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                invocation = Path(os.path.abspath(candidate))
                try:
                    resolved = candidate.resolve(strict=True)
                except (OSError, RuntimeError):
                    raise BootstrapError("Homebrew executable path is unsafe or unavailable") from None
                try:
                    invocation.relative_to(prefix)
                    resolved.relative_to(resolved_prefix)
                except ValueError:
                    raise BootstrapError("Homebrew executable path is outside the pinned Homebrew prefix") from None
                return invocation
        return None

    def _command_env(self, *, home: Path | None = None,
                     kubeconfig: Path | None = None, homebrew: bool = False) -> dict:
        result = dict(self.env)
        if home is not None:
            result["DEVSY_HOME"] = str(home)
            result["DEVSY_CONTEXT"] = self.profile["devsy"]["context"]
        if kubeconfig is not None:
            result["KUBECONFIG"] = str(kubeconfig)
        if homebrew:
            result["HOMEBREW_NO_AUTO_UPDATE"] = "1"
            result["HOMEBREW_NO_ENV_HINTS"] = "1"
        return result

    def _provider_state(self, binary: Path, home: Path, kubeconfig: Path) -> dict:
        result = self._command([
            str(binary), "--home", str(home), "--context", self.profile["devsy"]["context"],
            "--result-format", "json", "provider", "list",
        ], env=self._command_env(home=home, kubeconfig=kubeconfig))
        try:
            listing = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError):
            raise BootstrapError("Devsy provider inventory is invalid") from None
        return inspect_provider_state(listing, self.policy, str(kubeconfig))

    def _tap_state(self, brew: Path, brew_repository: Path, receipt: dict | None) -> dict:
        tap = Path(brew_repository) / "Library/Taps/joshyorko/homebrew-tools"
        if not tap.exists() and not tap.is_symlink():
            return {"path": tap, "present": False, "revision": None}
        if tap.is_symlink() or not tap.is_dir():
            raise BootstrapError("Josh tools tap path is unsafe")
        origin = self._command(["git", "-C", str(tap), "remote", "get-url", "origin"]).stdout.strip()
        dirty = self._command(["git", "-C", str(tap), "status", "--porcelain"]).stdout.strip()
        revision = self._command(["git", "-C", str(tap), "rev-parse", "HEAD"]).stdout.strip()
        allowed_revisions = {self.policy["devsy"]["tap_revision"]}
        if receipt and receipt.get("tap_revision"):
            allowed_revisions.add(receipt["tap_revision"])
        if (not tap_origin_matches(origin, self.policy["devsy"]["tap_repository"])
                or dirty or revision not in allowed_revisions):
            raise BootstrapError("conflicting Josh tools tap state; preserving the existing tap")
        formula_path = tap / self.policy["devsy"]["formula_path"]
        try:
            formula = formula_path.read_bytes()
        except OSError:
            raise BootstrapError("pinned Devsy formula is missing from the tap") from None
        verify_formula(formula, self.policy)
        return {"path": tap, "present": True, "revision": revision}

    def _formula_bytes(self) -> bytes:
        devsy = self.policy["devsy"]
        url = ("https://raw.githubusercontent.com/joshyorko/homebrew-tools/"
               + devsy["tap_revision"] + "/" + devsy["formula_path"])
        formula = self.fetcher(url)
        verify_formula(formula, self.policy)
        return formula

    def _homebrew_state(self, receipt: dict | None) -> dict:
        brew = self._brew_path()
        homebrew = self.policy["homebrew"]
        if brew is None:
            missing = [name for name in homebrew["required_commands"]
                       if shutil.which(name, path=self.env.get("PATH")) is None]
            if missing:
                raise BootstrapError("prepared VM lacks Homebrew prerequisite commands")
            script = self.fetcher(homebrew["installer_url"])
            if sha256(script) != homebrew["installer_sha256"]:
                raise BootstrapError("pinned Homebrew installer checksum mismatch")
            return {"present": False, "brew": None, "prefix": homebrew["prefix"],
                    "repository": None, "tap": None, "version": None}
        prefix = self._command([str(brew), "--prefix"]).stdout.strip()
        if Path(prefix) != Path(homebrew["prefix"]):
            raise BootstrapError("Homebrew prefix drift; preserving the existing installation")
        version = self._command([str(brew), "--version"]).stdout.splitlines()[0]
        repository = Path(self._command([str(brew), "--repository"]).stdout.strip())
        tap = self._tap_state(brew, repository, receipt)
        return {"present": True, "brew": brew, "prefix": prefix,
                "repository": repository, "tap": tap, "version": version}

    def _kubectl_install_path(self) -> Path:
        return Path(self.profile["state_dir"]) / "bin/kubectl"

    def _kubectl_state(self) -> dict:
        configured = self.policy["kubectl"]
        expected = configured["artifact_sha256"].get(self.machine)
        if expected is None:
            raise BootstrapError("pinned kubectl does not support this Linux architecture")
        path = self._kubectl_install_path()
        if not path.exists() and not path.is_symlink():
            return {"status": "missing", "path": path, "version": configured["version"],
                    "sha256": None, "target_sha256": expected,
                    "managed_path_present": False, "installable": True}
        try:
            validate_private_directory(path.parent, int(self.profile["uid"]))
            metadata = path.lstat()
            if (path.is_symlink() or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != int(self.profile["uid"])
                    or stat.S_IMODE(metadata.st_mode) != 0o755
                    or stat.S_IMODE(path.parent.lstat().st_mode) != 0o700
                    or not os.access(path, os.X_OK)):
                raise BootstrapError(KUBECTL_CONFLICT_REASON)
            actual = sha256(path.read_bytes())
            if actual != expected:
                raise BootstrapError(KUBECTL_CONFLICT_REASON)
            return {"status": "verified", "path": path, "version": configured["version"],
                    "sha256": actual, "target_sha256": expected,
                    "managed_path_present": True, "installable": False}
        except (OSError, BootstrapError):
            return {"status": "untrusted", "path": path, "version": configured["version"],
                    "sha256": None, "target_sha256": expected,
                    "managed_path_present": True, "installable": False}

    def _install_kubectl(self) -> dict:
        state = self._kubectl_state()
        if state["status"] == "verified":
            return state
        if state["status"] != "missing" or state["installable"] is not True:
            raise BootstrapError(KUBECTL_CONFLICT_REASON)
        configured = self.policy["kubectl"]
        architecture = configured["architecture"].get(self.machine)
        if architecture is None:
            raise BootstrapError("pinned kubectl does not support this Linux architecture")
        url = configured["source_url"].format(arch=architecture)
        expected_url = (f"https://dl.k8s.io/release/v{configured['version']}"
                        f"/bin/linux/{architecture}/kubectl")
        if url != expected_url:
            raise BootstrapError("pinned kubectl source URL is invalid")
        if self.fetcher is _fetch:
            artifact = _fetch_bounded(url, configured["max_bytes"])
        else:
            artifact = self.fetcher(url)
        if (not isinstance(artifact, bytes) or len(artifact) > configured["max_bytes"]
                or sha256(artifact) != state["target_sha256"]):
            raise BootstrapError("pinned Kubernetes kubectl checksum mismatch")
        target = self._kubectl_install_path()
        if target.exists() or target.is_symlink():
            raise BootstrapError(KUBECTL_CONFLICT_REASON)
        self._write_private(target, artifact, 0o755)
        installed = self._kubectl_state()
        if installed["status"] != "verified" or installed["path"] != target:
            self._restore_kubectl_snapshot({"kubectl": False}, Path(self.profile["state_dir"]))
            raise BootstrapError("installed pinned kubectl failed source/hash verification")
        return installed

    def _restore_kubectl_snapshot(self, files: dict, directory: Path) -> None:
        if "kubectl" not in files:
            return
        target = self._kubectl_install_path()
        if files.get("kubectl") is True:
            backup = directory / "kubectl.bin"
            data = backup.read_bytes()
            expected = self.policy["kubectl"]["artifact_sha256"].get(self.machine)
            if not expected or sha256(data) != expected:
                raise BootstrapError("pinned kubectl rollback snapshot failed its checksum")
            if target.is_symlink():
                raise BootstrapError("refusing to overwrite a kubectl symlink during rollback")
            if target.exists():
                metadata = target.lstat()
                if (not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != int(self.profile["uid"])):
                    raise BootstrapError("refusing to overwrite an unsafe kubectl rollback target")
            self._write_private(target, data, 0o755)
        elif target.exists() or target.is_symlink():
            expected = self.policy["kubectl"]["artifact_sha256"].get(self.machine)
            try:
                metadata = target.lstat()
                validate_private_directory(target.parent, int(self.profile["uid"]))
                if (target.is_symlink() or not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != int(self.profile["uid"])
                        or not expected or sha256(target.read_bytes()) != expected):
                    raise BootstrapError("refusing to remove an unverified kubectl rollback target")
                target.unlink()
            except OSError:
                raise BootstrapError("pinned kubectl rollback failed") from None
        try:
            target.parent.rmdir()
        except OSError:
            pass

    def _can_stage_missing_kubectl(self, state: dict) -> bool:
        kubectl = state.get("kubectl", {})
        expected = self.policy["kubectl"]["artifact_sha256"].get(self.machine)
        return (
            state.get("cluster") == {
                "ready": False, "status": "blocked", "reason": MISSING_KUBECTL_REASON,
            }
            and kubectl.get("status") == "missing"
            and kubectl.get("installable") is True
            and kubectl.get("target_sha256") == expected
            and kubectl.get("managed_path_present") is False
            and kubectl.get("path") == self._kubectl_install_path()
            and "install-pinned-kubectl" in state.get("changes", [])
        )

    def _cluster_admission(self, kubeconfig: Path) -> dict:
        kubectl_state = self._kubectl_state()
        if kubectl_state["status"] == "missing":
            raise BootstrapError(MISSING_KUBECTL_REASON)
        if kubectl_state["status"] != "verified":
            raise BootstrapError(KUBECTL_CONFLICT_REASON)
        kubectl = str(kubectl_state["path"])
        env = self._command_env(kubeconfig=kubeconfig)

        def get(*args):
            result = self._command([kubectl, "--kubeconfig", str(kubeconfig), "--context",
                                    "ror", *args, "-o", "json"], env=env, timeout=60,
                                   kubectl_preflight=True)
            try:
                return json.loads(result.stdout)
            except (TypeError, json.JSONDecodeError):
                raise BootstrapError("ROR returned invalid Kubernetes inventory") from None

        namespace = get("get", "namespace", "devsy")
        if namespace.get("metadata", {}).get("name") != "devsy":
            raise BootstrapError("authorized ROR namespace devsy is unavailable")
        constraints = get("get", "resourcequota,limitrange", "-n", "devsy")
        if constraints.get("items"):
            raise BootstrapError("ROR devsy quota or LimitRange changed; resource admission needs review")
        selector = self.policy["provider"]["node_selector"]
        selector_text = ",".join(f"{k}={v}" for k, v in sorted(selector.items()))
        nodes = get("get", "nodes", "-l", selector_text)
        selected = {}
        for node in nodes.get("items", []):
            conditions = node.get("status", {}).get("conditions", [])
            ready = any(row.get("type") == "Ready" and row.get("status") == "True" for row in conditions)
            if not ready or node.get("spec", {}).get("unschedulable"):
                continue
            name = node.get("metadata", {}).get("name")
            allocatable = node.get("status", {}).get("allocatable", {})
            if not name or not {"cpu", "memory"} <= set(allocatable):
                continue
            selected[name] = {"cpu": _cpu_millicores(allocatable["cpu"]),
                              "memory": _memory_bytes(allocatable["memory"])}
        if not selected:
            raise BootstrapError("ROR has no ready worker node matching the Devsy selector")
        pods = get("get", "pods", "-A")
        used = {name: {"cpu": 0, "memory": 0} for name in selected}
        for pod in pods.get("items", []):
            node = pod.get("spec", {}).get("nodeName")
            if node not in selected or pod.get("status", {}).get("phase") in ("Succeeded", "Failed"):
                continue
            request = _request_for_pod(pod)
            used[node]["cpu"] += request["cpu"]
            used[node]["memory"] += request["memory"]
        provider = self.policy["provider"]
        target = {"cpu": _cpu_millicores(provider["resources"]["requests"]["cpu"]),
                  "memory": _memory_bytes(provider["resources"]["requests"]["memory"])}
        fitting = [name for name, capacity in selected.items()
                   if capacity["cpu"] - used[name]["cpu"] >= target["cpu"]
                   and capacity["memory"] - used[name]["memory"] >= target["memory"]]
        if not fitting:
            raise BootstrapError("ROR worker allocatable capacity cannot admit the bounded Devsy request")
        classes = get("get", "storageclass")
        default_classes = [row.get("metadata", {}).get("name")
                           for row in classes.get("items", [])
                           if (row.get("metadata", {}).get("annotations", {})
                               .get("storageclass.kubernetes.io/is-default-class") == "true")]
        if default_classes != ["local-path"]:
            raise BootstrapError("ROR default storage class drift; PVC admission needs review")
        return {"ready": True, "status": "ready", "context": "ror", "namespace": "devsy",
                "ready_worker_nodes": len(selected), "fitting_worker_nodes": len(fitting),
                "default_storage_class": "local-path", "resource_quota": "none",
                "limit_range": "none"}

    def apply(self, *, approved: bool, source_sha: str) -> dict:
        if approved is not True:
            raise BootstrapError("explicit Devsy apply approval is required")
        if not re.fullmatch(r"[a-f0-9]{40}", source_sha or ""):
            raise BootstrapError("protected source revision is invalid")
        return self._apply(source_sha)

    def plan(self) -> dict:
        return self._public_plan(self._inspect())

    def assert_current(self) -> dict:
        state = self._inspect()
        if state["cluster"].get("ready") is not True:
            reason = state["cluster"].get("reason") or "ROR admission preflight is unavailable"
            raise BootstrapError("ROR admission preflight is blocked: " + reason)
        if state["changes"]:
            raise BootstrapError("Host Devsy drift detected; use protected plan and explicit apply")
        return self._public_plan(state)

    def rollback(self) -> dict:
        plan = self.rollback_plan()
        receipt = self._receipt()
        backup = Path(receipt["backup_dir"])
        snapshot = self._read_json_private(backup / "manifest.json", required=True)
        current_state = self._inspect(include_cluster=False)
        current_source = receipt.get("source_sha")
        if not isinstance(current_source, str) or not re.fullmatch(r"[a-f0-9]{40}", current_source):
            current_source = self._command([
                "git", "-C", str(current_state["repo"]), "rev-parse", "HEAD",
            ]).stdout.strip()
        current_backup = self._backup(current_state, current_source)
        try:
            self._restore(snapshot, backup)
            self._verify_restored(snapshot, backup)
        except Exception:
            try:
                self._restore(current_backup["manifest"], current_backup["directory"])
                self._verify_restored(current_backup["manifest"], current_backup["directory"])
            except Exception:
                raise BootstrapError("Host Devsy rollback failed; automatic recovery failed") from None
            raise BootstrapError("Host Devsy rollback failed; current host state restored") from None
        receipt["status"] = "rolled_back"
        receipt["tap_revision"] = snapshot.get("tap_revision")
        receipt["devsy_version"] = snapshot.get("devsy_version")
        receipt["devsy_sha256"] = snapshot.get("devsy_sha256")
        receipt["kubectl_version"] = snapshot.get("kubectl_version")
        receipt["kubectl_sha256"] = snapshot.get("kubectl_sha256")
        receipt["rolled_back_source_sha"] = plan["source_sha"]
        receipt["rolled_back_at_ns"] = time.time_ns()
        self._write_private(self._store() / "devsy-host-current.json",
                            (json.dumps(receipt, sort_keys=True) + "\n").encode())
        return {"operation": "rollback", "restored": True,
                "source_sha": plan["source_sha"],
                "devsy_version": snapshot.get("devsy_version"),
                "executor_untouched": True, "tunnel_untouched": True}

    def rollback_plan(self) -> dict:
        receipt = self._receipt()
        if not receipt or receipt.get("status") != "applied":
            raise BootstrapError("no successful Devsy bootstrap receipt is available")
        backup = Path(receipt.get("backup_dir", ""))
        if not backup.is_absolute() or self._store(create=False) not in backup.parents:
            raise BootstrapError("Devsy rollback receipt path is invalid")
        validate_private_directory(backup, int(self.profile["uid"]))
        snapshot = self._read_json_private(backup / "manifest.json", required=True)
        source_sha = snapshot.get("source_sha")
        if not isinstance(source_sha, str) or not re.fullmatch(r"[a-f0-9]{40}", source_sha):
            raise BootstrapError("Devsy rollback source revision is invalid")
        return {"ready": True, "source_sha": source_sha,
                "devsy_version": snapshot.get("devsy_version"),
                "provider_was_verified": snapshot.get("provider_was_verified") is True}

    def _issue27_prior_backup(self, case: dict) -> tuple[Path, dict, dict]:
        uid = int(self.profile["uid"])
        store = self._store(create=False)
        parent = store / "devsy-host-backups"
        validate_private_directory(parent, uid)
        backup = parent / case["prior_backup_directory"]
        validate_private_directory(backup, uid)
        manifest_path = backup / "manifest.json"
        validate_private_file(manifest_path, uid)
        signature_path = backup / "manifest.json.sig"
        if signature_path.exists() or signature_path.is_symlink():
            raise BootstrapError("prior backup has an unsupported signature file")
        manifest_bytes = manifest_path.read_bytes()
        if sha256(manifest_bytes) != case["prior_backup_manifest_sha256"]:
            raise BootstrapError("prior backup manifest does not match the incident digest")
        manifest = self._read_json_private(manifest_path, required=True)
        summary = validate_tap_reconciliation_manifest(manifest, case, self.policy)
        for name, present in manifest["files"].items():
            snapshot = backup / (name + ".bin")
            if present:
                validate_private_file(snapshot, uid)
            elif snapshot.exists() or snapshot.is_symlink():
                raise BootstrapError("prior backup contains a file absent from its manifest")
        self._verify_restored(manifest, backup)

        receipt_path = store / "devsy-host-current.json"
        if manifest["files"]["receipt"]:
            validate_private_file(receipt_path, uid)
            if receipt_path.read_bytes() != (backup / "receipt.bin").read_bytes():
                raise BootstrapError("current Devsy receipt differs from the prior backup")
            receipt = self._read_json_private(receipt_path, required=True)
            if receipt.get("status") == "applied":
                raise BootstrapError("a successful Devsy apply receipt already exists")
        elif receipt_path.exists() or receipt_path.is_symlink():
            raise BootstrapError("current Devsy receipt is absent from the prior backup")

        repo = Path(self.profile["repo_dir"])
        source_sha = self._command(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.strip()
        dirty = self._command([
            "git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all",
        ]).stdout.strip()
        validate_tap_reconciliation_source(source_sha, dirty, case)
        summary = {**summary, "prior_backup_source_sha": manifest["source_sha"],
                   "current_vm_source_sha": source_sha}
        return backup, manifest, summary

    def _authenticated_git_env(self) -> dict:
        result = dict(self.env)
        for name in tuple(result):
            if (name.startswith("GIT_") or name in {
                    "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
                    "GIT_SSL_NO_VERIFY", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH"}):
                result.pop(name, None)
        result["GIT_CONFIG_NOSYSTEM"] = "1"
        result["GIT_CONFIG_GLOBAL"] = os.devnull
        result["GIT_TERMINAL_PROMPT"] = "0"
        return result

    def _issue27_tap_location(self) -> dict:
        brew = self._brew_path()
        if brew is None:
            raise BootstrapError("pinned Homebrew is unavailable for tap reconciliation")
        prefix = Path(self.policy["homebrew"]["prefix"]).resolve(strict=True)
        repository_text = self._command([
            str(brew), "--repository",
        ], env=self._brew_env()).stdout.strip()
        repository = Path(repository_text)
        try:
            repository.resolve(strict=True).relative_to(prefix)
        except (OSError, ValueError):
            raise BootstrapError("Homebrew repository is outside the pinned prefix") from None
        tap = repository / "Library/Taps/joshyorko/homebrew-tools"
        for directory in (repository, repository / "Library", repository / "Library/Taps",
                          repository / "Library/Taps/joshyorko", tap):
            try:
                metadata = directory.lstat()
            except OSError:
                raise BootstrapError("expected incident tap path is unavailable") from None
            if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid != int(self.profile["uid"])):
                raise BootstrapError("incident tap path ownership or type is unsafe")

        origin = self._command([
            "git", "-C", str(tap), "remote", "get-url", "origin",
        ]).stdout.strip()
        if not tap_origin_matches(origin, self.policy["devsy"]["tap_repository"]):
            raise BootstrapError("incident tap origin differs from the approved repository")
        return {"brew": brew, "repository": repository, "tap": tap, "origin": origin}

    def _issue27_tap_state(self, case: dict) -> dict:
        location = self._issue27_tap_location()
        brew, repository, tap, origin = (
            location[name] for name in ("brew", "repository", "tap", "origin"))
        revision = self._command([
            "git", "-C", str(tap), "rev-parse", "HEAD",
        ]).stdout.strip()
        dirty = self._command([
            "git", "-C", str(tap), "status", "--porcelain", "--untracked-files=all",
        ]).stdout.strip()
        ignored = self._command([
            "git", "-C", str(tap), "clean", "-ndx",
        ]).stdout.strip()
        if dirty or ignored:
            raise BootstrapError("incident tap worktree is not clean")
        tree = tap_tree_manifest(tap, int(self.profile["uid"]))

        git_env = self._authenticated_git_env()
        git_args = ["git", "-c", "http.sslVerify=true", "-c", "core.hooksPath=" + os.devnull,
                    "-C", str(tap)]
        upstream = self._command([
            *git_args, "ls-remote", "--heads", "origin", "refs/heads/main",
        ], env=git_env, timeout=90).stdout.strip().splitlines()
        parsed = [line.split() for line in upstream]
        if (len(parsed) != 1 or len(parsed[0]) != 2
                or parsed[0][1] != "refs/heads/main"
                or parsed[0][0] != case["upstream_main_revision"]):
            raise BootstrapError("authenticated tap upstream head differs from the incident pin")
        target = case["target_tap_revision"]
        if self._command([
                *git_args, "cat-file", "-e", target + "^{commit}"],
                env=git_env, allow_failure=True).returncode:
            raise BootstrapError("approved tap pin is unavailable in the authenticated upstream history")
        if self._command([
                *git_args, "merge-base", "--is-ancestor", target,
                case["upstream_main_revision"]],
                env=git_env, allow_failure=True).returncode:
            raise BootstrapError("approved tap pin is not an ancestor of the authenticated upstream head")
        formula = self._command([
            *git_args, "show", target + ":" + self.policy["devsy"]["formula_path"],
        ], env=git_env).stdout.encode()
        verify_formula(formula, self.policy)
        return {"brew": brew, "repository": repository, "tap": tap,
                "origin": origin, "revision": revision, "tree": tree,
                "upstream_main_revision": parsed[0][0],
                "formula_sha256": sha256(formula),
                "git_args": git_args, "git_env": git_env}

    def _issue27_receipts(self, case: dict) -> tuple[Path, list[dict]]:
        store = self._store(create=False)
        parent = store / "devsy-tap-reconciliations"
        root = parent / case["case_id"]
        if parent.exists() or parent.is_symlink():
            validate_private_directory(parent, int(self.profile["uid"]))
        if not root.exists() and not root.is_symlink():
            return root, []
        validate_private_directory(root, int(self.profile["uid"]))
        receipts = []
        for run_dir in sorted(root.iterdir(), key=lambda path: path.name):
            validate_private_directory(run_dir, int(self.profile["uid"]))
            match = re.fullmatch(r"([0-9]{1,20})-([0-9]{1,3})", run_dir.name)
            if not match:
                raise BootstrapError("incident tap receipt directory identity is invalid")
            allowed = {"before.json", "after.json", "rollback.json", "tap-before",
                       "tap-before-manifest.json", "tap-after-manifest.json",
                       "tap-failed", "tap-failed-manifest.json"}
            if not {entry.name for entry in run_dir.iterdir()} <= allowed:
                raise BootstrapError("incident tap receipt contains an unknown artifact")
            before = self._read_json_private(run_dir / "before.json", required=True)
            after = self._read_json_private(run_dir / "after.json")
            rollback = self._read_json_private(run_dir / "rollback.json")
            if (before.get("schema_version") != 1
                    or before.get("case_id") != case["case_id"]
                    or before.get("github_run_id") != match.group(1)
                    or before.get("github_run_attempt") != match.group(2)
                    or before.get("tap_snapshot") != "tap-before"
                    or before.get("prior_backup_manifest_sha256")
                    != case["prior_backup_manifest_sha256"]
                    or before.get("prior_backup_authenticated") is not False
                    or before.get("receipt_signature_status") != "unsigned"
                    or before.get("status") != "started"
                    or not re.fullmatch(r"[a-f0-9]{40}", str(before.get("source_sha", "")))
                    or before.get("vm_source_sha") != case["current_vm_source_sha"]
                    or not re.fullmatch(r"[a-f0-9]{40}",
                                        str(before.get("prior_backup_source_sha", "")))
                    or before.get("tap_before_revision") != case["observed_tap_revision"]
                    or not re.fullmatch(r"[a-f0-9]{64}",
                                        str(before.get("tap_before_sha256", "")))):
                raise BootstrapError("prior tap reconciliation receipt identity mismatch")
            before_manifest_path = run_dir / "tap-before-manifest.json"
            before_manifest = self._read_json_private(before_manifest_path, required=True)
            snapshot = run_dir / "tap-before"
            actual_before = tap_tree_manifest(snapshot, int(self.profile["uid"]))
            if (actual_before != before_manifest
                    or before.get("tap_before_manifest_sha256")
                    != sha256(before_manifest_path.read_bytes())
                    or actual_before["sha256"] != before["tap_before_sha256"]):
                raise BootstrapError("tap reconciliation snapshot differs from its before receipt")
            if after is not None:
                after_manifest = self._read_json_private(
                    run_dir / "tap-after-manifest.json", required=True)
                if (after.get("status") != "completed"
                        or after.get("case_id") != case["case_id"]
                        or after.get("github_run_id") != match.group(1)
                        or after.get("github_run_attempt") != match.group(2)
                        or after.get("source_sha") != before.get("source_sha")
                        or after.get("vm_source_sha") != before.get("vm_source_sha")
                        or after.get("prior_backup_source_sha") != before.get("prior_backup_source_sha")
                        or after.get("tap_before_revision") != before.get("tap_before_revision")
                        or after.get("tap_before_sha256") != before.get("tap_before_sha256")
                        or after.get("tap_after_revision") != case["target_tap_revision"]
                        or after_manifest.get("sha256") != after.get("tap_after_sha256")
                        or after.get("tap_after_manifest_sha256")
                        != sha256((run_dir / "tap-after-manifest.json").read_bytes())):
                    raise BootstrapError("tap reconciliation after receipt is invalid")
                if (not re.fullmatch(r"[a-f0-9]{40}", str(before.get("source_sha", "")))
                        or not re.fullmatch(r"[a-f0-9]{64}",
                                            str(after.get("tap_after_sha256", "")))):
                    raise BootstrapError("tap reconciliation receipt digest is invalid")
            else:
                after_manifest = None
            if rollback is not None and rollback.get("status") not in ("restored", "failed"):
                raise BootstrapError("tap reconciliation rollback receipt is invalid")
            if rollback is not None and rollback.get("status") == "restored":
                if (rollback.get("case_id") != case["case_id"]
                        or rollback.get("github_run_id") != match.group(1)
                        or rollback.get("github_run_attempt") != match.group(2)
                        or rollback.get("tap_revision") != case["observed_tap_revision"]
                        or rollback.get("restored_tap_sha256") != before["tap_before_sha256"]
                        or rollback.get("receipt_signature_status") != "unsigned"):
                    raise BootstrapError("tap reconciliation rollback receipt is invalid")
                if rollback.get("failed_tree") == "tap-failed":
                    failed_manifest = self._read_json_private(
                        run_dir / "tap-failed-manifest.json", required=True)
                    actual_failed = tap_tree_manifest(run_dir / "tap-failed", int(self.profile["uid"]))
                    if (actual_failed != failed_manifest
                            or actual_failed["sha256"] != rollback.get("failed_tap_sha256")):
                        raise BootstrapError("failed tap snapshot differs from its rollback receipt")
            receipts.append({"directory": run_dir, "before": before,
                             "after": after, "after_manifest": after_manifest,
                             "rollback": rollback})
        return root, receipts

    def _issue27_reconciliation_state(self) -> dict:
        case = validate_tap_reconciliation_case(self.policy)
        backup, prior_manifest, prior_summary = self._issue27_prior_backup(case)
        tap_state = self._issue27_tap_state(case)
        receipt_root, receipts = self._issue27_receipts(case)
        if len(receipts) > 1:
            raise BootstrapError("multiple incident tap reconciliation attempts require operator review")
        if receipts:
            receipt = receipts[0]
            if receipt["rollback"] is not None:
                raise BootstrapError("incident tap reconciliation was already rolled back")
            if receipt["after"] is None:
                raise BootstrapError("an interrupted incident tap reconciliation requires protected rollback")
            after = receipt["after"]
            if (after.get("status") != "completed"
                    or after.get("tap_after_revision") != case["target_tap_revision"]
                    or tap_state["revision"] != case["target_tap_revision"]
                    or tap_state["tree"] != receipt["after_manifest"]
                    or tap_state["tree"]["sha256"] != after.get("tap_after_sha256")):
                raise BootstrapError("completed incident reconciliation receipt differs from the live tap")
            return {"case": case, "backup": backup, "prior_manifest": prior_manifest,
                    "prior_summary": prior_summary, "tap_state": tap_state,
                    "receipt_root": receipt_root, "receipts": receipts,
                    "already_reconciled": True}
        if tap_state["revision"] != case["observed_tap_revision"]:
            raise BootstrapError("live tap revision differs from the one-time incident observation")
        return {"case": case, "backup": backup, "prior_manifest": prior_manifest,
                "prior_summary": prior_summary, "tap_state": tap_state,
                "receipt_root": receipt_root, "receipts": receipts,
                "already_reconciled": False}

    def tap_reconciliation_plan(self) -> dict:
        try:
            state = self._issue27_reconciliation_state()
        except BootstrapError as error:
            return {"operation": "devsy-tap-reconcile-plan", "ready": False,
                    "status": "blocked", "reason": str(error),
                    "prior_backup_authenticated": False, "mutated": False}
        case = state["case"]
        tap = state["tap_state"]
        return {"operation": "devsy-tap-reconcile-plan", "ready": True,
                "status": "already-reconciled" if state["already_reconciled"] else "ready",
                "case_id": case["case_id"], "failed_run_id": case["failed_run_id"],
                "prior_backup_manifest_sha256": case["prior_backup_manifest_sha256"],
                "prior_backup_authenticated": False,
                "current_tap_revision": tap["revision"],
                "upstream_main_revision": tap["upstream_main_revision"],
                "vm_source_sha": state["prior_summary"]["current_vm_source_sha"],
                "prior_backup_source_sha": state["prior_summary"]["prior_backup_source_sha"],
                "target_tap_revision": case["target_tap_revision"],
                "tap_tree_sha256": tap["tree"]["sha256"],
                "tap_tree_bytes": tap["tree"]["bytes"],
                "current_tap_origin": tap["origin"],
                "prior_backup_status": "digest-matched-unauthenticated",
                "provider_service_unchanged": True,
                "mutated": False}

    @staticmethod
    def _issue27_run_key(github_run_id: str, github_run_attempt: str) -> str:
        if (not isinstance(github_run_id, str)
                or not re.fullmatch(r"[0-9]{1,20}", github_run_id)
                or not isinstance(github_run_attempt, str)
                or not re.fullmatch(r"[0-9]{1,3}", github_run_attempt)):
            raise BootstrapError("protected GitHub run identity is invalid")
        return github_run_id + "-" + github_run_attempt

    @staticmethod
    def _issue27_manifest_bytes(manifest: dict) -> bytes:
        return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()

    def _write_issue27_receipt(self, run_dir: Path, name: str, receipt: dict) -> None:
        self._write_private(run_dir / name, (json.dumps(receipt, sort_keys=True) + "\n").encode())

    def _issue27_prepare_receipt_directory(self, root: Path, run_key: str) -> Path:
        uid = int(self.profile["uid"])
        parent = root.parent
        if not parent.exists():
            parent.mkdir(mode=0o700)
        validate_private_directory(parent, uid)
        if not root.exists():
            root.mkdir(mode=0o700)
        validate_private_directory(root, uid)
        run_dir = root / run_key
        try:
            run_dir.mkdir(mode=0o700)
        except FileExistsError:
            raise BootstrapError("protected GitHub run already has a tap reconciliation receipt") from None
        validate_private_directory(run_dir, uid)
        return run_dir

    def _issue27_restore_receipted_tap(self, case: dict, run_dir: Path,
                                       before: dict, *, reason: str) -> dict:
        uid = int(self.profile["uid"])
        location = self._issue27_tap_location()
        tap = location["tap"]
        failed_snapshot = run_dir / "tap-failed"
        restored = restore_tap_tree(
            run_dir / before["tap_snapshot"], tap, failed_snapshot,
            before["tap_before_sha256"], uid,
        )
        restored_tree = tap_tree_manifest(tap, uid)
        restored_revision = self._command([
            "git", "-C", str(tap), "rev-parse", "HEAD",
        ]).stdout.strip()
        if (restored_revision != case["observed_tap_revision"]
                or restored_tree["sha256"] != before["tap_before_sha256"]):
            raise BootstrapError("tap rollback readback differs from the before receipt")
        failed_manifest = None
        if failed_snapshot.exists():
            failed_manifest = tap_tree_manifest(failed_snapshot, uid)
            self._write_private(run_dir / "tap-failed-manifest.json",
                                self._issue27_manifest_bytes(failed_manifest))
        receipt = {
            "schema_version": 1, "case_id": case["case_id"],
            "github_run_id": before["github_run_id"],
            "github_run_attempt": before["github_run_attempt"],
            "status": "restored", "reason": reason,
            "prior_backup_authenticated": False,
            "receipt_signature_status": "unsigned",
            "tap_revision": restored_revision,
            "restored_tap_sha256": restored_tree["sha256"],
            "failed_tap_sha256": failed_manifest["sha256"] if failed_manifest else None,
            "failed_tree": "tap-failed" if failed_manifest else None,
            "recorded_at_ns": time.time_ns(),
        }
        self._write_issue27_receipt(run_dir, "rollback.json", receipt)
        return {"restored_sha256": restored_tree["sha256"],
                "failed_sha256": restored.get("failed_sha256"),
                "receipt": receipt}

    def reconcile_tap(self, *, approved: bool, source_sha: str,
                      github_run_id: str, github_run_attempt: str) -> dict:
        if approved is not True:
            raise BootstrapError("explicit tap reconciliation approval is required")
        if not re.fullmatch(r"[a-f0-9]{40}", source_sha or ""):
            raise BootstrapError("protected source revision is invalid")
        run_key = self._issue27_run_key(github_run_id, github_run_attempt)
        state = self._issue27_reconciliation_state()
        if state["already_reconciled"]:
            after = state["receipts"][0]["after"]
            return {"operation": "devsy-tap-reconcile", "status": "already-reconciled",
                    "changed": False, "prior_backup_authenticated": False,
                    "tap_before_revision": after["tap_before_revision"],
                    "tap_after_revision": after["tap_after_revision"],
                    "tap_before_sha256": after["tap_before_sha256"],
                    "tap_after_sha256": after["tap_after_sha256"]}
        if state["receipts"]:
            raise BootstrapError("an incident tap reconciliation receipt already exists")

        case = state["case"]
        run_dir = self._issue27_prepare_receipt_directory(state["receipt_root"], run_key)
        snapshot_path = run_dir / "tap-before"
        before_written = False
        phase = "tap-snapshot"
        try:
            snapshot_manifest = copy_tap_tree(
                state["tap_state"]["tap"], snapshot_path, int(self.profile["uid"]),
            )
            if snapshot_manifest["sha256"] != state["tap_state"]["tree"]["sha256"]:
                raise BootstrapError("tap changed while its rollback snapshot was copied")
            snapshot_payload = self._issue27_manifest_bytes(snapshot_manifest)
            self._write_private(run_dir / "tap-before-manifest.json", snapshot_payload)
            before = {
                "schema_version": 1, "case_id": case["case_id"],
                "github_run_id": github_run_id, "github_run_attempt": github_run_attempt,
                "status": "started",
                "source_sha": source_sha,
                "prior_backup_manifest_sha256": case["prior_backup_manifest_sha256"],
                "prior_backup_authenticated": False,
                "receipt_signature_status": "unsigned",
                "vm_source_sha": state["prior_summary"]["current_vm_source_sha"],
                "prior_backup_source_sha": state["prior_summary"]["prior_backup_source_sha"],
                "tap_snapshot": "tap-before",
                "tap_before_revision": state["tap_state"]["revision"],
                "tap_before_origin": state["tap_state"]["origin"],
                "tap_before_upstream_main_revision": state["tap_state"]["upstream_main_revision"],
                "tap_before_sha256": snapshot_manifest["sha256"],
                "tap_before_manifest_sha256": sha256(snapshot_payload),
                "tap_before_bytes": snapshot_manifest["bytes"],
                "tap_before_files": snapshot_manifest["files"],
                "target_tap_revision": case["target_tap_revision"],
                "recorded_at_ns": time.time_ns(),
            }
            self._write_issue27_receipt(run_dir, "before.json", before)
            before_written = True

            phase = "baseline-revalidation"
            confirmed = self._issue27_tap_state(case)
            if (confirmed["origin"] != state["tap_state"]["origin"]
                    or confirmed["revision"] != state["tap_state"]["revision"]
                    or confirmed["upstream_main_revision"] != state["tap_state"]["upstream_main_revision"]
                    or confirmed["tree"]["sha256"] != snapshot_manifest["sha256"]):
                raise BootstrapError("tap baseline changed after the protected plan")

            phase = "checkout-pinned-revision"
            self._command([
                *confirmed["git_args"], "checkout", "--detach", case["target_tap_revision"],
            ], env=confirmed["git_env"], timeout=120)

            phase = "post-checkout-verification"
            after_state = self._issue27_tap_state(case)
            if after_state["revision"] != case["target_tap_revision"]:
                raise BootstrapError("tap checkout did not reach the approved revision")
            formula_path = after_state["tap"] / self.policy["devsy"]["formula_path"]
            try:
                formula_bytes = formula_path.read_bytes()
            except OSError:
                raise BootstrapError("approved Devsy formula is missing after tap checkout") from None
            if sha256(formula_bytes) != after_state["formula_sha256"]:
                raise BootstrapError("checked-out Devsy formula differs from its pinned commit")
            after_manifest = after_state["tree"]
            after_payload = self._issue27_manifest_bytes(after_manifest)
            self._write_private(run_dir / "tap-after-manifest.json", after_payload)
            after = {
                "schema_version": 1, "case_id": case["case_id"],
                "github_run_id": github_run_id, "github_run_attempt": github_run_attempt,
                "source_sha": source_sha, "status": "completed",
                "vm_source_sha": before["vm_source_sha"],
                "prior_backup_source_sha": before["prior_backup_source_sha"],
                "receipt_signature_status": "unsigned",
                "prior_backup_authenticated": False,
                "tap_before_revision": before["tap_before_revision"],
                "tap_before_sha256": before["tap_before_sha256"],
                "tap_after_revision": after_state["revision"],
                "tap_after_origin": after_state["origin"],
                "tap_after_upstream_main_revision": after_state["upstream_main_revision"],
                "tap_after_sha256": after_manifest["sha256"],
                "tap_after_manifest_sha256": sha256(after_payload),
                "tap_after_bytes": after_manifest["bytes"],
                "tap_after_files": after_manifest["files"],
                "formula_sha256": after_state["formula_sha256"],
                "recorded_at_ns": time.time_ns(),
            }
            phase = "after-receipt"
            self._write_issue27_receipt(run_dir, "after.json", after)
            return {"operation": "devsy-tap-reconcile", "status": "completed",
                    "changed": True, "case_id": case["case_id"],
                    "prior_backup_authenticated": False,
                    "tap_before_revision": before["tap_before_revision"],
                    "tap_before_sha256": before["tap_before_sha256"],
                    "tap_after_revision": after_state["revision"],
                    "tap_after_sha256": after_manifest["sha256"],
                    "provider_service_untouched": True, "rollback_ready": True}
        except Exception as error:
            failure = (str(error) if isinstance(error, BootstrapError)
                       else type(error).__name__)
            if not before_written:
                shutil.rmtree(run_dir, ignore_errors=True)
                raise BootstrapError("tap snapshot failed before reconciliation; the live tap was not changed: "
                                     + failure) from None
            try:
                self._issue27_restore_receipted_tap(
                    case, run_dir, before, reason="automatic rollback after " + phase,
                )
            except Exception:
                raise BootstrapError("Devsy tap reconciliation failed at " + phase
                                     + "; automatic rollback FAILED; operator recovery required") from None
            raise BootstrapError("Devsy tap reconciliation failed at " + phase + ": " + failure
                                 + "; automatic rollback restored the original tap") from None

    def tap_reconciliation_rollback_plan(self, *, github_run_id: str,
                                         github_run_attempt: str) -> dict:
        try:
            run_key = self._issue27_run_key(github_run_id, github_run_attempt)
            case = validate_tap_reconciliation_case(self.policy)
            self._issue27_prior_backup(case)
            _root, receipts = self._issue27_receipts(case)
            matches = [receipt for receipt in receipts
                       if receipt["directory"].name == run_key]
            if len(matches) != 1:
                raise BootstrapError("protected tap rollback receipt is unavailable")
            receipt = matches[0]
            if receipt["rollback"] is not None:
                raise BootstrapError("incident tap reconciliation was already rolled back")
            location = self._issue27_tap_location()
            current_tree = tap_tree_manifest(location["tap"], int(self.profile["uid"]))
            current_revision = self._command([
                "git", "-C", str(location["tap"]), "rev-parse", "HEAD",
            ]).stdout.strip()
            after = receipt["after"]
            if after is not None:
                state = self._issue27_tap_state(case)
                if (state["revision"] != after["tap_after_revision"]
                        or state["tree"] != receipt["after_manifest"]
                        or state["tree"]["sha256"] != after["tap_after_sha256"]):
                    raise BootstrapError("live tap differs from the completed reconciliation receipt")
            return {"operation": "devsy-tap-rollback-plan", "ready": True,
                    "status": "ready", "case_id": case["case_id"],
                    "github_run_id": github_run_id,
                    "github_run_attempt": github_run_attempt,
                    "tap_current_revision": current_revision,
                    "tap_current_sha256": current_tree["sha256"],
                    "tap_restore_revision": receipt["before"]["tap_before_revision"],
                    "tap_restore_sha256": receipt["before"]["tap_before_sha256"],
                    "prior_backup_authenticated": False, "mutated": False}
        except BootstrapError as error:
            return {"operation": "devsy-tap-rollback-plan", "ready": False,
                    "status": "blocked", "reason": str(error),
                    "prior_backup_authenticated": False, "mutated": False}

    def rollback_tap_reconciliation(self, *, approved: bool,
                                   github_run_id: str, github_run_attempt: str) -> dict:
        if approved is not True:
            raise BootstrapError("explicit tap reconciliation rollback approval is required")
        plan = self.tap_reconciliation_rollback_plan(
            github_run_id=github_run_id, github_run_attempt=github_run_attempt,
        )
        if plan.get("ready") is not True:
            raise BootstrapError("tap reconciliation rollback is blocked: " + plan.get("reason", "unknown gate"))
        case = validate_tap_reconciliation_case(self.policy)
        run_key = self._issue27_run_key(github_run_id, github_run_attempt)
        root, receipts = self._issue27_receipts(case)
        receipt = next(item for item in receipts if item["directory"].name == run_key)
        try:
            restored = self._issue27_restore_receipted_tap(
                case, receipt["directory"], receipt["before"],
                reason="explicit protected tap rollback",
            )
        except Exception:
            raise BootstrapError("Devsy tap rollback failed; operator recovery required") from None
        return {"operation": "devsy-tap-rollback", "restored": True,
                "case_id": case["case_id"], "tap_revision": case["observed_tap_revision"],
                "tap_sha256": restored["restored_sha256"],
                "failed_tap_sha256": restored["failed_sha256"],
                "provider_service_untouched": True}

    def _verify_restored(self, manifest: dict, directory: Path) -> None:
        state_dir = Path(self.profile["state_dir"])
        files = manifest.get("files", {})
        for name, path in (
            ("unit", self.unit_path),
            ("starter", state_dir / "start-host-devsy.py"),
            ("bridge_config", state_dir / "devsy-bridge/config.json"),
            ("devsy_config", Path(self.profile["devsy"]["config_source"])),
        ):
            if name not in files:
                continue
            expected = directory / (name + ".bin")
            present = files.get(name) is True
            if present:
                if not path.is_file() or path.is_symlink() or path.read_bytes() != expected.read_bytes():
                    raise BootstrapError("restored Host Devsy file differs from its rollback receipt")
            elif path.exists() or path.is_symlink():
                raise BootstrapError("unexpected Host Devsy file remains after rollback")

        if "kubectl" in files:
            path = self._kubectl_install_path()
            present = files.get("kubectl") is True
            if present:
                expected = directory / "kubectl.bin"
                metadata = path.lstat() if path.exists() else None
                if (metadata is None or path.is_symlink() or not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != int(self.profile["uid"])
                        or stat.S_IMODE(metadata.st_mode) != 0o755
                        or path.read_bytes() != expected.read_bytes()
                        or sha256(path.read_bytes())
                        != self.policy["kubectl"]["artifact_sha256"].get(self.machine)):
                    raise BootstrapError("restored pinned kubectl differs from its rollback receipt")
            elif path.exists() or path.is_symlink():
                raise BootstrapError("unexpected pinned kubectl remains after rollback")

        if files.get("unit"):
            service = self._service_properties()
            if (service.get("FragmentPath") != str(self.unit_path)
                    or service.get("ActiveState") != ("active" if manifest.get("unit_active") else "inactive")
                    or service.get("UnitFileState") != ("enabled" if manifest.get("unit_enabled") else "disabled")):
                raise BootstrapError("systemd identity or lifecycle did not match the rollback receipt")

        if manifest.get("provider_was_verified"):
            binary = Path(manifest.get("devsy_path") or "")
            expected_version = manifest.get("devsy_version")
            expected_hash = manifest.get("devsy_sha256")
            if expected_hash is None:
                if expected_version == self.policy["devsy"]["legacy_version"]:
                    expected_hash = self.policy["devsy"]["legacy_sha256"]
                elif expected_version == self.policy["devsy"]["version"]:
                    expected_hash = self.policy["devsy"]["artifact_sha256"].get(self.machine)
            if (not binary.is_file() or not expected_hash
                    or self._command([str(binary), "--version"]).stdout.strip().removeprefix("v") != expected_version
                    or sha256(binary.read_bytes()) != expected_hash):
                raise BootstrapError("restored Host Devsy CLI differs from its rollback receipt")
            provider = self._provider_state(
                binary, Path(self.profile["devsy"]["config_source"]).parent,
                Path(self.profile["devsy"]["kubeconfig_source"]))
            for key, value in manifest.get("provider_options", {}).items():
                if provider["options"].get(key, "") != value:
                    raise BootstrapError("restored ROR provider differs from its rollback receipt")

        if manifest.get("unit_active"):
            config = self._read_json_private(state_dir / "devsy-bridge/config.json", required=True)
            process = self._read_json_private(state_dir / "devsy-bridge/process.json", required=True)
            if not self.process_probe(config, process):
                raise BootstrapError("restored Host Devsy process identity did not match its receipt")
            if not self.health_probe(config):
                status = self._last_bridge_health_status
                if status not in {"unavailable", "invalid-response", "invalid-process-receipt",
                                  "not-ready", "instance-mismatch", "unexpected-response-fields"}:
                    status = "unknown"
                raise BootstrapError("restored Host Devsy bridge health gate failed: " + status)

    def _apply(self, source_sha: str) -> dict:
        state = self._inspect()
        backup = None
        kubectl_staged = False
        if state["cluster"].get("ready") is not True:
            if not self._can_stage_missing_kubectl(state):
                reason = state["cluster"].get("reason") or "ROR admission preflight is unavailable"
                raise BootstrapError("ROR admission preflight is blocked: " + reason)
            backup = self._backup(state, source_sha)
            try:
                self._install_kubectl()
                kubectl_staged = True
                state = self._inspect()
                if state["cluster"].get("ready") is not True:
                    reason = state["cluster"].get("reason") or "ROR admission preflight is unavailable"
                    raise BootstrapError("ROR admission preflight remains blocked: " + reason)
            except Exception as error:
                try:
                    self._restore_kubectl_snapshot(backup["manifest"]["files"],
                                                   backup["directory"])
                except Exception:
                    raise BootstrapError(
                        "Devsy apply stopped before provider or Devsy changes; staged kubectl rollback failed"
                    ) from None
                failure = str(error) if isinstance(error, BootstrapError) else type(error).__name__
                raise BootstrapError(
                    "Devsy apply stopped before provider or Devsy changes: " + failure
                    + "; staged kubectl was rolled back"
                ) from None
        if not state["changes"]:
            if kubectl_staged:
                configured = self.policy["kubectl"]
                receipt = {
                    "schema_version": 1, "status": "applied", "source_sha": source_sha,
                    "kubectl_version": configured["version"],
                    "kubectl_sha256": configured["artifact_sha256"][self.machine],
                    "kubectl_location": configured["install_location"],
                    "backup_dir": str(backup["directory"]),
                    "applied_at_ns": time.time_ns(),
                }
                self._write_private(self._store() / "devsy-host-current.json",
                                    (json.dumps(receipt, sort_keys=True) + "\n").encode())
                return {"operation": "apply", "changed": True,
                        "kubectl_version": receipt["kubectl_version"],
                        "kubectl_sha256": receipt["kubectl_sha256"],
                        "rollback_ready": True, "provider_untouched": True,
                        "service_untouched": True}
            return {"operation": "apply", "changed": False,
                    **self._public_plan(state)}
        if backup is None:
            backup = self._backup(state, source_sha)
        phase = "stop-service"
        try:
            if state["service"]["active"]:
                self._command(["sudo", "-n", "systemctl", "stop", "codex-control-plane-devsy"])
            phase = "homebrew"
            brew = self._ensure_homebrew(state)
            phase = "tap"
            self._ensure_tap(brew, state)
            phase = "devsy-install"
            binary = self._install_devsy(brew, state)
            home, _state_dir, repo, kubeconfig = self._validate_inputs()
            phase = "provider-config"
            provider = self._provider_state(binary, home, kubeconfig)
            provider_options(self.policy, str(kubeconfig))
            if provider["changes"]:
                self._set_provider_options(binary, home, kubeconfig,
                                           provider_options(self.policy, str(kubeconfig)))
            phase = "provider-readback"
            verified = self._provider_state(binary, home, kubeconfig)
            if verified["changes"]:
                raise BootstrapError("ROR provider readback did not match the approved resource policy")
            desired_unit = self._desired_unit(brew)
            phase = "bridge-starter"
            self._write_starter(repo, Path(self.profile["state_dir"]))
            phase = "systemd-unit"
            self._install_unit(desired_unit)
            self._command(["sudo", "-n", "systemctl", "daemon-reload"])
            self._command(["sudo", "-n", "systemctl", "enable", "codex-control-plane-devsy"])
            action = "restart" if state["unit_state"] != "absent" else "start"
            phase = "service-start"
            self._command(["sudo", "-n", "systemctl", action, "codex-control-plane-devsy"], timeout=180)
            phase = "live-verification"
            self._verify_live(brew, binary, desired_unit, home, kubeconfig)
            receipt = {
                "schema_version": 1,
                "status": "applied",
                "source_sha": source_sha,
                "devsy_source_repository": self.policy["devsy"]["source_repository"],
                "devsy_source_revision": self.policy["devsy"]["source_revision"],
                "devsy_version": self.policy["devsy"]["version"],
                "devsy_sha256": self.policy["devsy"]["artifact_sha256"][self.machine],
                "kubectl_version": self.policy["kubectl"]["version"],
                "kubectl_sha256": self.policy["kubectl"]["artifact_sha256"][self.machine],
                "kubectl_location": self.policy["kubectl"]["install_location"],
                "tap_revision": self.policy["devsy"]["tap_revision"],
                "unit_sha256": sha256(desired_unit),
                "backup_dir": str(backup["directory"]),
                "applied_at_ns": time.time_ns(),
            }
            phase = "receipt"
            self._write_private(self._store() / "devsy-host-current.json",
                                (json.dumps(receipt, sort_keys=True) + "\n").encode())
            return {"operation": "apply", "changed": True,
                    "devsy_source_repository": receipt["devsy_source_repository"],
                    "devsy_source_revision": receipt["devsy_source_revision"],
                    "devsy_version": receipt["devsy_version"],
                    "devsy_sha256": receipt["devsy_sha256"],
                    "kubectl_version": receipt["kubectl_version"],
                    "kubectl_sha256": receipt["kubectl_sha256"],
                    "provider": "kubernetes", "kubernetes_context": "ror",
                    "namespace": "devsy", "unit_sha256": receipt["unit_sha256"],
                    "rollback_ready": True, "executor_untouched": True,
                    "tunnel_untouched": True}
        except Exception as error:
            failure = str(error) if isinstance(error, BootstrapError) else type(error).__name__
            try:
                self._restore(backup["manifest"], backup["directory"])
                self._verify_restored(backup["manifest"], backup["directory"])
            except Exception:
                raise BootstrapError("Devsy apply failed at " + phase
                                    + "; automatic rollback failed") from None
            raise BootstrapError("Devsy apply failed at " + phase
                                + ": " + failure + "; previous host state restored") from None

    def _probe_bridge(self, config: dict) -> bool:
        self._last_bridge_health_status = "unavailable"
        try:
            with host_bridge_health_opener().open(
                    "http://" + config["gateway"] + ":8089/health", timeout=10) as response:
                value = json.loads(response.read(4096))
        except Exception:
            return False
        try:
            receipt = self._read_json_private(Path(config["state"]) / "process.json", required=True)
        except BootstrapError:
            self._last_bridge_health_status = "invalid-process-receipt"
            return False
        self._last_bridge_health_status = classify_bridge_health_response(
            value, receipt.get("instance"),
        )
        return self._last_bridge_health_status == "healthy"

    def _inspect(self, *, include_cluster: bool = True) -> dict:
        home, state_dir, repo, kubeconfig = self._validate_inputs()
        receipt = self._receipt()
        brew_state = self._homebrew_state(receipt)
        formula = self._formula_bytes()
        current_unit = self._current_unit()
        bridge_config = self._read_json_private(state_dir / "devsy-bridge/config.json")
        if current_unit is None and bridge_config is not None:
            raise BootstrapError("Host Devsy bridge state exists without its managed systemd unit")
        starter = self._starter_state(state_dir)
        brew_bin = Path(brew_state["prefix"]) / "bin/devsy"
        desired_unit = self._desired_unit_from_path(brew_bin, home, repo, state_dir, kubeconfig)
        unit_state = classify_unit(current_unit, desired_unit,
                                   self.policy["devsy"]["legacy_unit_sha256"])
        service = self._service_properties() if current_unit is not None else {}
        if current_unit is not None:
            if service.get("FragmentPath") != str(self.unit_path):
                raise BootstrapError("conflicting systemd unit source; preserving the service")
            if (service.get("User") != self.profile["service_user"]
                    or service.get("Group") != self.profile["service_group"]
                    or "/start-host-devsy.py" not in service.get("ExecStart", "")):
                raise BootstrapError("conflicting systemd bridge identity or ExecStart")
        binary, devsy_state = self._provider_binary(brew_state, state_dir)
        if devsy_state is None:
            provider_state = None
        else:
            provider_state = devsy_state["provider"]
        kubectl_state = self._kubectl_state()
        if include_cluster:
            try:
                cluster = self._cluster_admission(kubeconfig)
            except BootstrapError as error:
                cluster = {"ready": False, "status": "blocked", "reason": str(error)}
        else:
            cluster = {"status": "not-queried-for-rollback"}
        changes = []
        if not brew_state["present"]:
            changes.append("install-homebrew")
        if not brew_state["tap"] or brew_state["tap"]["revision"] != self.policy["devsy"]["tap_revision"]:
            changes.append("pin-joshyorko-tools-tap")
        target_hash = self.policy["devsy"]["artifact_sha256"][self.machine]
        binary_matches = bool(devsy_state and devsy_state["version"] == self.policy["devsy"]["version"]
                              and devsy_state["sha256"] == target_hash
                              and binary.resolve() == brew_bin.resolve())
        if not binary_matches:
            changes.append("install-tap-devsy")
        if kubectl_state["status"] == "missing":
            changes.append("install-pinned-kubectl")
        if provider_state is None or provider_state["changes"]:
            changes.append("configure-ror-provider")
        props = service
        active = props.get("ActiveState") == "active"
        enabled = props.get("UnitFileState") == "enabled"
        if unit_state != "managed":
            changes.append("install-systemd-bridge")
        if starter != "managed":
            changes.append("install-managed-bridge-starter")
        if not active or not enabled:
            changes.append("enable-start-systemd-bridge")
        return {
            "changes": sorted(set(changes)), "unit_state": unit_state,
            "starter_state": starter,
            "desired_unit": desired_unit, "service": {"active": active, "enabled": enabled},
            "service_properties": {name: service.get(name) for name in
                                   ("FragmentPath", "User", "Group", "ExecStart")},
            "unit_sha256": sha256(current_unit) if current_unit is not None else None,
            "brew": brew_state, "formula": formula, "binary": binary,
            "kubectl": kubectl_state,
            "devsy": devsy_state, "provider": provider_state, "cluster": cluster,
            "home": home, "state_dir": state_dir, "repo": repo,
            "kubeconfig": kubeconfig, "receipt": receipt,
        }

    def _public_plan(self, state: dict) -> dict:
        provider = self.policy["provider"]
        brew = state["brew"]
        tap = brew.get("tap")
        devsy = state["devsy"]
        binary = state["binary"]
        current_provider = state["provider"]
        current_options = current_provider.get("options", {}) if current_provider else {}
        service_properties = state.get("service_properties", {})
        template = current_options.get("POD_MANIFEST_TEMPLATE", "")
        formula = state.get("formula")
        kubectl = state.get("kubectl", {})
        kubectl_policy = self.policy["kubectl"]
        target_binary = (Path(brew["prefix"]) / "bin/devsy") if brew.get("prefix") else None
        binary_matches = bool(
            devsy and target_binary and devsy["version"] == self.policy["devsy"]["version"]
            and devsy["sha256"] == self.policy["devsy"]["artifact_sha256"].get(self.machine)
            and Path(binary).resolve() == target_binary.resolve()
        )
        cluster_ready = state["cluster"].get("ready") is True
        status = ("blocked" if not cluster_ready else
                  "current" if not state["changes"] else "changes-required")
        return {
            "ready": cluster_ready,
            "status": status,
            "changes": state["changes"],
            "homebrew_present": brew["present"],
            "tap_revision": self.policy["devsy"]["tap_revision"],
            "devsy_current_version": devsy["version"] if devsy else None,
            "devsy_target_version": self.policy["devsy"]["version"],
            "source_provenance": {
                "repository": self.policy["devsy"]["source_repository"],
                "revision": self.policy["devsy"]["source_revision"],
                "release": self.policy["devsy"]["release_tag"],
                "artifact_sha256": self.policy["devsy"]["artifact_sha256"].get(self.machine),
            },
            "provider": {"name": "kubernetes", "default": True,
                         "kubernetes_context": "ror", "namespace": "devsy",
                         "requests": provider["resources"]["requests"],
                         "limits": provider["resources"]["limits"],
                         "init_requests": provider["init_resources"]["requests"],
                         "init_limits": provider["init_resources"]["limits"],
                         "node_selector": provider["node_selector"]},
            "observed": {
                "tap_current_revision": tap.get("revision") if tap else None,
                "formula_sha256": sha256(formula) if isinstance(formula, bytes) else None,
                "devsy": {
                    "binary": str(binary) if binary else None,
                    "version": devsy["version"] if devsy else None,
                    "sha256": devsy["sha256"] if devsy else None,
                    "matches_pinned_homebrew_binary": binary_matches,
                    "source_revision": (self.policy["devsy"]["source_revision"]
                                        if binary_matches else None),
                },
                "kubectl": {
                    "status": kubectl.get("status", "unknown"),
                    "platform": self.machine,
                    "version": kubectl_policy["version"],
                    "sha256": kubectl.get("sha256"),
                    "target_sha256": kubectl_policy["artifact_sha256"].get(self.machine),
                    "install_location": kubectl_policy["install_location"],
                    "managed_path_present": kubectl.get("managed_path_present", False),
                },
                "provider": ({
                    "name": current_provider["name"],
                    "default": current_provider["default"],
                    "context": current_options.get("KUBERNETES_CONTEXT"),
                    "namespace": current_options.get("KUBERNETES_NAMESPACE"),
                    "create_namespace": current_options.get("CREATE_NAMESPACE"),
                    "node_selector": current_options.get("NODE_SELECTOR"),
                    "resources": current_options.get("RESOURCES"),
                    "kubeconfig_configured": bool(current_options.get("KUBERNETES_CONFIG")),
                    "pod_manifest_template_sha256": sha256(template.encode()) if template else None,
                } if current_provider else None),
                "systemd": {
                    "unit_state": state["unit_state"],
                    "unit_sha256": state.get("unit_sha256"),
                    "bridge_starter": state["starter_state"],
                    "active": state["service"]["active"],
                    "enabled": state["service"]["enabled"],
                    "fragment_path": service_properties.get("FragmentPath"),
                    "user": service_properties.get("User"),
                    "group": service_properties.get("Group"),
                    "exec_start": service_properties.get("ExecStart"),
                },
            },
            "cluster": state["cluster"],
            "systemd_unit": state["unit_state"],
            "bridge_starter": state["starter_state"],
            "service_active": state["service"]["active"],
            "service_enabled": state["service"]["enabled"],
        }

    def _current_unit(self) -> bytes | None:
        if not self.unit_path.exists() and not self.unit_path.is_symlink():
            return None
        metadata = self.unit_path.lstat()
        expected_uid = 0 if self.unit_path == UNIT_PATH else int(self.profile["uid"])
        if (not stat.S_ISREG(metadata.st_mode) or self.unit_path.is_symlink()
                or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o644):
            raise BootstrapError("conflicting systemd unit ownership or mode")
        return self.unit_path.read_bytes()

    def _desired_unit_from_path(self, binary: Path, home: Path, repo: Path,
                                state_dir: Path, kubeconfig: Path) -> bytes:
        devsy = self.profile["devsy"]
        return render_unit(user=self.profile["service_user"],
                           group=self.profile["service_group"], repo_dir=str(repo),
                           state_dir=str(state_dir), devsy_bin=str(binary),
                           devsy_home=str(Path(devsy["config_source"]).parent),
                           config_source=devsy["config_source"], context_dir=devsy["context_dir"],
                           kubeconfig=str(kubeconfig), template_text=self.unit_template)

    def _desired_unit(self, brew: Path) -> bytes:
        home, state, repo, kubeconfig = self._validate_inputs()
        return self._desired_unit_from_path(Path(brew).parent / "devsy", home, repo, state, kubeconfig)

    def _service_properties(self) -> dict:
        result = self._command([
            "systemctl", "show", "codex-control-plane-devsy",
            "-p", "FragmentPath", "-p", "ActiveState", "-p", "UnitFileState",
            "-p", "User", "-p", "Group", "-p", "ExecStart",
        ], allow_failure=True)
        if result.returncode:
            return {}
        return {line.split("=", 1)[0]: line.split("=", 1)[1]
                for line in result.stdout.splitlines() if "=" in line}

    def _provider_binary(self, brew_state: dict, state_dir: Path) -> tuple[Path | None, dict | None]:
        binary = self._binary_from_bridge(state_dir)
        if binary is None and brew_state["present"]:
            candidate = Path(brew_state["prefix"]) / "bin/devsy"
            if candidate.is_file():
                binary = candidate.resolve()
        if binary is None:
            return None, None
        version = self._command([str(binary), "--version"]).stdout.strip().removeprefix("v")
        digest = sha256(binary.read_bytes())
        devsy = self.policy["devsy"]
        target_hash = devsy["artifact_sha256"].get(self.machine)
        if ((version, digest) != (devsy["version"], target_hash)
                and (version, digest) != (devsy["legacy_version"], devsy["legacy_sha256"])):
            raise BootstrapError("Host Devsy version or checksum drift; preserving the existing binary")
        home = Path(self.profile["devsy"]["config_source"]).parent
        kubeconfig = Path(self.profile["devsy"]["kubeconfig_source"])
        provider = self._provider_state(binary, home, kubeconfig)
        return binary, {"version": version, "sha256": digest,
                        "path": binary, "provider": provider}

    def _brew_env(self) -> dict:
        return self._command_env(homebrew=True)

    def _ensure_homebrew(self, state: dict) -> Path:
        if state["brew"]["present"]:
            return Path(state["brew"]["brew"])
        installer = self.fetcher(self.policy["homebrew"]["installer_url"])
        if sha256(installer) != self.policy["homebrew"]["installer_sha256"]:
            raise BootstrapError("pinned Homebrew installer checksum mismatch")
        state_dir = Path(self.profile["state_dir"])
        with tempfile.TemporaryDirectory(prefix="devsy-homebrew-", dir=state_dir) as temporary:
            script = Path(temporary) / "install.sh"
            script.write_bytes(installer)
            script.chmod(0o600)
            env = dict(self.env, CI="1", NONINTERACTIVE="1", HOMEBREW_ON_LINUX="1")
            self._command(["/bin/bash", str(script), "--path",
                           self.policy["homebrew"]["prefix"]], env=env, timeout=900)
        brew = Path(self.policy["homebrew"]["prefix"]) / "bin/brew"
        if not brew.is_file() or not os.access(brew, os.X_OK):
            raise BootstrapError("Homebrew installer did not create its declared binary")
        return brew.resolve()

    def _ensure_tap(self, brew: Path, state: dict) -> Path:
        repository = Path(self._command([str(brew), "--repository"], env=self._brew_env()).stdout.strip())
        tap = repository / "Library/Taps/joshyorko/homebrew-tools"
        devsy = self.policy["devsy"]
        if not tap.exists():
            self._command([str(brew), "tap", devsy["tap"]], env=self._brew_env(), timeout=300)
        if not tap.is_dir() or tap.is_symlink():
            raise BootstrapError("Josh tools tap was not installed at the managed Homebrew path")
        origin = self._command(["git", "-C", str(tap), "remote", "get-url", "origin"]).stdout.strip()
        if not tap_origin_matches(origin, devsy["tap_repository"]):
            raise BootstrapError("Josh tools tap origin changed")
        dirty = self._command(["git", "-C", str(tap), "status", "--porcelain"]).stdout.strip()
        if dirty:
            raise BootstrapError("Josh tools tap has local edits; preserving the existing tap")
        self._command(["git", "-C", str(tap), "fetch", "--depth", "1", "origin",
                       devsy["tap_revision"]], timeout=300)
        self._command(["git", "-C", str(tap), "checkout", "--detach",
                       devsy["tap_revision"]])
        formula_path = tap / devsy["formula_path"]
        try:
            verify_formula(formula_path.read_bytes(), self.policy)
        except OSError:
            raise BootstrapError("pinned Devsy formula is unavailable after tap checkout") from None
        return tap

    def _install_devsy(self, brew: Path, state: dict) -> Path:
        prefix = Path(self._command([str(brew), "--prefix"], env=self._brew_env()).stdout.strip())
        binary = prefix / "bin/devsy"
        target_hash = self.policy["devsy"]["artifact_sha256"].get(self.machine)
        current = state["devsy"]
        matches = bool(current and current["version"] == self.policy["devsy"]["version"]
                       and current["sha256"] == target_hash
                       and Path(current["path"]).resolve() == binary.resolve())
        if not matches:
            self._command([str(brew), "install", self.policy["devsy"]["tap"] + "/devsy"],
                          env=self._brew_env(), timeout=900)
        if not binary.is_file():
            raise BootstrapError("tap install did not create the Devsy CLI")
        resolved = binary.resolve()
        version = self._command([str(resolved), "--version"]).stdout.strip().removeprefix("v")
        digest = sha256(resolved.read_bytes())
        if version != self.policy["devsy"]["version"] or digest != target_hash:
            raise BootstrapError("installed Devsy CLI version or checksum mismatch")
        return binary

    def _set_provider_options(self, binary: Path, home: Path, kubeconfig: Path,
                              options: dict[str, str]) -> None:
        args = [str(binary), "--home", str(home), "--context",
                self.profile["devsy"]["context"], "--result-format", "json",
                "provider", "set", "kubernetes", "--skip-init"]
        for key in sorted(options):
            args.extend(("--option", key + "=" + options[key]))
        self._command(args, env=self._command_env(home=home, kubeconfig=kubeconfig), timeout=120)

    def _write_starter(self, repo: Path, state_dir: Path) -> None:
        self._write_private(state_dir / "start-host-devsy.py",
                            self.starter_source.encode(), 0o700)

    def _starter_state(self, state_dir: Path) -> str:
        path = state_dir / "start-host-devsy.py"
        if not path.exists() and not path.is_symlink():
            return "absent"
        try:
            metadata = path.lstat()
            content = path.read_text()
        except (OSError, UnicodeError):
            raise BootstrapError("Host Devsy starter is unavailable") from None
        if (path.is_symlink() or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != int(self.profile["uid"])
                or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise BootstrapError("conflicting Host Devsy starter ownership or mode")
        if content == self.starter_source:
            return "managed"
        legacy = ("import runpy\nrunpy.run_path(" + repr(str(Path(self.profile["repo_dir"])
                                                                       / "scripts/host_devsy_service.py"))
                   + ", run_name=\"__main__\")\n")
        if content == legacy:
            return "legacy"
        raise BootstrapError("conflicting Host Devsy starter; preserving the existing file")

    def _install_unit(self, content: bytes) -> None:
        if self.unit_path == UNIT_PATH:
            temporary = Path(self.profile["state_dir"]) / ("codex-control-plane-devsy." + str(os.getpid()))
            self._write_private(temporary, content, 0o600)
            try:
                self._command(["sudo", "-n", "install", "-o", "root", "-g", "root",
                               "-m", "0644", str(temporary), str(self.unit_path)])
            finally:
                temporary.unlink(missing_ok=True)
        else:
            self._write_private(self.unit_path, content, 0o644)

    def _remove_unit(self) -> None:
        if self.unit_path == UNIT_PATH:
            self._command(["sudo", "-n", "rm", "-f", "--", str(self.unit_path)])
        else:
            self.unit_path.unlink(missing_ok=True)

    def _verify_live(self, brew: Path, binary: Path, desired_unit: bytes,
                     home: Path, kubeconfig: Path) -> None:
        kubectl = self._kubectl_state()
        if (kubectl["status"] != "verified"
                or kubectl["sha256"] != self.policy["kubectl"]["artifact_sha256"].get(self.machine)):
            raise BootstrapError("running host kubectl failed pinned version/checksum verification")
        current_unit = self._current_unit()
        if current_unit != desired_unit:
            raise BootstrapError("systemd unit readback did not match the managed unit")
        props = self._service_properties()
        if (props.get("FragmentPath") != str(self.unit_path)
                or props.get("User") != self.profile["service_user"]
                or props.get("Group") != self.profile["service_group"]
                or "start-host-devsy.py" not in props.get("ExecStart", "")
                or props.get("ActiveState") != "active"
                or props.get("UnitFileState") != "enabled"):
            raise BootstrapError("systemd Devsy unit identity or health readback failed")
        state_dir = Path(self.profile["state_dir"])
        bridge_config = self._read_json_private(state_dir / "devsy-bridge/config.json", required=True)
        configured_binary = Path(bridge_config.get("binary", "")).resolve()
        if configured_binary != binary.resolve():
            raise BootstrapError("running bridge does not use the tap-managed Devsy binary")
        version = self._command([str(configured_binary), "--version"]).stdout.strip().removeprefix("v")
        if (version != self.policy["devsy"]["version"]
                or sha256(configured_binary.read_bytes()) != self.policy["devsy"]["artifact_sha256"][self.machine]):
            raise BootstrapError("running bridge Devsy binary failed version/checksum verification")
        process = self._read_json_private(state_dir / "devsy-bridge/process.json", required=True)
        if not self.process_probe(bridge_config, process):
            raise BootstrapError("running bridge process identity did not match its receipt")
        if not self.health_probe(bridge_config):
            raise BootstrapError("Host Devsy bridge health identity check failed")
        provider = self._provider_state(binary, home, kubeconfig)
        if provider["changes"]:
            raise BootstrapError("ROR provider readback did not match the approved resource policy")

    def _process_matches(self, _config: dict, receipt: dict) -> bool:
        pid = receipt.get("pid")
        try:
            stat_fields = Path(f"/proc/{int(pid)}/stat").read_text().rsplit(")", 1)[1].split()
            command = Path(f"/proc/{int(pid)}/cmdline").read_bytes().split(b"\0")
        except (OSError, ValueError, IndexError, TypeError):
            return False
        expected_helper = str(Path(self.profile["repo_dir"]) / "scripts/devsy_bridge.py").encode()
        return (stat_fields[0] != "Z" and stat_fields[19] == receipt.get("started")
                and expected_helper in command and b"--serve" in command)

    def _backup(self, state: dict, source_sha: str) -> dict:
        if not re.fullmatch(r"[a-f0-9]{40}", source_sha or ""):
            raise BootstrapError("rollback source revision is invalid")
        store = self._store()
        parent = store / "devsy-host-backups"
        if not parent.exists():
            parent.mkdir(mode=0o700)
        validate_private_directory(parent, int(self.profile["uid"]))
        directory = parent / str(time.time_ns())
        directory.mkdir(mode=0o700)
        state_dir = Path(self.profile["state_dir"])
        targets = {
            "unit": self.unit_path,
            "starter": state_dir / "start-host-devsy.py",
            "bridge_config": state_dir / "devsy-bridge/config.json",
            "receipt": store / "devsy-host-current.json",
            "devsy_config": Path(self.profile["devsy"]["config_source"]),
            "kubectl": self._kubectl_install_path(),
        }
        present = {}
        for name, path in targets.items():
            present[name] = path.exists() and not path.is_symlink()
            if present[name]:
                if path.is_symlink() or not path.is_file():
                    raise BootstrapError("Devsy rollback input is not a regular file")
                self._write_private(directory / (name + ".bin"), path.read_bytes(), 0o600)
        keys = provider_options(self.policy, str(state["kubeconfig"])).keys()
        options_before = ({key: state["provider"]["options"].get(key, "") for key in keys}
                          if state["provider"] else {})
        kubectl_state = state.get("kubectl", {})
        manifest = {
            "schema_version": 1,
            "source_sha": source_sha,
            "files": present,
            "unit_active": state["service"]["active"],
            "unit_enabled": state["service"]["enabled"],
            "unit_state": state["unit_state"],
            "provider_options": options_before,
            "provider_was_verified": state["provider"] is not None,
            "tap_was_present": bool(state["brew"]["tap"] and state["brew"]["tap"]["present"]),
            "tap_revision": state["brew"]["tap"]["revision"] if state["brew"]["tap"] else None,
            "devsy_version": state["devsy"]["version"] if state["devsy"] else None,
            "devsy_sha256": state["devsy"]["sha256"] if state["devsy"] else None,
            "devsy_path": str(state["binary"]) if state["binary"] else None,
            "kubectl_version": (kubectl_state.get("version")
                                if kubectl_state.get("status") == "verified" else None),
            "kubectl_sha256": (kubectl_state.get("sha256")
                               if kubectl_state.get("status") == "verified" else None),
        }
        self._write_private(directory / "manifest.json",
                            (json.dumps(manifest, sort_keys=True) + "\n").encode())
        return {"directory": directory, "manifest": manifest}

    def _restore(self, manifest: dict, directory: Path) -> None:
        state_dir = Path(self.profile["state_dir"])
        if manifest.get("unit_active"):
            self._command(["sudo", "-n", "systemctl", "stop", "codex-control-plane-devsy"], allow_failure=True)
        if manifest.get("provider_was_verified"):
            binary = Path(manifest.get("devsy_path") or "")
            expected_version = manifest.get("devsy_version")
            expected_hash = manifest.get("devsy_sha256")
            if expected_hash is None:
                if expected_version == self.policy["devsy"]["legacy_version"]:
                    expected_hash = self.policy["devsy"]["legacy_sha256"]
                elif expected_version == self.policy["devsy"]["version"]:
                    expected_hash = self.policy["devsy"]["artifact_sha256"].get(self.machine)
            if not binary.is_file() or not expected_hash:
                raise BootstrapError("rollback Devsy CLI is unavailable")
            actual_version = self._command([str(binary), "--version"]).stdout.strip().removeprefix("v")
            if actual_version != expected_version or sha256(binary.read_bytes()) != expected_hash:
                raise BootstrapError("rollback Devsy CLI failed its saved version/checksum")
            home = Path(self.profile["devsy"]["config_source"]).parent
            kubeconfig = Path(self.profile["devsy"]["kubeconfig_source"])
            self._set_provider_options(binary, home, kubeconfig,
                                       manifest.get("provider_options", {}))
        files = manifest.get("files", {})
        unit_backup = directory / "unit.bin"
        if files.get("unit"):
            self._install_unit(unit_backup.read_bytes())
        else:
            self._remove_unit()
        for name, path, mode in (
            ("starter", state_dir / "start-host-devsy.py", 0o700),
            ("bridge_config", state_dir / "devsy-bridge/config.json", 0o600),
            ("devsy_config", Path(self.profile["devsy"]["config_source"]), 0o600),
        ):
            if name not in files:
                continue
            backup = directory / (name + ".bin")
            if files.get(name):
                self._write_private(path, backup.read_bytes(), mode)
            else:
                path.unlink(missing_ok=True)
        self._restore_kubectl_snapshot(files, directory)
        self._command(["sudo", "-n", "systemctl", "daemon-reload"], allow_failure=True)
        if files.get("unit") and manifest.get("unit_enabled"):
            self._command(["sudo", "-n", "systemctl", "enable", "codex-control-plane-devsy"], allow_failure=True)
        elif not manifest.get("unit_enabled"):
            self._command(["sudo", "-n", "systemctl", "disable", "codex-control-plane-devsy"], allow_failure=True)
        if files.get("unit") and manifest.get("unit_active"):
            self._command(["sudo", "-n", "systemctl", "start", "codex-control-plane-devsy"], timeout=180)
        elif not files.get("unit"):
            self._command(["sudo", "-n", "systemctl", "disable", "--now", "codex-control-plane-devsy"], allow_failure=True)
        tap_revision = manifest.get("tap_revision")
        if manifest.get("tap_was_present") and tap_revision:
            brew = self._brew_path()
            if brew:
                repo = Path(self._command([str(brew), "--repository"], env=self._brew_env()).stdout.strip())
                tap = repo / "Library/Taps/joshyorko/homebrew-tools"
                self._command(["git", "-C", str(tap), "checkout", "--detach", tap_revision])
        elif manifest.get("tap_was_present") is False:
            brew = self._brew_path()
            if brew:
                repo = Path(self._command([str(brew), "--repository"], env=self._brew_env()).stdout.strip())
                tap = repo / "Library/Taps/joshyorko/homebrew-tools"
                if tap.exists() or tap.is_symlink():
                    if tap.is_symlink() or not tap.is_dir():
                        raise BootstrapError("rollback refused to remove an unsafe Josh tools tap")
                    origin = self._command([
                        "git", "-C", str(tap), "remote", "get-url", "origin",
                    ]).stdout.strip()
                    dirty = self._command(["git", "-C", str(tap), "status", "--porcelain"]).stdout.strip()
                    if (not tap_origin_matches(origin, self.policy["devsy"]["tap_repository"])
                            or dirty):
                        raise BootstrapError("rollback refused to remove a conflicting Josh tools tap")
                    self._command([
                        str(brew), "untap", self.policy["devsy"]["tap"],
                    ], env=self._brew_env())
                    if tap.exists() or tap.is_symlink():
                        raise BootstrapError("rollback left the transaction-created Josh tools tap in place")
            else:
                tap = (Path(self.policy["homebrew"]["prefix"])
                       / "Homebrew/Library/Taps/joshyorko/homebrew-tools")
                if tap.exists() or tap.is_symlink():
                    raise BootstrapError("rollback cannot verify transaction-created tap removal")
        old_receipt = directory / "receipt.bin"
        store = self._store()
        if files.get("receipt"):
            self._write_private(store / "devsy-host-current.json", old_receipt.read_bytes())
        else:
            (store / "devsy-host-current.json").unlink(missing_ok=True)
