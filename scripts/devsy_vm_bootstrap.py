#!/usr/bin/env python3
"""Idempotent VM-host Devsy installation and drift checks."""

from __future__ import annotations

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


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_policy(path: Path = POLICY_PATH) -> dict:
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise BootstrapError("VM Devsy bootstrap policy is unavailable or invalid") from None
    if (not isinstance(value, dict) or value.get("schema_version") != 1
            or not isinstance(value.get("homebrew"), dict)
            or not isinstance(value.get("devsy"), dict)
            or not isinstance(value.get("provider"), dict)):
        raise BootstrapError("VM Devsy bootstrap policy schema is unsupported")
    return value


def validate_platform(system: str, machine: str) -> None:
    if system != "Linux" or machine not in ("aarch64", "arm64"):
        raise BootstrapError("unsupported host platform; expected Linux ARM64")


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
    version = re.search(r'(?m)^\s*version\s+"([^"]+)"', source)
    arm_hash = re.search(r'(?ms)on_arm\s+do.*?sha256\s+"([a-f0-9]{64})"', source)
    if (not version or version.group(1) != devsy["version"] or not arm_hash
            or arm_hash.group(1) != devsy["artifact_sha256"]["aarch64"]):
        raise BootstrapError("pinned Josh tap formula version or ARM64 checksum drifted")
    return source


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
        self.machine = machine or platform.machine()
        self.unit_path = Path(unit_path)
        self.env = dict(os.environ if env is None else env)
        self.health_probe = health_probe or self._probe_bridge
        self.process_probe = process_probe or self._process_matches
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
                 env: dict | None = None, allow_failure: bool = False) -> subprocess.CompletedProcess:
        try:
            result = self.runner(arguments, capture_output=True, text=True,
                                 timeout=timeout, env=env or self.env)
        except (OSError, subprocess.TimeoutExpired):
            raise BootstrapError("VM Devsy bootstrap command failed or timed out") from None
        if result.returncode and not allow_failure:
            raise BootstrapError("VM Devsy bootstrap command failed; raw output withheld")
        return result

    def _validate_inputs(self) -> tuple[Path, Path, Path, Path]:
        validate_platform(self.system, self.machine)
        try:
            devsy = self.profile["devsy"]
            uid = int(self.profile["uid"])
            home = Path(self.profile.get("home") or Path(devsy["config_source"]).parents[4])
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
                return candidate.resolve()
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
        if (origin.rstrip("/") != self.policy["devsy"]["tap_repository"].rstrip("/")
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

    def _cluster_admission(self, kubeconfig: Path) -> dict:
        kubectl = shutil.which("kubectl", path=self.env.get("PATH"))
        if kubectl is None:
            candidate = Path("/usr/bin/kubectl")
            if candidate.is_file() and os.access(candidate, os.X_OK):
                kubectl = str(candidate)
        if kubectl is None:
            raise BootstrapError("kubectl is required for the ROR admission preflight")
        env = self._command_env(kubeconfig=kubeconfig)

        def get(*args):
            result = self._command([kubectl, "--kubeconfig", str(kubeconfig), "--context",
                                    "ror", *args, "-o", "json"], env=env, timeout=60)
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
        pods = get("get", "pods", "-A")
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
        return {"context": "ror", "namespace": "devsy", "ready_worker_nodes": len(selected),
                "fitting_worker_nodes": len(fitting), "default_storage_class": "local-path",
                "resource_quota": "none", "limit_range": "none"}

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
            if not self.process_probe(config, process) or not self.health_probe(config):
                raise BootstrapError("restored Host Devsy service health did not match its identity")

    def _apply(self, source_sha: str) -> dict:
        state = self._inspect()
        if not state["changes"]:
            return {"operation": "apply", "changed": False,
                    **self._public_plan(state)}
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
                "devsy_version": self.policy["devsy"]["version"],
                "devsy_sha256": self.policy["devsy"]["artifact_sha256"][self.machine],
                "tap_revision": self.policy["devsy"]["tap_revision"],
                "unit_sha256": sha256(desired_unit),
                "backup_dir": str(backup),
                "applied_at_ns": time.time_ns(),
            }
            phase = "receipt"
            self._write_private(self._store() / "devsy-host-current.json",
                                (json.dumps(receipt, sort_keys=True) + "\n").encode())
            return {"operation": "apply", "changed": True,
                    "devsy_version": receipt["devsy_version"],
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
        from urllib.request import Request, urlopen
        try:
            with urlopen("http://" + config["gateway"] + ":8089/health", timeout=10) as response:
                value = json.loads(response.read(4096))
            receipt = self._read_json_private(Path(config["state"]) / "process.json", required=True)
            return value == {"ready": True, "instance": receipt.get("instance")}
        except Exception:
            return False

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
        cluster = (self._cluster_admission(kubeconfig) if include_cluster
                   else {"status": "not-queried-for-rollback"})
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
            "brew": brew_state, "formula": formula, "binary": binary,
            "devsy": devsy_state, "provider": provider_state, "cluster": cluster,
            "home": home, "state_dir": state_dir, "repo": repo,
            "kubeconfig": kubeconfig, "receipt": receipt,
        }

    def _public_plan(self, state: dict) -> dict:
        provider = self.policy["provider"]
        return {
            "ready": True,
            "status": "current" if not state["changes"] else "changes-required",
            "changes": state["changes"],
            "homebrew_present": state["brew"]["present"],
            "tap_revision": self.policy["devsy"]["tap_revision"],
            "devsy_current_version": state["devsy"]["version"] if state["devsy"] else None,
            "devsy_target_version": self.policy["devsy"]["version"],
            "provider": {"name": "kubernetes", "default": True,
                         "kubernetes_context": "ror", "namespace": "devsy",
                         "requests": provider["resources"]["requests"],
                         "limits": provider["resources"]["limits"],
                         "init_requests": provider["init_resources"]["requests"],
                         "init_limits": provider["init_resources"]["limits"],
                         "node_selector": provider["node_selector"]},
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
        if origin.rstrip("/") != devsy["tap_repository"].rstrip("/"):
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
        old_receipt = directory / "receipt.bin"
        store = self._store()
        if files.get("receipt"):
            self._write_private(store / "devsy-host-current.json", old_receipt.read_bytes())
        else:
            (store / "devsy-host-current.json").unlink(missing_ok=True)
