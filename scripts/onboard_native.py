#!/usr/bin/env python3
"""Connect this device's existing native Codex daemon to a central CAS."""
from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Callable

import native_codex_ssh

ROOT = Path(__file__).resolve().parents[1]


class OnboardingError(ValueError):
    """An actionable device prerequisite or ownership conflict."""


def private_file(path: Path, mode: int = 0o600) -> None:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != mode):
        raise OnboardingError(f"Expected an owned private regular file, mode {mode:04o}: {path}")


def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise OnboardingError(f"Expected an owned private directory, mode 0700: {path}")


def write_matching(path: Path, content: str, *, json_content: bool = False) -> bool:
    """Create once or adopt matching private files without overwriting assets."""
    if path.exists() or path.is_symlink():
        private_file(path)
        before = path.read_text()
        matches = json.loads(before) == json.loads(content) if json_content else before == content
        if not matches:
            raise OnboardingError(f"Existing configuration has different content; refusing to replace {path}")
        return False
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return True


def write_private_json(path: Path, value: dict) -> None:
    if path.exists() or path.is_symlink():
        private_file(path)
    fd, temporary = tempfile.mkstemp(prefix=".onboarding-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def load_acceptance(state: Path, supplied: dict | None) -> dict | None:
    if supplied is not None:
        return supplied
    path = state / "onboarding-settings.json"
    if not (path.exists() or path.is_symlink()):
        return None
    private_file(path)
    value = json.loads(path.read_text())
    native = value.get("native")
    if (set(value) != {"schema_version", "native"} or value["schema_version"] != 1
            or not isinstance(native, dict) or set(native) != {"target", "cwd", "thread_id"}
            or native["target"] != "local"):
        raise OnboardingError("Private onboarding settings have an unsupported acceptance schema.")
    return native


def save_acceptance(state: Path, native: dict | None) -> None:
    if native is not None:
        write_private_json(state / "onboarding-settings.json", {"schema_version": 1, "native": native})


def install_dependencies(*, non_interactive: bool = False, run: Callable = subprocess.run) -> None:
    """Explicit opt-in package setup on supported mutable Linux distributions."""
    missing = [name for name in ("tailscale", "sshd", "ssh-keygen") if not shutil.which(name)]
    if not missing:
        return
    if non_interactive or not sys.stdin.isatty():
        raise OnboardingError("Dependency installation requires an interactive terminal for sudo; install the prerequisites and rerun.")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator:
            release[key] = value.strip('"')
    distro = release.get("ID")
    if Path("/run/ostree-booted").exists() or distro not in {"debian", "ubuntu", "fedora", "rocky", "almalinux"}:
        raise OnboardingError("Automatic package installation is unsupported on this host. Use its supported Tailscale/OpenSSH setup; immutable Bluefin hosts are never layered by onboarding.")
    print("Installing missing host prerequisites with sudo (--install-dependencies was requested).", file=sys.stderr)
    if "sshd" in missing or "ssh-keygen" in missing:
        command = (["apt-get", "install", "-y", "openssh-server", "openssh-client"]
                   if distro in {"debian", "ubuntu"} else ["dnf", "install", "-y", "openssh-server", "openssh-clients"])
        run(["sudo", *command], check=True)
    if "tailscale" in missing:
        if not shutil.which("curl"):
            raise OnboardingError("curl is required to download the official Tailscale installer; see https://tailscale.com/download/linux.")
        with tempfile.TemporaryDirectory(prefix="native-tailscale-") as directory:
            installer = str(Path(directory) / "install.sh")
            run(["curl", "--fail", "--location", "--proto", "=https", "--tlsv1.2", "--output", installer,
                 "https://tailscale.com/install.sh"], check=True, timeout=60)
            run(["sudo", "sh", installer], check=True)


def tailnet_address(status: dict) -> str:
    for value in status.get("TailscaleIPs") or []:
        address = ipaddress.ip_address(value)
        if address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10"):
            return str(address)
    raise OnboardingError("Tailscale has no assigned tailnet IPv4 address.")


def ensure_tailnet(*, non_interactive: bool = False, run: Callable = subprocess.run) -> str:
    executable = shutil.which("tailscale")
    if not executable:
        raise OnboardingError("Install Tailscale using https://tailscale.com/download/linux, then rerun onboarding.")
    for _ in range(4):
        result = run([executable, "status", "--json"], capture_output=True, text=True, timeout=20)
        try:
            status = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise OnboardingError("Cannot read Tailscale status; enable tailscaled and rerun onboarding.") from None
        state = status.get("BackendState")
        if state == "Running":
            return tailnet_address(status)
        if state not in ("NeedsLogin", "Stopped"):
            raise OnboardingError(f"Tailscale is {state or 'unavailable'}; resolve device approval or daemon health and rerun.")
        command = "login" if state == "NeedsLogin" else "up"
        if non_interactive or not sys.stdin.isatty():
            raise OnboardingError(f"Tailscale needs attention. Run sudo tailscale {command} interactively, then rerun onboarding.")
        print(f"Tailscale requires {command}; complete any sudo/browser prompt to continue.", file=sys.stderr)
        result = run(["sudo", executable, command], check=False)
        if result.returncode:
            raise OnboardingError(f"Tailscale {command} did not complete; no central registration was attempted.")
    raise OnboardingError("Tailscale did not become ready; rerun after login/device approval completes.")


def discover_daemon(*, codex_bin: Path | None = None, socket_path: Path | None = None,
                    home: Path | None = None, run: Callable = subprocess.run) -> tuple[Path, Path]:
    home = home or Path.home()
    if codex_bin is None:
        stable = home / ".codex/packages/app-server-daemon/current/bin/codex"
        if stable.is_file():
            codex_bin = stable
        else:
            found = shutil.which("codex")
            if not found:
                raise OnboardingError("No native Codex executable found. Supply --codex-bin and --socket for your running daemon.")
            codex_bin = Path(found)
    if socket_path is None:
        stable_socket = home / ".codex/app-server-control/app-server-control.sock"
        if stable_socket.exists():
            socket_path = stable_socket
        else:
            alternatives = list(Path(f"/tmp/codex-daemon-{os.getuid()}").glob("*"))
            candidates = [p for p in alternatives if p.is_socket()]
            if len(candidates) != 1:
                raise OnboardingError("Native Codex socket is missing or ambiguous; supply --socket for the existing running daemon.")
            socket_path = candidates[0]
    codex_bin = codex_bin.absolute()
    socket_path = socket_path.absolute()
    if not native_codex_ssh.SAFE_PATH.fullmatch(str(codex_bin)) or not native_codex_ssh.SAFE_PATH.fullmatch(str(socket_path)):
        raise OnboardingError("Codex executable and socket paths must be absolute safe paths without shell syntax.")
    if not codex_bin.is_file() or not os.access(codex_bin, os.X_OK):
        raise OnboardingError(f"Codex executable is unavailable: {codex_bin}")
    if not socket_path.is_socket():
        raise OnboardingError(f"Native Codex socket is unavailable or is not a socket: {socket_path}")
    result = run([str(codex_bin), "app-server", "daemon", "version"], capture_output=True,
                 stdin=subprocess.DEVNULL, text=True, timeout=20)
    try:
        version = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise OnboardingError("Native Codex daemon version probe failed; start/authenticate your existing Codex daemon and rerun.") from None
    if result.returncode or version.get("status") != "running":
        raise OnboardingError("Native Codex daemon is not running; onboarding never starts or replaces it.")
    reported = version.get("socketPath")
    if reported is not None and Path(reported).resolve() != socket_path.resolve():
        raise OnboardingError("Native Codex version probe reports a different socket; supply the executable and socket belonging to the same daemon.")
    # Keep the stable path, even when it resolves into /tmp.
    return codex_bin, socket_path


def user_unit_dir() -> Path:
    return Path.home() / ".config/systemd/user"


def user_service_env() -> dict:
    runtime = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    return dict(os.environ, XDG_RUNTIME_DIR=runtime,
                DBUS_SESSION_BUS_ADDRESS=os.environ.get("DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime}/bus"))


def prepare_endpoint(state: Path, codex: Path, sock: Path, address: str, port: int,
                     controller: dict, *, run: Callable = subprocess.run) -> str:
    """Adopt/create the bounded endpoint and return its public host identity."""
    sshd = shutil.which("sshd")
    if not sshd:
        raise OnboardingError("OpenSSH server (sshd) is missing. Install it through this host's supported package setup, then rerun; no central files were changed.")
    if not shutil.which("ssh-keygen") or not shutil.which("systemctl"):
        raise OnboardingError("This Linux onboarding path requires ssh-keygen and systemd user services.")
    private_directory(state)
    key = state / "ssh_host_ed25519_key"
    if key.exists() or key.is_symlink():
        private_file(key)
    else:
        if key.with_suffix(".pub").exists():
            raise OnboardingError("Host public key exists without its private key; restore it instead of rotating identity.")
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            stdin=subprocess.DEVNULL, check=True, timeout=20)
        private_file(key)
    client_key = controller["public_key"].split()
    if len(client_key) < 2 or client_key[0] != "ssh-ed25519":
        raise OnboardingError("Controller returned an unsupported native SSH public key.")
    source = str(ipaddress.IPv4Address(controller["address"]))
    if ipaddress.ip_address(source) not in ipaddress.ip_network("100.64.0.0/10"):
        raise OnboardingError("Controller address must be its assigned Tailscale IPv4 address.")
    auth = state / "authorized_keys"
    authorization = f'from="{source}",restrict ' + " ".join(client_key[:2])
    if auth.exists() or auth.is_symlink():
        private_file(auth)
        lines = [line.split() for line in auth.read_text().splitlines() if line.strip()]
        expected = authorization.split()
        if len(lines) != 1 or lines[0][:3] != expected:
            raise OnboardingError(f"Existing authorized keys have different content; refusing to replace {auth}")
    else:
        write_matching(auth, authorization + "\n")
    profile = {"address": address, "port": port, "codex_bin": str(codex), "socket": str(sock),
               "state_dir": str(state), "helper": str(state / "native_codex_ssh.py")}
    write_matching(state / "profile.json", json.dumps(profile, indent=2) + "\n", json_content=True)
    native_codex_ssh.prepare(state / "profile.json")
    run([sshd, "-t", "-f", str(state / "sshd_config")], check=True,
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20)
    directory = user_unit_dir()
    directory.mkdir(parents=True, exist_ok=True)
    unit_content = (state / "native-codex-ssh.service").read_text().replace("ExecStart=/usr/bin/sshd ", f"ExecStart={sshd} ")
    if Path("/usr/bin/sshd").exists() and Path("/usr/bin/sshd").samefile(sshd):
        unit_content = (state / "native-codex-ssh.service").read_text()
    changed = write_matching(directory / "native-codex-ssh.service", unit_content)
    env = user_service_env()
    common = dict(env=env, capture_output=True, text=True, timeout=20)
    if changed:
        run(["systemctl", "--user", "daemon-reload"], check=True, **common)
    enabled = run(["systemctl", "--user", "is-enabled", "native-codex-ssh.service"], **common)
    if enabled.returncode:
        run(["systemctl", "--user", "enable", "native-codex-ssh.service"], check=True, **common)
    active = run(["systemctl", "--user", "is-active", "native-codex-ssh.service"], **common)
    if active.returncode:
        run(["systemctl", "--user", "start", "native-codex-ssh.service"], check=True, **common)
    result = run(["ssh-keygen", "-y", "-f", str(key)], check=True,
                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20)
    public = result.stdout.split()
    if len(public) < 2 or public[0] != "ssh-ed25519":
        raise OnboardingError("The existing host key is not an Ed25519 identity; refusing to rotate it.")
    return " ".join(public[:2])


def native_tuple(cwd: str | None, thread_id: str | None) -> dict | None:
    if bool(cwd) != bool(thread_id):
        raise OnboardingError("--native-cwd and --native-thread-id must be supplied together.")
    return {"target": "local", "cwd": cwd, "thread_id": thread_id} if cwd else None


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--name", required=True, help="Logical CAS target name, e.g. dakota-cpu")
    result.add_argument("--local-env", type=Path, default=ROOT / ".env.kamal.local")
    result.add_argument("--instance-profile", type=Path)
    result.add_argument("--codex-bin", type=Path)
    result.add_argument("--socket", dest="socket_path", type=Path)
    result.add_argument("--state-dir", type=Path, default=Path.home() / ".local/state/native-codex-ssh")
    result.add_argument("--port", type=int, default=22222)
    result.add_argument("--native-cwd")
    result.add_argument("--native-thread-id")
    result.add_argument("--non-interactive", action="store_true", help="Fail with instructions rather than open sudo/browser prompts")
    result.add_argument("--install-dependencies", action="store_true", help="Allow interactive sudo installation on supported mutable Linux hosts")
    result.add_argument("--prepare-only", action="store_true", help="Prepare SSH and export its descriptor for protected CI registration")
    result.add_argument("--descriptor-out", type=Path, help="Private descriptor destination; defaults to state-dir/native-target.json")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if os.geteuid() == 0:
            raise OnboardingError("Run onboarding as the non-root owner of the existing Codex daemon.")
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", args.name) or args.name == "local":
            raise OnboardingError("Choose a target name using lowercase letters, digits and hyphens, other than local.")
        if not 1024 <= args.port <= 65535:
            raise OnboardingError("SSH port must be between 1024 and 65535.")
        native = native_tuple(args.native_cwd, args.native_thread_id)
        state = args.state_dir.absolute()
        private_directory(state)
        lock_path = state / "onboarding.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+") as lock:
            private_file(lock_path)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            native = load_acceptance(state, native)
            if args.install_dependencies:
                install_dependencies(non_interactive=args.non_interactive)
            print("Checking Tailscale and the existing native Codex daemon...", file=sys.stderr, flush=True)
            address = ensure_tailnet(non_interactive=args.non_interactive)
            codex, sock = discover_daemon(codex_bin=args.codex_bin, socket_path=args.socket_path)
            import native_onboarding_controller as controller
            connection = controller.connect(args.local_env.absolute(), args.instance_profile)
            info = connection.info()
            print("Preparing or adopting the restricted SSH endpoint...", file=sys.stderr, flush=True)
            public = prepare_endpoint(state, codex, sock, address, args.port, info)
            descriptor = {"schema_version": 1, "name": args.name, "address": address, "port": args.port,
                          "user": pwd.getpwuid(os.geteuid()).pw_name, "codex_bin": str(codex), "socket": str(sock),
                          "host_public_key": public, "controller_fingerprint": info["controller_fingerprint"]}
            if args.prepare_only:
                destination = args.descriptor_out.absolute() if args.descriptor_out else state / "native-target.json"
                write_private_json(destination, descriptor)
                save_acceptance(state, native)
                print(json.dumps({"target": args.name, "status": "prepared", "descriptor_file": str(destination)}, indent=2))
                return 0
            print("Registering and verifying through CAS and Executor...", file=sys.stderr, flush=True)
            receipt = connection.register(descriptor, native=native)
            path = state / "onboarding-receipt.json"
            write_private_json(path, {"descriptor": descriptor, "registration": receipt})
            save_acceptance(state, native)
            print(json.dumps({"target": args.name, "status": "ready", "registration": receipt}, indent=2))
        return 0
    except (OnboardingError, native_codex_ssh.ConfigurationError, OSError, ValueError, RuntimeError,
            subprocess.SubprocessError) as error:
        print(f"Native onboarding incomplete: {error}", file=sys.stderr)
        print("Existing native Codex and any prepared SSH endpoint were preserved. Rerun after resolving the blocker.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
