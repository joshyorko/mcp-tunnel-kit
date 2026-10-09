"""Prepare an isolated Devsy config for headless scoped workspace jobs."""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile


class HeadlessDevsyError(Exception):
    """A safe, fixed diagnostic for refusing isolated config preparation."""


def _config_path(env):
    configured = env.get("DEVSY_CONFIG")
    if configured:
        return Path(configured)
    home = env.get("DEVSY_HOME")
    if home:
        return Path(home) / "config.yaml"
    return Path(env.get("HOME", str(Path.home()))) / ".devsy" / "config.yaml"


def _bound_bytes(path, scope):
    try:
        resolved = path.resolve(strict=True)
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise HeadlessDevsyError
            content = source.read()
        digest = hashlib.sha256(content).hexdigest()
        if scope.get("bindings", {}).get(str(resolved)) != digest:
            raise HeadlessDevsyError
        return resolved, content, digest
    except HeadlessDevsyError:
        raise
    except Exception as exc:
        raise HeadlessDevsyError from exc


def _run(binary, cwd, env, args):
    try:
        result = subprocess.run(
            [str(binary), *args], cwd=cwd, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=10, check=False,
        )
        if result.returncode != 0:
            raise HeadlessDevsyError
        return result.stdout
    except HeadlessDevsyError:
        raise
    except Exception as exc:
        raise HeadlessDevsyError from exc


def prepare(binary, cwd, env, scope, scratch):
    """Return an env using a bound, private config copy with SSH tunneling off.

    The supplied scratch directory is treated as job-owned; a unique 0700 child
    holds the 0600 copy so concurrent jobs never share mutable config state.
    """
    if not isinstance(env, dict) or not isinstance(scope, dict):
        raise HeadlessDevsyError("Unable to prepare isolated headless Devsy configuration.")
    original, content, digest = _bound_bytes(_config_path(env), scope)
    scratch = Path(scratch)
    try:
        scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
        scratch_info = scratch.lstat()
        if (not stat.S_ISDIR(scratch_info.st_mode) or scratch_info.st_uid != os.getuid()
                or stat.S_IMODE(scratch_info.st_mode) != 0o700):
            raise HeadlessDevsyError
        job_dir = Path(tempfile.mkdtemp(prefix="devsy-headless-", dir=scratch))
        job_dir.chmod(0o700)
        config_copy = job_dir / "config.yaml"
        fd = os.open(config_copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        copied_env = dict(env)
        copied_env["DEVSY_HOME"] = env.get("DEVSY_HOME") or str(
            Path(env.get("HOME", str(Path.home()))) / ".devsy"
        )
        copied_env["DEVSY_CONFIG"] = str(config_copy)
        context = scope.get("context")
        if not isinstance(context, str) or not context:
            raise HeadlessDevsyError

        # Exercise the native writer only after DEVSY_CONFIG points at the copy.
        _run(binary, cwd, copied_env,
             ["--context", context, "context", "set", "--option", "SSH_TUNNEL_MODE=false"])
        current = hashlib.sha256(original.read_bytes()).hexdigest()
        if current != digest:
            raise HeadlessDevsyError
        output = _run(binary, cwd, copied_env,
                      ["--context", context, "context", "get", "--result-format", "json"])
        options = json.loads(output)
        tunnel = options.get("SSH_TUNNEL_MODE", {}).get("value")
        if tunnel != "false":
            raise HeadlessDevsyError
        return copied_env
    except HeadlessDevsyError:
        raise HeadlessDevsyError("Unable to prepare isolated headless Devsy configuration.")
    except Exception as exc:
        raise HeadlessDevsyError("Unable to prepare isolated headless Devsy configuration.") from exc
