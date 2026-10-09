"""Resolve one immutable source snapshot for an approved new worker create."""

import hashlib
import json
import os
import re
import selectors
import subprocess
import time
import urllib.request


APPROVED_REPOSITORY = "https://github.com/joshyorko/codex-action-server.git"
APPROVED_SOURCE_REF = "refs/heads/main"
APPROVED_RECIPE = ".devcontainer/remote-worker/devcontainer.json"
MAX_RECIPE_BYTES = 1024 * 1024
MAX_RESOLUTION_SECONDS = 10
MAX_LS_REMOTE_BYTES = 128


class SourceResolutionError(Exception):
    """A safe fixed diagnostic for refusing source snapshot resolution."""


def _fetch(url, timeout, max_bytes):
    request = urllib.request.Request(url, headers={"User-Agent": "codex-devsy-worker/1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        content = response.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise SourceResolutionError
    return content


def _run_ls_remote(argv, timeout):
    git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    git_env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1",
                   GIT_CONFIG_GLOBAL=os.devnull)
    process = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env=git_env,
    )
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise SourceResolutionError
                chunk = os.read(process.stdout.fileno(), MAX_LS_REMOTE_BYTES + 1 - len(output))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_LS_REMOTE_BYTES:
                    raise SourceResolutionError
        return subprocess.CompletedProcess(
            argv, process.wait(timeout=max(0, deadline - time.monotonic())),
            output.decode("ascii", errors="strict"), "",
        )
    except Exception:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        process.stdout.close()


def resolve(scope, run=None, fetch=_fetch):
    """Resolve the fixed public main ref and its fixed devcontainer document."""
    if not isinstance(scope, dict) or any(
        scope.get(key) != expected
        for key, expected in (
            ("repository", APPROVED_REPOSITORY),
            ("source_ref", APPROVED_SOURCE_REF),
            ("recipe", APPROVED_RECIPE),
        )
    ):
        raise SourceResolutionError("Approved worker source policy refused.")
    try:
        command = [
            "git", "-c", "credential.helper=", "ls-remote", "--exit-code",
            APPROVED_REPOSITORY, APPROVED_SOURCE_REF,
        ]
        result = (run or _run_ls_remote)(command, timeout=MAX_RESOLUTION_SECONDS)
        match = re.fullmatch(r"([a-f0-9]{40})\trefs/heads/main\n?", result.stdout or "")
        if result.returncode != 0 or not match:
            raise SourceResolutionError
        revision = match.group(1)
        url = (
            "https://raw.githubusercontent.com/joshyorko/codex-action-server/"
            f"{revision}/{APPROVED_RECIPE}"
        )
        recipe = fetch(url, timeout=MAX_RESOLUTION_SECONDS, max_bytes=MAX_RECIPE_BYTES)
        if not isinstance(recipe, bytes) or not recipe or len(recipe) > MAX_RECIPE_BYTES:
            raise SourceResolutionError
        document = json.loads(recipe)
        if not isinstance(document, dict):
            raise SourceResolutionError
        return {
            "repository": APPROVED_REPOSITORY,
            "source_ref": APPROVED_SOURCE_REF,
            "revision": revision,
            "recipe": APPROVED_RECIPE,
            "recipe_sha256": hashlib.sha256(recipe).hexdigest(),
            "recipe_snapshot": recipe,
        }
    except SourceResolutionError:
        raise SourceResolutionError("Approved worker source could not be resolved.") from None
    except Exception as exc:
        raise SourceResolutionError("Approved worker source could not be resolved.") from exc
