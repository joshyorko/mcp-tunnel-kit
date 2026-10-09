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


def _registry_fetch(url, headers):
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=MAX_RESOLUTION_SECONDS) as response:
        value = response.read(8 * 1024 * 1024 + 1)
    if len(value) > 8 * 1024 * 1024:
        raise SourceResolutionError
    return value


def _image_snapshot(revision, fetch):
    repository = "ghcr.io/joshyorko/codex-action-server"
    token = json.loads(fetch("https://ghcr.io/token?service=ghcr.io&scope=repository:joshyorko/codex-action-server:pull", {})).get("token")
    if not isinstance(token, str) or not token:
        raise SourceResolutionError
    headers = {"Authorization": "Bearer " + token, "Accept": ", ".join([
        "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.docker.distribution.manifest.v2+json"])}
    base = "https://ghcr.io/v2/joshyorko/codex-action-server/"
    raw = fetch(base + "manifests/worker-sha-" + revision, headers)
    manifest = json.loads(raw)
    if "manifests" in manifest:
        candidates = [entry for entry in manifest["manifests"]
                      if entry.get("platform", {}).get("os") == "linux"
                      and entry.get("platform", {}).get("architecture") == "amd64"]
        if len(candidates) != 1:
            raise SourceResolutionError
        digest = candidates[0]["digest"]
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise SourceResolutionError
        raw = fetch(base + "manifests/" + digest, headers)
        if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
            raise SourceResolutionError
        manifest = json.loads(raw)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    config_digest = manifest["config"]["digest"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", config_digest):
        raise SourceResolutionError
    config_raw = fetch(base + "blobs/" + config_digest, headers)
    if "sha256:" + hashlib.sha256(config_raw).hexdigest() != config_digest:
        raise SourceResolutionError
    config = json.loads(config_raw)
    if (config.get("architecture") != "amd64" or config.get("os") != "linux"
            or config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != revision):
        raise SourceResolutionError
    return {"source_kind": "image", "image_ref": repository, "image_digest": digest}


def resolve(scope, run=None, fetch=_fetch, registry_fetch=_registry_fetch):
    """Resolve the fixed public main ref and its fixed devcontainer document."""
    if not isinstance(scope, dict) or any(
        scope.get(key) != expected
        for key, expected in (
            ("repository", APPROVED_REPOSITORY),
            ("source_ref", APPROVED_SOURCE_REF),
            ("recipe", "Containerfile.worker" if scope.get("source_kind") == "image" else APPROVED_RECIPE),
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
        image_mode = scope.get("source_kind") == "image"
        if image_mode and scope.get("image_repository") != "ghcr.io/joshyorko/codex-action-server":
            raise SourceResolutionError
        recipe_path = "Containerfile.worker" if image_mode else APPROVED_RECIPE
        url = (
            "https://raw.githubusercontent.com/joshyorko/codex-action-server/"
            f"{revision}/{recipe_path}"
        )
        recipe = fetch(url, timeout=MAX_RESOLUTION_SECONDS, max_bytes=MAX_RECIPE_BYTES)
        if not isinstance(recipe, bytes) or not recipe or len(recipe) > MAX_RECIPE_BYTES:
            raise SourceResolutionError
        if not image_mode and not isinstance(json.loads(recipe), dict):
            raise SourceResolutionError
        image = _image_snapshot(revision, registry_fetch) if image_mode else {}
        return {
            "repository": APPROVED_REPOSITORY,
            "source_ref": APPROVED_SOURCE_REF,
            "revision": revision,
            "recipe": recipe_path,
            "recipe_sha256": hashlib.sha256(recipe).hexdigest(),
            "recipe_snapshot": recipe,
            **image,
        }
    except SourceResolutionError:
        raise SourceResolutionError("Approved worker source could not be resolved.") from None
    except Exception as exc:
        raise SourceResolutionError("Approved worker source could not be resolved.") from exc
