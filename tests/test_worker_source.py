import importlib.util
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def source_module():
    path = ROOT / "scripts/worker_source.py"
    spec = importlib.util.spec_from_file_location("worker_source_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_source_resolution_pins_only_approved_main_and_hashes_recipe():
    module = source_module()
    sha = "1" * 40
    recipe = b'{"name":"remote worker"}\n'
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, f"{sha}\trefs/heads/main\n", "")

    def fetch(url, timeout, max_bytes):
        calls.append((url, timeout, max_bytes))
        return recipe

    snapshot = module.resolve(
        {"repository": "https://github.com/joshyorko/codex-action-server.git",
         "source_ref": "refs/heads/main",
         "recipe": ".devcontainer/remote-worker/devcontainer.json",
         "caller_repository": "https://caller.invalid/repo.git",
         "caller_ref": "refs/heads/evil"},
        run=run,
        fetch=fetch,
    )

    assert calls[0][0] == [
        "git", "-c", "credential.helper=", "ls-remote", "--exit-code",
        "https://github.com/joshyorko/codex-action-server.git", "refs/heads/main",
    ]
    assert calls[0][1]["timeout"] <= 10
    assert calls[1][0] == (
        "https://raw.githubusercontent.com/joshyorko/codex-action-server/"
        f"{sha}/.devcontainer/remote-worker/devcontainer.json"
    )
    assert snapshot == {
        "repository": "https://github.com/joshyorko/codex-action-server.git",
        "source_ref": "refs/heads/main",
        "revision": sha,
        "recipe": ".devcontainer/remote-worker/devcontainer.json",
        "recipe_sha256": "b5e6d0924939ab2cb1abfd5db8a47200d330fd1d33bf4e615b19b0d136c56824",
        "recipe_snapshot": recipe,
    }


def test_source_resolution_rejects_non_exact_or_ambiguous_main_ref():
    module = source_module()
    malformed = subprocess.CompletedProcess(
        ["git"], 0, "refs/heads/main\t" + "1" * 40 + "\n", ""
    )

    def run(argv, **kwargs):
        return malformed

    def fetch(*_args, **_kwargs):
        raise AssertionError("Recipe fetch must not follow an invalid ref result.")

    try:
        module.resolve({}, run=run, fetch=fetch)
    except module.SourceResolutionError:
        pass
    else:
        raise AssertionError("Malformed ls-remote output was accepted.")
