import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from instance_profile import decode, encode, load, validate


def example():
    return json.loads((ROOT / "config/instance.example.json").read_text())


def write_private(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def test_generic_profile_is_valid_and_round_trips_for_remote_boundary():
    value = example()
    assert decode(encode(value)) == value


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(unexpected="key"),
    lambda value: value["deploy_host"].update(host_key_fingerprint="SHA256:unknown"),
    lambda value: value["vm"]["network"].update(gateway="203.0.113.1"),
    lambda value: value["vm"].update(repo_dir="relative/path"),
])
def test_rejects_unknown_or_unsafe_profile_values(mutation):
    value = example()
    mutation(value)
    with pytest.raises(ValueError):
        validate(value)


def test_profile_file_requires_private_owned_regular_non_symlink_file(tmp_path):
    path = write_private(tmp_path / "instance.json", example())
    assert load(path) == example()

    path.chmod(0o644)
    with pytest.raises(ValueError, match="mode-0600"):
        load(path)

    path.chmod(0o600)
    link = tmp_path / "instance-link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="mode-0600"):
        load(link)


def test_missing_profile_fails_with_install_path(tmp_path):
    with pytest.raises(ValueError, match="Private instance profile is missing"):
        load(tmp_path / "missing.json")

    with pytest.raises(ValueError, match="path must be absolute"):
        load(Path("relative-instance.json"))
