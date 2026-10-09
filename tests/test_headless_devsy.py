import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def module():
    path = ROOT / "scripts/headless_devsy.py"
    spec = importlib.util.spec_from_file_location("headless_devsy_test", path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def fixture(tmp_path):
    source = tmp_path / "home" / "config.yaml"
    source.parent.mkdir(mode=0o700)
    source.write_text("{}\n")
    source.chmod(0o600)
    scope = {"context": "default", "bindings": {
        str(source.resolve()): hashlib.sha256(source.read_bytes()).hexdigest(),
    }}
    binary = tmp_path / "devsy"
    binary.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
path = Path(os.environ['DEVSY_CONFIG'])
if path.parent.stat().st_mode & 0o777 != 0o700 or path.stat().st_mode & 0o777 != 0o600:
    raise SystemExit(71)
if os.environ.get('DEVSY_HOME') != ORIGINAL_HOME:
    raise SystemExit(72)
if sys.argv[1:] == ['--context', 'default', 'context', 'set', '--option', 'SSH_TUNNEL_MODE=false']:
    path.write_text(json.dumps({'SSH_TUNNEL_MODE': {'value': 'false'}}))
elif sys.argv[1:] == ['--context', 'default', 'context', 'get', '--result-format', 'json']:
    print(path.read_text())
else:
    raise SystemExit(73)
""".replace("ORIGINAL_HOME", repr(str(source.parent))))
    binary.chmod(0o700)
    return source, scope, binary


def test_prepare_writes_native_setting_to_private_copy_and_keeps_original(tmp_path):
    loaded = module()
    source, scope, binary = fixture(tmp_path)
    before = source.read_bytes()
    scratch = tmp_path / "scratch"
    env = {"DEVSY_HOME": str(source.parent), "KEEP_ME": "unchanged"}

    result = loaded.prepare(binary, tmp_path, env, scope, scratch)

    copied = Path(result["DEVSY_CONFIG"])
    assert result["DEVSY_HOME"] == str(source.parent)
    assert result["KEEP_ME"] == "unchanged"
    assert copied != source
    assert copied.parent.stat().st_mode & 0o777 == 0o700
    assert copied.stat().st_mode & 0o777 == 0o600
    assert json.loads(copied.read_text())["SSH_TUNNEL_MODE"]["value"] == "false"
    assert source.read_bytes() == before


def test_prepare_refuses_unbound_config_before_invoking_devsy(tmp_path):
    loaded = module()
    source, scope, binary = fixture(tmp_path)
    scope["bindings"] = {}
    marker = tmp_path / "called"
    binary.write_text("#!/usr/bin/env python3\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n")
    binary.chmod(0o700)

    with pytest.raises(loaded.HeadlessDevsyError):
        loaded.prepare(binary, tmp_path, {"DEVSY_HOME": str(source.parent)}, scope,
                       tmp_path / "scratch")

    assert not marker.exists()
    assert not (tmp_path / "scratch").exists()


def test_prepare_refuses_if_native_set_does_not_disable_tunnel(tmp_path):
    loaded = module()
    source, scope, binary = fixture(tmp_path)
    binary.write_text("""#!/usr/bin/env python3
import json, sys
if sys.argv[-2:] == ['--option', 'SSH_TUNNEL_MODE=false']:
    raise SystemExit(0)
print(json.dumps({'SSH_TUNNEL_MODE': {'value': 'true'}}))
""")
    binary.chmod(0o700)

    with pytest.raises(loaded.HeadlessDevsyError):
        loaded.prepare(binary, tmp_path, {"DEVSY_HOME": str(source.parent)}, scope,
                       tmp_path / "scratch")

    assert source.read_text() == "{}\n"
