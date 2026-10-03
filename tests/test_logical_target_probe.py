import importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest
spec=importlib.util.spec_from_file_location('check',Path(__file__).parents[1]/'codex_mcp_check.py')
check=importlib.util.module_from_spec(spec);spec.loader.exec_module(check)


def test_result_preserves_selected_logical_target():
    response=SimpleNamespace(is_error=False,structured_content={'result':{'operation':'thread/list','connection':{'target':'devsy'},'result':{'data':[]}}})
    assert check.native_result(response,'thread/list','devsy')=={'data':[]}


def test_wrong_target_is_rejected():
    response=SimpleNamespace(is_error=False,structured_content={'result':{'operation':'thread/list','connection':{'target':'local'},'result':{'data':[]}}})
    with pytest.raises(check.ProbeError):check.native_result(response,'thread/list','devsy')
