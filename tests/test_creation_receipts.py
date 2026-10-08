"""Real synthetic stdio effects prove uncertain creates are never replayed."""

import json

import pytest

from test_devsy_bridge import bridge, fixture


def configured(tmp_path):
    module = bridge()
    devsy = fixture(
        module,
        tmp_path,
        FIXTURE_MODE="create-uncertain",
        FIXTURE_CALLS=str(tmp_path / "calls"),
        FIXTURE_RESOURCES=str(tmp_path / "resources"),
    )
    devsy.creation_state = tmp_path / "creation-receipts"
    return module, devsy


REQUEST = {
    "name": "codex-action-server",
    "source": "git:https://github.com/joshyorko/codex-action-server.git",
    "provider": "kubernetes",
    "devcontainer_path": ".devcontainer/remote-worker/devcontainer.json",
}


def test_lost_response_is_explicitly_uncertain_and_replay_never_creates_again(tmp_path):
    _, devsy = configured(tmp_path)
    result = devsy.call("workspace_create", REQUEST)
    receipt = result.get("structuredContent", {})
    assert receipt.get("status") == "outcome_unknown"
    assert result["isError"] is True
    assert receipt["retry_safe"] is False
    assert receipt["may_have_succeeded"] is True

    # A new bridge object models process restart after external side effects.
    _, restarted = configured(tmp_path)
    repeated = restarted.call("workspace_create", REQUEST)["structuredContent"]
    assert repeated["operation_id"] == receipt["operation_id"]
    assert repeated["retry_safe"] is False
    assert (tmp_path / "calls").read_text().splitlines().count("workspace_create") == 1


def test_existing_name_is_observed_without_mutating_or_claiming_creation(tmp_path):
    _, devsy = configured(tmp_path)
    (tmp_path / "resources").write_text(json.dumps([{"name": "codex-action-server"}]))
    result = devsy.call("workspace_create", REQUEST)["structuredContent"]
    assert result["status"] == "existing_requires_inspection"
    assert result["retry_safe"] is False
    assert "workspace_create" not in (tmp_path / "calls").read_text().splitlines()


def test_changed_request_cannot_reuse_same_named_creation_intent(tmp_path):
    _, devsy = configured(tmp_path)
    devsy.call("workspace_create", REQUEST)
    conflict = devsy.call(
        "workspace_create",
        {**REQUEST, "source": "git:https://example.invalid/other.git"},
    )
    assert conflict["isError"] is True
    assert conflict["structuredContent"]["status"] == "request_conflict"
    assert (tmp_path / "calls").read_text().splitlines().count("workspace_create") == 1


def test_receipt_poll_never_submits_or_queries_upstream(tmp_path):
    _, devsy = configured(tmp_path)
    result = devsy.call("workspace_create_receipt", {"name": "codex-action-server"})
    assert result["structuredContent"]["status"] == "not_submitted"
    assert not (tmp_path / "calls").exists()
    devsy.call("workspace_create", REQUEST)
    prior = (tmp_path / "calls").read_bytes()
    assert (
        devsy.call("workspace_create_receipt", {"name": "codex-action-server"})[
            "structuredContent"
        ]["status"]
        == "outcome_unknown"
    )
    assert (tmp_path / "calls").read_bytes() == prior


def test_receipt_storage_refuses_symlink_and_does_not_call_upstream(tmp_path):
    module, devsy = configured(tmp_path)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    devsy.creation_state.symlink_to(other, target_is_directory=True)
    with pytest.raises(module.BridgeError):
        devsy.call("workspace_create", REQUEST)
    assert not (tmp_path / "calls").exists()


def test_raw_create_remains_destructive_and_only_receipt_is_readonly(tmp_path):
    _, devsy = configured(tmp_path)
    tools = {x["name"]: x for x in devsy.catalog()}
    assert tools["workspace_create"]["annotations"]["destructiveHint"] is True
    assert tools["workspace_create"]["annotations"]["readOnlyHint"] is False
    assert tools["workspace_create_receipt"]["annotations"]["readOnlyHint"] is True


def test_same_name_live_lock_returns_progress_without_another_submission(tmp_path):
    import threading

    module, devsy = configured(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = devsy.upstream_call

    def upstream(tool, arguments):
        if tool == "workspace_create":
            entered.set()
            assert release.wait(5)
        return original(tool, arguments)

    devsy.upstream_call = upstream
    results = []
    first = threading.Thread(
        target=lambda: results.append(devsy.call("workspace_create", REQUEST))
    )
    first.start()
    assert entered.wait(5)
    try:
        _, second = configured(tmp_path)
        result = second.call("workspace_create", REQUEST)["structuredContent"]
        assert result["status"] == "in_progress"
        assert result["retry_safe"] is False
    finally:
        release.set()
        first.join(5)
    assert not first.is_alive()
    assert (tmp_path / "calls").read_text().splitlines().count("workspace_create") == 1


def test_completed_receipt_is_reused_after_restart_without_new_upstream_calls(tmp_path):
    module, devsy = configured(tmp_path)
    ordinary = fixture(module, tmp_path, FIXTURE_CALLS=str(tmp_path / "calls"))
    # Retain a real stdio call for submission, and valid synthetic empty inventory.
    ordinary.creation_inventory = lambda: set()
    ordinary.creation_state = devsy.creation_state
    original = ordinary.call("workspace_create", REQUEST)
    assert original["_meta"]["creationReceipt"]["status"] == "completed"
    before = (tmp_path / "calls").read_bytes()
    _, restarted = configured(tmp_path)
    replay = restarted.call("workspace_create", REQUEST)["structuredContent"]
    assert replay["status"] == "completed"
    assert (
        replay["operation_id"] == original["_meta"]["creationReceipt"]["operation_id"]
    )
    assert (tmp_path / "calls").read_bytes() == before
