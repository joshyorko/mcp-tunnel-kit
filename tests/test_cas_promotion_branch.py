import importlib.util
import json
from pathlib import Path

import pytest


ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("cas_promotion_branch_test",ROOT/"scripts/cas_promotion_branch.py")
branch=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(branch)


def bot_commit():
    return {"author_name":branch.BOT_NAME,"author_email":branch.BOT_EMAIL,
            "committer_name":branch.BOT_NAME,"committer_email":branch.BOT_EMAIL}


def draft_pr():
    return {"author":{"login":branch.BOT_NAME},"baseRefName":"main",
            "headRefName":branch.BRANCH,"isDraft":True}


def test_update_accepts_only_bot_authored_manifest_and_evidence_branch():
    branch.validate_branch(commits=[bot_commit()],
        changed_files=["config/deploy-images.json","config/cas-promotion.json"],
        pull_requests=[draft_pr()])


@pytest.mark.parametrize("commits,files,prs",[
    ([{**bot_commit(),"author_name":"human"}], ["config/deploy-images.json"], []),
    ([bot_commit()], ["scripts/deploy_control_plane.py"], []),
    ([bot_commit()], ["config/deploy-images.json"], [{**draft_pr(),"isDraft":False}]),
    ([bot_commit()], ["config/deploy-images.json"], [{**draft_pr(),"author":{"login":"human"}}]),
])
def test_update_refuses_human_edits_or_non_draft_pr(commits,files,prs):
    with pytest.raises(ValueError):
        branch.validate_branch(commits=commits,changed_files=files,pull_requests=prs)
