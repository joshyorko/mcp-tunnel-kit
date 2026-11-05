"""Refuse to replace a human-owned CAS promotion branch."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
BRANCH = "automation/cas-promotion"
ALLOWED_FILES = {"config/deploy-images.json", "config/cas-promotion.json"}


def validate_branch(*, commits: list[dict], changed_files: list[str], pull_requests: list[dict]) -> None:
    for commit in commits:
        if (commit.get("author_name") != BOT_NAME or commit.get("author_email") != BOT_EMAIL
                or commit.get("committer_name") != BOT_NAME
                or commit.get("committer_email") != BOT_EMAIL):
            raise ValueError("Existing CAS promotion branch has a non-automation commit")
    if not set(changed_files).issubset(ALLOWED_FILES):
        raise ValueError("Existing CAS promotion branch contains unrelated changes")
    if len(pull_requests) > 1:
        raise ValueError("Multiple open CAS promotion PRs use the automation branch")
    if pull_requests:
        request = pull_requests[0]
        if (request.get("author", {}).get("login") != BOT_NAME
                or request.get("baseRefName") != "main"
                or request.get("headRefName") != BRANCH
                or request.get("isDraft") is not True):
            raise ValueError("Existing CAS promotion PR is not an automation-owned draft")


def check_git_branch(base_ref: str, branch_ref: str, pull_requests: list[dict], *, cwd: Path = Path.cwd()) -> None:
    fmt = "%an%x00%ae%x00%cn%x00%ce"
    result = subprocess.run(["git", "log", "--format=" + fmt, base_ref + ".." + branch_ref],
                            cwd=cwd, check=True, capture_output=True, text=True)
    commits = []
    for line in result.stdout.splitlines():
        fields = line.split("\0")
        if len(fields) != 4:
            raise ValueError("Existing CAS promotion branch history is invalid")
        commits.append(dict(zip(("author_name", "author_email", "committer_name", "committer_email"), fields)))
    result = subprocess.run(["git", "diff", "--name-only", base_ref + "..." + branch_ref],
                            cwd=cwd, check=True, capture_output=True, text=True)
    changed_files = [line for line in result.stdout.splitlines() if line]
    validate_branch(commits=commits, changed_files=changed_files, pull_requests=pull_requests)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--branch-ref", required=True)
    parser.add_argument("--pull-requests", type=Path, required=True)
    args = parser.parse_args()
    try:
        pull_requests = json.loads(args.pull_requests.read_text(encoding="utf-8"))
        if not isinstance(pull_requests, list) or any(not isinstance(row, dict) for row in pull_requests):
            raise ValueError("Open CAS promotion PR response is invalid")
        check_git_branch(args.base_ref, args.branch_ref, pull_requests)
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.SubprocessError, ValueError):
        print("Existing CAS promotion branch is not safe to update; no branch was changed.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
