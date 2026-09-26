# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from metis_firmware_campaign import autonomous_campaign


def test_resume_repeats_zero_completed_provider_calls(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    calls = project / "provider-calls"
    failed = project / "late-callback-failed"
    helper = project / "provider_stage.py"
    helper.write_text(
        "\n".join(
            (
                "import json, os, pathlib, sys",
                "from metis.cli.review_checkpoints import review_checkpoint_callbacks",
                "from metis.version import __version__",
                "callbacks=review_checkpoint_callbacks(codebase_path='unused',enabled=True)",
                "records=callbacks['review_resume_callback']('provider_fixture') or {}",
                f"calls=pathlib.Path({str(calls)!r})",
                "if 'record-a' not in records:",
                " calls.open('a').write('provider-call\\n')",
                " callbacks['review_checkpoint_callback']({'metis_version':__version__,'producer':'provider_fixture','key':'record-a','record':{'result':'complete'}},1,1)",
                f"failed=pathlib.Path({str(failed)!r})",
                "if not failed.exists(): failed.write_text('late diagnostic callback failure');sys.exit(19)",
                "pathlib.Path(sys.argv[1],'result.json').write_text(json.dumps({'resumed':bool(records),'provider_calls_repeated':0}))",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    profile_path = project / "profile.json"
    profile_path.write_text("{}", encoding="utf-8")
    stage = {
        "stage_id": "provider-stage",
        "phase": "PROVIDER_HEALTH",
        "adapter": [sys.executable, str(helper), "{output_dir}"],
        "required_outputs": ["result.json"],
    }
    profile = {
        "schema_version": "5",
        "project": {"project_id": "firmware"},
        "automation": {
            "campaign_reader_limit": 1,
            "provider_worker_configuration_limit": 1,
        },
    }
    args = (stage, profile, {"locator": str(profile_path), "sha256": "a" * 64})
    with pytest.raises(autonomous_campaign.ContractError, match="adapter failed"):
        autonomous_campaign.execute_stage(*args, tmp_path / "state", tmp_path / "candidate.db", {}, {}, {"tickets": [], "confluence": []}, {})
    receipt = autonomous_campaign.execute_stage(*args, tmp_path / "state", tmp_path / "candidate.db", {}, {}, {"tickets": [], "confluence": []}, {})
    assert receipt["status"] == "COMPLETE"
    assert calls.read_text().splitlines() == ["provider-call"]
    assert list((tmp_path / "state" / "provider-results").rglob("*.sqlite3"))


def test_checkout_state_supports_only_safe_git_tracked_symlinks(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "target.c").write_text("int target(void) { return 0; }\n")
    os.symlink("target.c", repo / "tracked-link.c")
    subprocess.run(["git", "-C", str(repo), "add", "target.c", "tracked-link.c"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "fixture"], check=True, capture_output=True)
    state = autonomous_campaign.checkout_state(repo)
    assert state["files"] == 2 and len(state["tree_sha256"]) == 64
    (repo / "tracked-link.c").unlink()
    (tmp_path / "outside.c").write_text("int outside(void);\n")
    os.symlink("../outside.c", repo / "tracked-link.c")
    subprocess.run(["git", "-C", str(repo), "add", "tracked-link.c"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "escape"], check=True, capture_output=True)
    with pytest.raises(autonomous_campaign.ContractError, match="escapes source checkout"):
        autonomous_campaign.checkout_state(repo)
