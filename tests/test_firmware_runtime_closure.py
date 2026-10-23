# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from metis_firmware_campaign import autonomous_campaign
from metis_firmware_campaign.analysis_packet import validate as validate_analysis_packet


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


def test_v672_boundary_repairs(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    profile_path = project / "profile.json"
    profile_path.write_text("{}")
    candidate = project / "candidate.db"
    with sqlite3.connect(candidate) as database:
        database.execute("CREATE TABLE probe(value TEXT)")
        database.execute("INSERT INTO probe VALUES('original')")
    helper = project / "adapter.py"
    helper.write_text(
        "import json,os,pathlib,sqlite3,sys\n"
        "c=json.loads(pathlib.Path(sys.argv[2]).read_text());o=pathlib.Path(c['output_directory']);p=pathlib.Path(c['project_directory'])\n"
        "a=sys.argv[1]\n"
        "if a=='env':print(os.environ.get('FIRMWARE_REVIEW_OTHER_STAGE_TOKEN','absent'))\n"
        "if a=='direct':\n with sqlite3.connect(p/'candidate.db') as d:d.execute(\"UPDATE probe SET value='bad'\")\n"
        "if a=='collect':v=json.loads((p/'remote.json').read_text())\n"
        "else:v={'ok':True}\n"
        "(o/'result.json').write_text(json.dumps(v))\n"
    )
    profile = {"schema_version": "6.7", "project": {"project_id": "fixture"},
               "automation": {"campaign_reader_limit": 1,
                              "provider_worker_configuration_limit": 1}}
    identity = {"locator": str(profile_path), "sha256": "a" * 64}
    state = project / "state"
    selectors = {"tickets": [], "confluence": []}

    def execute(stage):
        return autonomous_campaign.execute_stage(
            stage, profile, identity, state, candidate, {}, {}, selectors, {}
        )

    def stage(stage_id, action="ok", phase="SOURCE_COLLECTION", **extra):
        return {"stage_id": stage_id, "phase": phase,
                "adapter": [sys.executable, str(helper), action, "{context}"],
                "required_outputs": ["result.json"], **extra}

    missing = "FIRMWARE_REVIEW_MISSING_TOKEN"
    os.environ.pop(missing, None)
    assert execute(stage("credential", credential_env=[missing]))["status"] == "BLOCKED"
    os.environ[missing] = "dummy"
    assert execute(stage("credential", credential_env=[missing]))["status"] == "COMPLETE"
    os.environ.pop(missing)

    sentinel = "FIRMWARE-REVIEW-FAKE-TOKEN"
    os.environ["FIRMWARE_REVIEW_OTHER_STAGE_TOKEN"] = sentinel
    receipt = execute(stage("env", "env"))
    assert sentinel not in (
        state / "stages" / "env" / receipt["stage_identity"] / "stdout.log"
    ).read_text()
    os.environ.pop("FIRMWARE_REVIEW_OTHER_STAGE_TOKEN")

    with pytest.raises(autonomous_campaign.ContractError, match="authoritative candidate directly"):
        execute(stage("direct", "direct"))
    with sqlite3.connect(candidate) as database:
        assert database.execute("SELECT value FROM probe").fetchone()[0] == "original"

    (project / "remote.json").write_text('{"tickets":["old"]}')
    current = stage("current", "collect", "CURRENT_TICKET_COLLECTION", refresh_on_resume=True)
    execute(current)
    (project / "remote.json").write_text('{"tickets":["old","new"]}')
    refreshed = execute(current)
    assert json.loads((state / "stages" / "current" / refreshed["stage_identity"] / "result.json").read_text())["tickets"] == ["old", "new"]

    worker = project / "worker.py"
    worker.write_text("print('one')\n")
    worker_stage = stage("worker", worker_adapter=[sys.executable, str(worker)])
    first = autonomous_campaign.stage_inputs(worker_stage, profile, identity, state, candidate, {}, {}, selectors, {})["worker_adapter_sha256"]
    worker.write_text("print('two')\n")
    second = autonomous_campaign.stage_inputs(worker_stage, profile, identity, state, candidate, {}, {}, selectors, {})["worker_adapter_sha256"]
    assert first != second


def test_v67_terminal_capsule_and_checkout_containment(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "inside.c").write_text("int inside(void);\n")
    (tmp_path / "outside.c").write_text("int outside(void);\n")
    record = {"record_id": "fixture", "decision_status": "TERMINAL",
              "technical_class": "NO_BUG", "programme_scope": "UNRESOLVED",
              "scanner_claim_status": "UNSUPPORTED", "source_reread": True,
              "decisive_sources": [{"component_id": "core", "path": "inside.c",
                                    "line": 1, "file_sha256": autonomous_campaign.file_hash(source / "inside.c")}],
              "exact_counterevidence": "Operation absent.",
              "exact_counterevidence_category": "CLAIMED_OPERATION_SINK_OR_EFFECT_ABSENT",
              "creates_root": False}
    packet = {"contract_version": "6.7", "authoritative_integrator": True,
              "campaign_write_attempts": 0, "records": [record]}
    packet["packet_sha256"] = autonomous_campaign.object_hash(packet)
    errors = validate_analysis_packet(packet, {"core": str(source)})
    assert any("capsule" in error for error in errors)
    record["decisive_sources"][0].update(path="../outside.c", file_sha256=autonomous_campaign.file_hash(tmp_path / "outside.c"))
    packet["packet_sha256"] = autonomous_campaign.object_hash({key: value for key, value in packet.items() if key != "packet_sha256"})
    assert any("escapes checkout" in error for error in validate_analysis_packet(packet, {"core": str(source)}))
