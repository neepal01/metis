# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path

import pytest

from metis.cli import entry
from metis_firmware_campaign import analysis_packet
from metis_firmware_campaign import autonomous_campaign
from metis_firmware_campaign import launcher


def _profile(
    path: Path, *, components: list[dict], launcher_config: dict | None = None
):
    path.write_text(
        json.dumps(
            {
                "schema_version": "5",
                "project": {
                    "project_id": "example-firmware",
                    "components": components,
                },
                "automation": {
                    "format_version": "firmware-autonomous-campaign-v1",
                    "metis_cli": launcher_config or {},
                },
            }
        ),
        encoding="utf-8",
    )


def _component(component_id: str, repository: str) -> dict:
    return {
        "component_id": component_id,
        "repository": repository,
        "revision": "a" * 40,
        "tree_sha256": "b" * 64,
    }


def test_launch_derives_project_paths_and_primary_source(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source"
    source.mkdir()
    profile = tmp_path / "profile.json"
    _profile(
        profile, components=[_component("firmware", "https://example/firmware.git")]
    )
    captured = {}

    def run(args):
        captured.update(vars(args))
        return {"workflow_sha256": "c" * 64}

    monkeypatch.setattr(launcher.autonomous_campaign, "run", run)
    assert (
        launcher.launch(
            profile_path=profile,
            codebase_path=source,
            resume=True,
            additional_source_paths=[],
        )
        == 0
    )
    assert captured["candidate"] == str(
        tmp_path / "candidate" / "example-firmware.candidate.db"
    )
    assert captured["state"] == str(tmp_path / "automation")
    assert captured["source_path"] == [f"firmware={source}"]
    assert json.loads(capsys.readouterr().out)["result"] == "PASS"


def test_existing_state_requires_resume(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source"
    source.mkdir()
    state = tmp_path / "automation"
    state.mkdir()
    (state / "receipt.json").write_text("{}", encoding="utf-8")
    profile = tmp_path / "profile.json"
    _profile(
        profile, components=[_component("firmware", "https://example/firmware.git")]
    )
    monkeypatch.setattr(
        launcher.autonomous_campaign,
        "run",
        lambda _args: pytest.fail("campaign should not run"),
    )
    assert (
        launcher.launch(
            profile_path=profile,
            codebase_path=source,
            resume=False,
            additional_source_paths=[],
        )
        == 1
    )
    assert "requires --resume" in json.loads(capsys.readouterr().err)["error"]


def test_multi_component_profile_accepts_additional_source(tmp_path, monkeypatch):
    source = tmp_path / "primary"
    source.mkdir()
    support = tmp_path / "support"
    support.mkdir()
    profile = tmp_path / "profile.json"
    _profile(
        profile,
        components=[
            _component("firmware", "https://example/firmware.git"),
            _component("support", "https://example/support.git"),
        ],
        launcher_config={"primary_component_id": "firmware"},
    )
    captured = {}
    monkeypatch.setattr(
        launcher.autonomous_campaign,
        "run",
        lambda args: captured.update(vars(args)) or {},
    )
    assert (
        launcher.launch(
            profile_path=profile,
            codebase_path=source,
            resume=True,
            additional_source_paths=[f"support={support}"],
        )
        == 0
    )
    assert captured["source_path"] == [f"firmware={source}", f"support={support}"]


@pytest.mark.parametrize(
    ("launcher_config", "error"),
    [
        ({"candidate": "../production.db"}, "campaign project directory"),
        ({"state": "../shared-state"}, "campaign project directory"),
    ],
)
def test_launch_rejects_outputs_outside_campaign_project(
    tmp_path, monkeypatch, capsys, launcher_config, error
):
    source = tmp_path / "source"
    source.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    profile = project / "profile.json"
    _profile(
        profile,
        components=[_component("firmware", "https://example/firmware.git")],
        launcher_config=launcher_config,
    )
    monkeypatch.setattr(
        launcher.autonomous_campaign,
        "run",
        lambda _args: pytest.fail("campaign should not run"),
    )
    assert (
        launcher.launch(
            profile_path=profile,
            codebase_path=source,
            resume=True,
            additional_source_paths=[],
        )
        == 1
    )
    assert error in json.loads(capsys.readouterr().err)["error"]


def test_launch_rejects_source_as_output_location(tmp_path, monkeypatch, capsys):
    project = tmp_path / "project"
    project.mkdir()
    source = project / "source"
    source.mkdir()
    profile = project / "profile.json"
    _profile(
        profile,
        components=[_component("firmware", "https://example/firmware.git")],
        launcher_config={"state": "source/campaign-state"},
    )
    monkeypatch.setattr(
        launcher.autonomous_campaign,
        "run",
        lambda _args: pytest.fail("campaign should not run"),
    )
    assert (
        launcher.launch(
            profile_path=profile,
            codebase_path=source,
            resume=True,
            additional_source_paths=[],
        )
        == 1
    )
    assert "outside the primary source" in json.loads(capsys.readouterr().err)["error"]


def test_launch_rejects_duplicate_source_components(tmp_path, monkeypatch, capsys):
    source = tmp_path / "primary"
    source.mkdir()
    support = tmp_path / "support"
    support.mkdir()
    profile = tmp_path / "profile.json"
    _profile(
        profile,
        components=[
            _component("firmware", "https://example/firmware.git"),
            _component("support", "https://example/support.git"),
        ],
        launcher_config={"primary_component_id": "firmware"},
    )
    monkeypatch.setattr(
        launcher.autonomous_campaign,
        "run",
        lambda _args: pytest.fail("campaign should not run"),
    )
    assert (
        launcher.launch(
            profile_path=profile,
            codebase_path=source,
            resume=True,
            additional_source_paths=[f"support={support}", f"support={support}"],
        )
        == 1
    )
    assert "must be unique" in json.loads(capsys.readouterr().err)["error"]


def test_worker_cannot_emit_authoritative_packet(tmp_path, monkeypatch):
    stage = tmp_path / "stage"
    stage.mkdir()
    context = {"source_checkouts": {}}

    def emit(_command, _context, work, _credentials):
        packet = {
            "records": [
                {
                    "record_id": "record-1",
                    "decision_status": "NON_TERMINAL",
                    "technical_class": "DEFERRED",
                    "programme_scope": "UNRESOLVED",
                    "scanner_claim_status": "UNRESOLVED",
                    "source_reread": True,
                    "decisive_sources": [],
                    "reopen_condition": "Exact source input remains unavailable.",
                }
            ],
            "campaign_write_attempts": 0,
            "authoritative_integrator": True,
        }
        packet["packet_sha256"] = autonomous_campaign.object_hash(packet)
        (work / "result.packet.json").write_text(json.dumps(packet), encoding="utf-8")

    monkeypatch.setattr(autonomous_campaign, "run_command", emit)
    with pytest.raises(
        autonomous_campaign.ContractError, match="worker 0 analysis packet failed"
    ):
        autonomous_campaign.worker_run(0, ["unused"], context, stage, [])


def test_decisive_source_cannot_escape_its_component_checkout(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside.c"
    outside.write_text("int outside(void) { return 1; }\n", encoding="utf-8")
    record = {
        "record_id": "record-1",
        "decision_status": "TERMINAL",
        "technical_class": "NO_BUG",
        "programme_scope": "NOT_APPLICABLE",
        "scanner_claim_status": "UNSUPPORTED",
        "source_reread": True,
        "decisive_sources": [
            {
                "component_id": "firmware",
                "path": "../outside.c",
                "file_sha256": autonomous_campaign.file_hash(outside),
            }
        ],
        "exact_counterevidence": "The exact source disproves the claim.",
    }
    packet = {"records": [record], "campaign_write_attempts": 0}
    packet["packet_sha256"] = autonomous_campaign.object_hash(packet)
    errors = autonomous_campaign.validate_analysis_packet(
        packet, {"firmware": str(source)}
    )
    assert "decisive source escapes checkout: record-1" in errors


def test_valid_record_requires_substantive_proof_and_hash_bound_dedup(tmp_path):
    source = tmp_path / "firmware.c"
    source.write_text("int firmware(void) { return 0; }\n", encoding="utf-8")
    record = {
        "record_id": "record-1",
        "decision_status": "TERMINAL",
        "technical_class": "VALID_VULNERABILITY",
        "programme_scope": "IN_SCOPE",
        "scanner_claim_status": "SUPPORTED",
        "source_reread": True,
        "decisive_sources": [
            {
                "component_id": "firmware",
                "path": source.name,
                "file_sha256": autonomous_campaign.file_hash(source),
            }
        ],
        "proof_tuple": {name: "" for name in analysis_packet.PROOF},
        "five_layer_dedup": {
            "status": "COMPLETE",
            "layers": {name: {} for name in analysis_packet.LAYERS},
        },
        "root_relationship": {
            "kind": "RELATED_VARIANT",
            "root_id": "root-1",
        },
        "creates_root": False,
    }
    packet = {"records": [record], "campaign_write_attempts": 0}
    packet["packet_sha256"] = autonomous_campaign.object_hash(packet)
    errors = autonomous_campaign.validate_analysis_packet(
        packet, {"firmware": str(tmp_path)}
    )
    assert "valid record lacks complete proof tuple: record-1" in errors
    assert "valid record lacks five-layer dedup: record-1" in errors


def test_metis_cli_dispatches_firmware_campaign_before_engine_construction(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    profile = tmp_path / "profile.json"
    profile.write_text("{}", encoding="utf-8")
    captured = {}

    def run(**kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(launcher, "launch", run)
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "--firmware-campaign",
            str(profile),
            "--codebase-path",
            str(source),
            "--resume",
        ],
    )
    entry.main()
    assert captured == {
        "profile_path": profile,
        "codebase_path": source,
        "resume": True,
        "additional_source_paths": [],
    }


def test_metis_cli_rejects_mixed_firmware_and_regular_configuration(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    profile = tmp_path / "profile.json"
    profile.write_text("{}", encoding="utf-8")
    config = tmp_path / "metis.yaml"
    config.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "--firmware-campaign",
            str(profile),
            "--config",
            str(config),
            "--codebase-path",
            str(source),
        ],
    )
    with pytest.raises(SystemExit, match="2"):
        entry.main()


def test_metis_cli_runs_restart_safe_campaign_without_engine_configuration(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    decisive = source / "firmware.c"
    decisive.write_text("int firmware(void) { return 0; }\n", encoding="utf-8")
    tree_hash = autonomous_campaign.object_hash(
        [
            {
                "path": decisive.name,
                "sha256": autonomous_campaign.file_hash(decisive),
            }
        ]
    )
    stages = []
    for phase in sorted(autonomous_campaign.PHASES):
        stage = {
            "stage_id": phase.lower(),
            "phase": phase,
            "depends_on": [],
            "adapter": ["python3", "blocked-adapter.py"],
            "required_outputs": ["blocked.json"],
            "credential_env": ["METIS_FIRMWARE_CAMPAIGN_TEST_MISSING"],
        }
        if phase == "PACKET_VALIDATION":
            stage["worker_adapter"] = ["python3", "blocked-worker.py"]
        stages.append(stage)
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps(
            {
                "schema_version": "5",
                "project": {
                    "project_id": "example-firmware",
                    "components": [
                        {
                            "component_id": "firmware",
                            "repository": "https://example/firmware.git",
                            "revision": "a" * 40,
                            "tree_sha256": tree_hash,
                        }
                    ],
                },
                "automation": {
                    "format_version": autonomous_campaign.FORMAT,
                    "campaign_reader_limit": 11,
                    "provider_worker_configuration_limit": 100,
                    "stages": stages,
                },
                "governance": {
                    "candidate_database_only": True,
                    "production_write_target_configured": False,
                    "production_write_attempts": 0,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("METIS_FIRMWARE_CAMPAIGN_TEST_MISSING", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "--firmware-campaign",
            str(profile),
            "--codebase-path",
            str(source),
            "--resume",
        ],
    )
    entry.main()
    workflow = json.loads((tmp_path / "automation" / "workflow.json").read_text())
    assert set(workflow["statuses"].values()) == {"BLOCKED"}
    assert workflow["campaign_write_attempts"] == 0
