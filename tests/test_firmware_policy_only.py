from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
from unittest.mock import patch

import pytest

from metis_firmware_campaign import autonomous_campaign as campaign


STANDALONE = (
    Path(__file__).resolve().parents[2]
    / "portable-firmware-campaign/.agents/skills/firmware-finding-pipeline/scripts/autonomous_campaign.py"
)
V610_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "portable-firmware-campaign/.agents/skills/firmware-campaign-bootstrap/scripts/test_policy_decision_dimensions_v610.py"
)


def implementations():
    sys.path.insert(0, str(STANDALONE.parent))
    spec = importlib.util.spec_from_file_location("policy_only_standalone", STANDALONE)
    standalone = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(standalone)
    return (("metis", campaign), ("standalone", standalone))


def current_policy_fixture(root: Path, *, lifetime=timedelta(hours=23)):
    spec = importlib.util.spec_from_file_location("current_policy_fixture", V610_FIXTURE)
    fixture = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(fixture)
    reconciler = fixture.load(fixture.SCRIPT, "current_policy_reconciler")
    base = fixture.load(fixture.V68_TEST, "current_policy_candidate")
    candidate = root / "candidate.db"
    base.candidate(candidate, reconciler)
    evidence = fixture.matrix(root, reconciler, candidate, mode="arm", lifetime=lifetime)
    return fixture, reconciler, candidate, evidence


def test_policy_decision_controls_end_to_end() -> None:
    script = (
        Path(__file__).resolve().parents[2]
        / "portable-firmware-campaign/.agents/skills/firmware-campaign-bootstrap/scripts/test_policy_decision_controls_v68.py"
    )
    result = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_unicode_relative_evidence_and_source_kind_verifier_parity(
    tmp_path: Path,
) -> None:
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "portable-firmware-campaign/.agents/skills/firmware-campaign-bootstrap/scripts/test_policy_decision_controls_v68.py"
    )
    spec = importlib.util.spec_from_file_location("policy_parity_fixture", fixture_path)
    fixture = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(fixture)
    reconciler = fixture.load()
    candidate = tmp_path / "candidate.db"
    fixture.candidate(candidate, reconciler)
    source, lease = fixture.evidence(tmp_path)
    evidence = fixture.input_file(tmp_path, reconciler, candidate, source, lease)
    value = json.loads(evidence.read_text())
    value["roots"][0]["evaluations"][0]["rationale"] = "café policy rationale"
    evidence.write_bytes(fixture.canon(value) + b"\n")
    result = fixture.run(candidate, evidence, tmp_path, tmp_path / "out")
    assert result.returncode == 0, result.stderr
    verifier = fixture.VERIFIER
    verified = subprocess.run(
        [
            sys.executable,
            str(verifier),
            str(candidate),
            "--project-directory",
            str(tmp_path),
        ],
        text=True,
        capture_output=True,
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr
    core_path = fixture.SCRIPT.with_name("verify_candidate.py")
    sys.path.insert(0, str(core_path.parent))
    core_spec = importlib.util.spec_from_file_location("core_policy_parity", core_path)
    core = importlib.util.module_from_spec(core_spec)
    assert core_spec.loader
    core_spec.loader.exec_module(core)
    with sqlite3.connect(candidate) as database:
        row = database.execute(
            "SELECT c.source_content_hash,c.source_kind,c.collection_scope,c.retrieved_at,c.expires_at,c.source_evidence_locator,c.freshness_lease_locator,c.freshness_lease_hash "
            "FROM policy_rule_evidence_condition c JOIN policy_rule_evaluation r USING(evaluation_id) WHERE r.authority_class='CURRENT_GENERAL_PROGRAMME'"
        ).fetchone()
    assert core.policy_lease_valid(*row, tmp_path)
    lease_value = json.loads(lease.read_text())
    lease_value["source_kind"] = "CURRENT_TICKETS"
    wrong = tmp_path / "wrong-kind-lease.json"
    wrong.write_bytes(fixture.canon(lease_value) + b"\n")
    assert not core.policy_lease_valid(
        *row[:-2], wrong.name, fixture.sha(wrong), tmp_path
    )
    reporter_path = fixture.REPORT
    reporter_spec = importlib.util.spec_from_file_location(
        "direct_policy_report", reporter_path
    )
    reporter = importlib.util.module_from_spec(reporter_spec)
    assert reporter_spec.loader
    reporter_spec.loader.exec_module(reporter)
    current, errors = reporter.inspect(candidate, tmp_path)
    assert not errors and current["completion_predicates"]["POLICY_EVIDENCE_CURRENT"]
    source.write_text("changed source\n")
    stale, errors = reporter.inspect(candidate, tmp_path)
    assert errors and not stale["completion_predicates"]["POLICY_EVIDENCE_CURRENT"]
    source.write_text("policy\n")
    exporter_path = fixture.SCRIPT.with_name("export_internal_review_packages.py")
    exporter_spec = importlib.util.spec_from_file_location(
        "direct_policy_export", exporter_path
    )
    exporter = importlib.util.module_from_spec(exporter_spec)
    assert exporter_spec.loader
    exporter_spec.loader.exec_module(exporter)
    profile = tmp_path / "v68-profile.json"
    profile.write_text('{"schema_version":"6.8"}\n')
    policy_dir = tmp_path / "out"
    stale_dir = tmp_path / "stale-ledger"
    stale_dir.mkdir()
    shutil.copy2(policy_dir / "POLICY-INDEX.json", stale_dir / "POLICY-INDEX.json")
    ledger = json.loads((policy_dir / "POLICY-TRANSITION-LEDGER.json").read_text())
    ledger["transitions"][-1]["new_decision_hash"] = "0" * 64
    ledger["content_hash"] = exporter.object_hash(
        {key: value for key, value in ledger.items() if key != "content_hash"}
    )
    (stale_dir / "POLICY-TRANSITION-LEDGER.json").write_text(
        json.dumps(ledger, sort_keys=True) + "\n"
    )
    with pytest.raises(RuntimeError, match="ledger head"):
        exporter.export(
            profile,
            candidate,
            tmp_path,
            tmp_path / "exported",
            {},
            None,
            fixture.sha(candidate),
            [],
            [stale_dir],
            [],
        )


def test_core_verifier_forwards_project_to_population_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    core_path = (
        Path(__file__).resolve().parents[2]
        / "portable-firmware-campaign/.agents/skills/firmware-campaign-bootstrap/scripts/verify_candidate.py"
    )
    sys.path.insert(0, str(core_path.parent))
    spec = importlib.util.spec_from_file_location("core_population_context", core_path)
    core = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(core)
    candidate = tmp_path / "candidate.db"
    sqlite3.connect(candidate).close()
    contract = tmp_path / "contract.json"
    _write(contract, {"schema_version": "6", "required_capabilities": {}})
    seen = []

    def observe(candidate_path, project=None):
        seen.append(project)
        return {}, []

    with (
        patch.object(core, "check_semantics"),
        patch.object(core, "check_capability_v6"),
        patch.object(core, "check_population_scoped_reporting", side_effect=observe),
        patch.object(
            sys,
            "argv",
            [
                "verify_candidate.py",
                str(candidate),
                str(contract),
                "--project-directory",
                str(tmp_path),
            ],
        ),
    ):
        assert core.main() == 0
    capsys.readouterr()
    assert seen == [tmp_path.resolve()]


def _write(path: Path, value: object) -> None:
    path.write_bytes(campaign.canonical(value) + b"\n")


def _bundle(root: Path, project_id: str, *, expired: bool = False) -> Path:
    policy = root / "policy.json"
    tickets = root / "tickets.json"
    _write(policy, {"rules": []})
    _write(tickets, {"records": []})
    retrieved = datetime.now(timezone.utc) - timedelta(days=2 if expired else 0)
    expires = retrieved + timedelta(days=1)
    sources = []
    for kind, path, scope in (
        ("PROGRAMME_POLICY", policy, "FULL_PROGRAMME"),
        ("CURRENT_TICKETS", tickets, "TRACKED_COHORT"),
    ):
        sources.append(
            {
                "source_id": "fixture-" + kind.lower(),
                "source_kind": kind,
                "source_locator": "https://fixture.invalid/" + kind.lower(),
                "retrieval_status": "SUCCESS",
                "collection_scope": scope,
                "retrieved_at": retrieved.isoformat(),
                "expires_at": expires.isoformat(),
                "evidence": {"locator": path.name, "sha256": campaign.file_hash(path)},
            }
        )
    bundle = root / "refresh.json"
    _write(
        bundle,
        {
            "format_version": campaign.POLICY_REFRESH_FORMAT,
            "project_id": project_id,
            "sources": sources,
        },
    )
    return bundle


def _receipt(state: Path, stage_id: str) -> dict:
    identity = "identity-" + stage_id
    root = state / "stages" / stage_id / identity
    root.mkdir(parents=True)
    _write(root / "stage.json", {"stage_id": stage_id})
    body = {
        "stage_id": stage_id,
        "stage_identity": identity,
        "status": "COMPLETE",
        "input_sha256": "1" * 64,
        "outputs": [
            {
                "locator": "stage.json",
                "sha256": campaign.file_hash(root / "stage.json"),
                "size": (root / "stage.json").stat().st_size,
            }
        ],
    }
    body["receipt_sha256"] = campaign.object_hash(body)
    _write(root / "receipt.json", body)
    return body


def test_policy_refresh_bundle_rejects_expired_and_changed_source(
    tmp_path: Path,
) -> None:
    good = _bundle(tmp_path, "fixture")
    assert campaign.policy_refresh_bundle(good, "fixture")[
        "sha256"
    ] == campaign.file_hash(good)
    expired = (
        _bundle(tmp_path / "expired", "fixture", expired=True)
        if (tmp_path / "expired").mkdir() is None
        else None
    )
    with pytest.raises(campaign.ContractError, match="freshness window"):
        campaign.policy_refresh_bundle(expired, "fixture")
    policy = tmp_path / "policy.json"
    policy.write_text("changed\n")
    with pytest.raises(campaign.ContractError, match="content changed"):
        campaign.policy_refresh_bundle(good, "fixture")


def test_policy_only_preserves_full_receipts_and_never_dispatches_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_path = tmp_path / "profile.json"
    _write(profile_path, {})
    candidate = tmp_path / "candidate.db"
    sqlite3.connect(candidate).close()
    stages = []
    for stage_id, phase in [
        ("provider", "METIS_FULL_SCAN"),
        ("current", "CURRENT_TICKET_COLLECTION"),
        ("threat", "THREAT_POLICY_COLLECTION"),
        ("policy", "POLICY_RECONCILIATION"),
        ("followup", "EXISTING_REPORT_FOLLOWUP"),
        ("export", "PACKAGE_EXPORT"),
        ("population", "POPULATION_SCOPED_REPORTING"),
        ("seal", "PACKAGE_AND_SEAL"),
    ]:
        stages.append(
            {
                "stage_id": stage_id,
                "phase": phase,
                "depends_on": []
                if stage_id in {"provider", "current", "threat"}
                else (
                    ["provider", "current", "threat"]
                    if stage_id == "policy"
                    else (
                        ["provider", "policy"]
                        if stage_id in {"followup", "export"}
                        else (
                            ["provider", "policy", "export"]
                            if stage_id == "population"
                            else [
                                "provider",
                                "policy",
                                "followup",
                                "export",
                                "population",
                            ]
                        )
                    )
                ),
            }
        )
    next(stage for stage in stages if stage["stage_id"] == "current")[
        "credential_env"
    ] = ["CONNECTOR_SECRET"]
    profile = {
        "schema_version": "6.7",
        "project": {"project_id": "fixture"},
        "automation": {
            "provider_worker_configuration_limit": 1,
            "campaign_reader_limit": 1,
            "provider_execution_mode": "FROZEN_REPLAY",
            "stages": stages,
        },
    }
    identity = {
        "locator": str(profile_path),
        "sha256": campaign.file_hash(profile_path),
    }
    monkeypatch.setattr(campaign, "parse_bindings", lambda *a: {})
    monkeypatch.setattr(campaign, "source_paths", lambda *a: {})
    monkeypatch.setattr(campaign, "verify_profile", lambda *a: (profile, identity))
    state = tmp_path / "state"
    state.mkdir()
    prior = {
        stage["stage_id"]: _receipt(state, stage["stage_id"])["receipt_sha256"]
        for stage in stages
    }
    workflow = {
        "format_version": campaign.FORMAT,
        "profile_sha256": identity["sha256"],
        "candidate": campaign.candidate_state(candidate),
        "stages": prior,
        "statuses": {key: "COMPLETE" for key in prior},
        "human_blockers": [],
        "evidence_blockers": [],
        "campaign_write_attempts": 0,
    }
    workflow["workflow_sha256"] = campaign.object_hash(workflow)
    _write(state / "workflow.json", workflow)
    dispatched = []

    def execute(stage, *args, **kwargs):
        assert (
            stage.get("credential_env") == []
            if stage["phase"] in campaign.POLICY_ONLY_PHASES
            else True
        )
        dispatched.append(stage["phase"])
        return {
            "stage_id": stage["stage_id"],
            "stage_identity": "new-" + stage["stage_id"],
            "status": "COMPLETE",
            "receipt_sha256": "new-" + stage["stage_id"],
            "outputs": [],
        }

    monkeypatch.setattr(campaign, "execute_stage", execute)
    bundle = _bundle(tmp_path, "fixture")
    args = argparse.Namespace(
        candidate=str(candidate),
        ticket_selector=[],
        confluence_selector=[],
        project_profile=profile_path,
        source=[],
        source_path=[],
        credential_env=[],
        state=str(state),
        policy_only=True,
        policy_refresh_bundle=bundle,
    )
    result = campaign.run(args)
    assert not set(dispatched) & campaign.METIS_PROVIDER_PHASES
    assert set(result["stages"]) == set(prior)
    assert result["stages"]["provider"] == prior["provider"]
    assert (
        result["provider_phase_dispatches_permitted"] == 0
        and result["execution_mode"] == "POLICY_ONLY"
    )


def test_policy_only_rejects_explicit_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_path = tmp_path / "profile.json"
    _write(profile_path, {})
    candidate = tmp_path / "candidate.db"
    sqlite3.connect(candidate).close()
    bundle = _bundle(tmp_path, "fixture")
    profile = {
        "schema_version": "6.7",
        "project": {"project_id": "fixture"},
        "automation": {
            "provider_worker_configuration_limit": 1,
            "campaign_reader_limit": 1,
            "stages": [
                {
                    "stage_id": "current",
                    "phase": "CURRENT_TICKET_COLLECTION",
                    "credential_env": ["SECRET"],
                }
            ],
        },
    }
    monkeypatch.setattr(campaign, "parse_bindings", lambda *a: {})
    monkeypatch.setattr(campaign, "source_paths", lambda *a: {})
    monkeypatch.setattr(
        campaign,
        "verify_profile",
        lambda *a: (
            profile,
            {"locator": str(profile_path), "sha256": campaign.file_hash(profile_path)},
        ),
    )
    args = argparse.Namespace(
        candidate=str(candidate),
        ticket_selector=[],
        confluence_selector=[],
        project_profile=profile_path,
        source=[],
        source_path=[],
        credential_env=["SECRET"],
        state=str(tmp_path / "state"),
        policy_only=True,
        policy_refresh_bundle=bundle,
    )
    with pytest.raises(campaign.ContractError, match="cannot receive credentials"):
        campaign.run(args)


def test_cached_scope_expires_in_both_coordinators(tmp_path: Path) -> None:
    for name, implementation in implementations():
        root = tmp_path / name
        root.mkdir()
        fixture, reconciler, candidate, evidence = current_policy_fixture(
            root, lifetime=timedelta(seconds=3)
        )
        state = root / "state"
        dependency_root = state / "stages/collect-threat-policy/dependency"
        dependency_root.mkdir(parents=True)
        copied = dependency_root / "policy-reconciliation-input.json"
        copied.write_bytes(evidence.read_bytes())
        dependency = {
            "stage_id": "collect-threat-policy",
            "stage_identity": "dependency",
            "status": "COMPLETE",
            "receipt_sha256": "d" * 64,
            "outputs": [
                {
                    "locator": copied.name,
                    "sha256": implementation.file_hash(copied),
                    "size": copied.stat().st_size,
                }
            ],
        }
        profile_path = root / "profile.json"
        _write(profile_path, {})
        profile = {
            "schema_version": "6.8",
            "project": {"project_id": "fixture"},
            "automation": {
                "campaign_reader_limit": 1,
                "provider_worker_configuration_limit": 1,
            },
        }
        identity = {
            "locator": str(profile_path),
            "sha256": implementation.file_hash(profile_path),
        }
        stage = {
            "stage_id": "policy-reconciliation",
            "phase": "POLICY_RECONCILIATION",
            "builtin": "POLICY_PRECEDENCE_RECONCILIATION",
            "required_outputs": sorted(
                implementation.V68_OUTPUTS["policy-reconciliation"]
            ),
        }
        first = implementation.execute_stage(
            stage,
            profile,
            identity,
            state,
            candidate,
            {},
            {},
            {},
            {"collect-threat-policy": dependency},
        )
        evidence_value = json.loads(evidence.read_text())
        lease_path = root / evidence_value["source_populations"][0]["source_freshness"]["evidence"]["locator"]
        expires = datetime.fromisoformat(
            json.loads(lease_path.read_text())["expires_at"]
        ).timestamp()
        time.sleep(max(0, expires - time.time() + 0.1))
        with pytest.raises(implementation.ContractError):
            implementation.execute_stage(
                stage,
                profile,
                identity,
                state,
                candidate,
                {},
                {},
                {},
                {"collect-threat-policy": dependency},
            )
        assert not (
            state / "stages/policy-reconciliation" / first["stage_identity"]
        ).exists()
        downstream = {
            "stage_id": "fresh-package",
            "phase": "PACKAGE_EXPORT",
            "builtin": "INTERNAL_TECHNICAL_PACKAGE_EXPORT",
            "required_outputs": [],
        }
        with pytest.raises(
            implementation.ContractError, match="stale or unverified evidence"
        ):
            implementation.execute_stage(
                downstream, profile, identity, state, candidate, {}, {}, {}, {}
            )


def test_actual_capability_fts_and_all_sqlite_types_have_stable_lineage(
    tmp_path: Path,
) -> None:
    schema = (
        Path(__file__).resolve().parents[2]
        / "portable-firmware-campaign/.agents/skills/firmware-campaign-bootstrap/assets/capability-schema-v6.sql"
    )
    for name, implementation in implementations():
        candidate = tmp_path / f"{name}-fts.db"
        with sqlite3.connect(candidate) as database:
            database.executescript(schema.read_text())
            database.execute("CREATE TABLE lineage_types(value)")
            database.executemany(
                "INSERT INTO lineage_types VALUES(?)",
                [(None,), (42,), (1.25,), ("café",), (sqlite3.Binary(b"\x00\xff"),)],
            )
            database.execute(
                "INSERT INTO knowledge_fts VALUES('ROOT','root:1','title','body')"
            )
        first = implementation.technical_candidate_lineage(candidate)
        assert first == implementation.technical_candidate_lineage(candidate)
        profile_path = tmp_path / f"{name}-full-profile.json"
        _write(profile_path, {})
        profile = {
            "schema_version": "6.7",
            "project": {"project_id": "fixture"},
            "automation": {"stages": []},
        }
        args = argparse.Namespace(
            candidate=str(candidate),
            ticket_selector=[],
            confluence_selector=[],
            project_profile=profile_path,
            source=[],
            source_path=[],
            credential_env=[],
            state=str(tmp_path / f"{name}-full-state"),
            policy_only=False,
            policy_refresh_bundle=None,
        )
        with (
            patch.object(implementation, "parse_bindings", return_value={}),
            patch.object(implementation, "source_paths", return_value={}),
            patch.object(
                implementation,
                "verify_profile",
                return_value=(
                    profile,
                    {
                        "locator": str(profile_path),
                        "sha256": implementation.file_hash(profile_path),
                    },
                ),
            ),
        ):
            completed = implementation.run(args)
        assert (
            completed["technical_lineage_version"]
            == implementation.TECHNICAL_LINEAGE_VERSION
        )
        with sqlite3.connect(candidate) as database:
            database.execute("UPDATE knowledge_fts SET body='different'")
        assert first != implementation.technical_candidate_lineage(candidate)


def test_legacy_context_requires_its_original_receipt_commitment(
    tmp_path: Path,
) -> None:
    for name, implementation in implementations():
        root = tmp_path / name
        root.mkdir()
        candidate = root / "candidate.db"
        with sqlite3.connect(candidate) as database:
            database.execute("CREATE TABLE technical(value TEXT)")
            database.execute("INSERT INTO technical VALUES('unchanged')")
        material = root / "graph.json"
        material.write_text('{"graph":"unchanged"}\n')
        profile_path = root / "profile.json"
        _write(profile_path, {})
        profile = {
            "schema_version": "6.7",
            "project": {"project_id": "fixture"},
            "automation": {
                "campaign_reader_limit": 1,
                "provider_worker_configuration_limit": 1,
                "stages": [],
            },
        }
        identity = {
            "locator": str(profile_path),
            "sha256": implementation.file_hash(profile_path),
        }
        stage = {
            "stage_id": "source",
            "phase": "SOURCE_COLLECTION",
            "input_files": [material.name],
            "adapter": [sys.executable, "synthetic-adapter.py"],
            "required_outputs": ["result.json"],
        }
        profile["automation"]["stages"] = [stage]
        state = root / "state"

        def write_stage(command, context, output, credentials):
            implementation.atomic_json(output / "context.json", context)
            implementation.atomic_json(output / "result.json", {"ok": True})

        with patch.object(implementation, "run_command", side_effect=write_stage):
            original = implementation.execute_stage(
                stage, profile, identity, state, candidate, {}, {}, {}, {}
            )
        prior = {
            "candidate": implementation.candidate_state(candidate),
            "workflow_sha256": "legacy-workflow",
        }
        authenticated = implementation.completed_receipt(
            state, "source", original["receipt_sha256"]
        )
        implementation.policy_only_technical_admission(
            profile,
            identity,
            prior,
            state,
            candidate,
            {"source": authenticated},
            implementation.technical_input_lineage(profile, root),
        )
        context = Path(authenticated["_receipt_directory"]) / "context.json"
        value = json.loads(context.read_text())
        value["input_files"][0]["sha256"] = "0" * 64
        implementation.atomic_json(context, value)
        sidecar = state / "policy-only-technical-lineage.json"
        sidecar.unlink()
        with pytest.raises(implementation.ContractError, match="not committed"):
            implementation.policy_only_technical_admission(
                profile,
                identity,
                prior,
                state,
                candidate,
                {"source": authenticated},
                implementation.technical_input_lineage(profile, root),
            )


def test_interrupted_refresh_keeps_prior_receipt_reachable(tmp_path: Path) -> None:
    for name, implementation in implementations():
        root = tmp_path / name
        root.mkdir()
        candidate = root / "candidate.db"
        with sqlite3.connect(candidate) as database:
            database.execute("CREATE TABLE technical(value TEXT)")
        profile_path = root / "profile.json"
        _write(profile_path, {})
        profile = {
            "schema_version": "6.7",
            "project": {"project_id": "fixture"},
            "automation": {
                "campaign_reader_limit": 1,
                "provider_worker_configuration_limit": 1,
            },
        }
        identity = {
            "locator": str(profile_path),
            "sha256": implementation.file_hash(profile_path),
        }
        stage = {
            "stage_id": "current",
            "phase": "CURRENT_TICKET_COLLECTION",
            "adapter": [sys.executable, "synthetic-adapter.py"],
            "required_outputs": ["result.json"],
            "refresh_on_resume": True,
        }

        def write_stage(command, context, output, credentials):
            implementation.atomic_json(output / "context.json", context)
            implementation.atomic_json(output / "result.json", {"ok": True})

        state = root / "state"
        with patch.object(implementation, "run_command", side_effect=write_stage):
            first = implementation.execute_stage(
                stage, profile, identity, state, candidate, {}, {}, {}, {}
            )
        with patch.object(
            implementation, "run_command", side_effect=RuntimeError("interrupted")
        ):
            with pytest.raises(RuntimeError, match="interrupted"):
                implementation.execute_stage(
                    stage, profile, identity, state, candidate, {}, {}, {}, {}
                )
        recovered = implementation.completed_receipt(
            state, "current", first["receipt_sha256"]
        )
        assert "historical-stages" in recovered["_receipt_directory"]
        profile["automation"]["stages"] = [stage]
        workflow = {
            "format_version": implementation.FORMAT,
            "profile_sha256": identity["sha256"],
            "candidate": implementation.candidate_state(candidate),
            "stages": {"current": first["receipt_sha256"]},
        }
        workflow["workflow_sha256"] = implementation.object_hash(workflow)
        implementation.atomic_json(state / "workflow.json", workflow)
        arguments = argparse.Namespace(
            candidate=str(candidate),
            ticket_selector=[],
            confluence_selector=[],
            project_profile=profile_path,
            source=[],
            source_path=[],
            credential_env=[],
            state=str(state),
            policy_only=True,
            policy_refresh_bundle=_bundle(root, "fixture"),
        )
        with (
            patch.object(implementation, "parse_bindings", return_value={}),
            patch.object(implementation, "source_paths", return_value={}),
            patch.object(
                implementation, "verify_profile", return_value=(profile, identity)
            ),
            patch.object(implementation, "run_command", side_effect=write_stage),
        ):
            resumed = implementation.run(arguments)
        assert resumed["statuses"]["current"] == "COMPLETE"


def test_equivalent_retired_receipts_use_committed_stage_inputs(tmp_path: Path) -> None:
    for name, implementation in implementations():
        state = tmp_path / name
        payload = b"{}\n"
        output_sha = hashlib.sha256(payload).hexdigest()
        committed = {
            "format_version": implementation.FORMAT,
            "project_id": "fixture",
            "profile_sha256": "1" * 64,
            "stage_id": "source",
            "phase": "SOURCE_COLLECTION",
            "adapter_sha256": "2" * 64,
            "source_bindings": {},
            "source_checkouts": {},
            "selectors": {},
            "input_files": [],
            "dependencies": {},
        }
        identity = implementation.object_hash(committed)
        receipt = {
            "stage_id": "source",
            "phase": "SOURCE_COLLECTION",
            "stage_identity": identity,
            "status": "COMPLETE",
            "input_sha256": identity,
            "outputs": [{"locator": "result.json", "sha256": output_sha, "size": 3}],
            "campaign_write_attempts": 0,
        }
        receipt["receipt_sha256"] = implementation.object_hash(receipt)
        directories = []
        for reason in ("refresh", "policy-evidence-refresh"):
            directory = (
                state
                / "historical-stages/source"
                / identity
                / f"{receipt['receipt_sha256']}-{reason}"
            )
            directory.mkdir(parents=True)
            implementation.atomic_json(directory / "receipt.json", receipt)
            implementation.atomic_json(
                directory / "context.json",
                {**committed, "output_directory": f"/temporary/{reason}"},
            )
            (directory / "result.json").write_bytes(payload)
            directories.append(directory)
        recovered = implementation.completed_receipt(
            state, "source", receipt["receipt_sha256"]
        )
        assert Path(recovered["_receipt_directory"]) == min(directories)
        implementation.atomic_json(
            directories[1] / "context.json",
            {
                **committed,
                "project_id": "conflicting",
                "output_directory": "/temporary/policy-evidence-refresh",
            },
        )
        with pytest.raises(
            implementation.ContractError, match="does not reproduce input commitment"
        ):
            implementation.completed_receipt(state, "source", receipt["receipt_sha256"])


def test_policy_only_binds_technical_lineage_without_database_byte_equality(
    tmp_path: Path,
) -> None:
    for name, implementation in implementations():
        root = tmp_path / name
        root.mkdir()
        candidate = root / "candidate.db"
        with sqlite3.connect(candidate) as database:
            database.executescript(
                "CREATE TABLE root(root_id TEXT,current_decision TEXT,source_hash TEXT);CREATE TABLE campaign_subject(record_id TEXT,technical_class TEXT,programme_scope TEXT,decision_status TEXT);CREATE TABLE evidence_ref(evidence_id TEXT,content_hash TEXT);INSERT INTO root VALUES('r','VALID_VULNERABILITY','1');INSERT INTO campaign_subject VALUES('x','VALID_VULNERABILITY','UNRESOLVED','TERMINAL');INSERT INTO evidence_ref VALUES('e','1');"
            )
        graph = root / "graph.json"
        _write(graph, {"graph": "original"})
        profile_path = root / "profile.json"
        _write(profile_path, {})
        stages = [
            {
                "stage_id": "provider",
                "phase": "METIS_FULL_SCAN",
                "depends_on": [],
                "input_files": [graph.name],
            },
            {
                "stage_id": "policy",
                "phase": "POLICY_RECONCILIATION",
                "depends_on": ["provider"],
            },
        ]
        profile = {
            "schema_version": "6.8",
            "project": {"project_id": "fixture"},
            "automation": {"stages": stages},
        }
        identity = {
            "locator": str(profile_path),
            "sha256": implementation.file_hash(profile_path),
        }

        def prepare(state: Path):
            prior = {}
            for stage in stages:
                prior[stage["stage_id"]] = _receipt(state, stage["stage_id"])[
                    "receipt_sha256"
                ]
            workflow = {
                "format_version": implementation.FORMAT,
                "profile_sha256": identity["sha256"],
                "candidate": implementation.candidate_state(candidate),
                "stages": prior,
                "technical_candidate_lineage_sha256": implementation.technical_candidate_lineage(
                    candidate
                ),
                "technical_input_lineage_sha256": implementation.technical_input_lineage(
                    profile, root
                ),
                "technical_lineage_version": implementation.TECHNICAL_LINEAGE_VERSION,
            }
            workflow["workflow_sha256"] = implementation.object_hash(workflow)
            implementation.atomic_json(state / "workflow.json", workflow)

        def args(state):
            return argparse.Namespace(
                candidate=str(candidate),
                ticket_selector=[],
                confluence_selector=[],
                project_profile=profile_path,
                source=[],
                source_path=[],
                credential_env=[],
                state=str(state),
                policy_only=True,
                policy_refresh_bundle=_bundle(root, "fixture"),
            )

        common = (
            patch.object(implementation, "parse_bindings", return_value={}),
            patch.object(implementation, "source_paths", return_value={}),
            patch.object(
                implementation, "verify_profile", return_value=(profile, identity)
            ),
            patch.object(
                implementation,
                "execute_stage",
                side_effect=lambda stage, *a, **kw: {
                    "stage_id": stage["stage_id"],
                    "stage_identity": "new-" + stage["stage_id"],
                    "status": "COMPLETE",
                    "receipt_sha256": "new-" + stage["stage_id"],
                    "outputs": [],
                },
            ),
        )
        state = root / "policy-change"
        state.mkdir()
        prepare(state)
        with sqlite3.connect(candidate) as database:
            database.execute("UPDATE campaign_subject SET programme_scope='IN_SCOPE'")
            database.commit()
        with common[0], common[1], common[2], common[3]:
            implementation.run(args(state))
        state = root / "graph-change"
        state.mkdir()
        prepare(state)
        graph.write_text('{"graph":"changed"}\n')
        with pytest.raises(
            implementation.ContractError, match="technical input lineage changed"
        ):
            with (
                patch.object(implementation, "parse_bindings", return_value={}),
                patch.object(implementation, "source_paths", return_value={}),
                patch.object(
                    implementation, "verify_profile", return_value=(profile, identity)
                ),
            ):
                implementation.run(args(state))
        graph.write_text('{"graph":"original"}\n')
        state = root / "technical-evidence-change"
        state.mkdir()
        prepare(state)
        with sqlite3.connect(candidate) as database:
            database.execute("UPDATE evidence_ref SET content_hash='2'")
            database.commit()
        with pytest.raises(
            implementation.ContractError, match="candidate technical lineage changed"
        ):
            with (
                patch.object(implementation, "parse_bindings", return_value={}),
                patch.object(implementation, "source_paths", return_value={}),
                patch.object(
                    implementation, "verify_profile", return_value=(profile, identity)
                ),
            ):
                implementation.run(args(state))
        state = root / "technical-change"
        state.mkdir()
        prepare(state)
        with sqlite3.connect(candidate) as database:
            database.execute("UPDATE root SET source_hash='2'")
            database.commit()
        with pytest.raises(
            implementation.ContractError, match="candidate technical lineage changed"
        ):
            with (
                patch.object(implementation, "parse_bindings", return_value={}),
                patch.object(implementation, "source_paths", return_value={}),
                patch.object(
                    implementation, "verify_profile", return_value=(profile, identity)
                ),
            ):
                implementation.run(args(state))


def test_policy_builtins_receive_no_ambient_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook = tmp_path / "hook"
    hook.mkdir()
    (hook / "sitecustomize.py").write_text(
        "import os\nprint('AMBIENT_SECRET='+str(bool(os.environ.get(\"PIPELINE_SECRET\"))))\n"
    )
    monkeypatch.setenv("PIPELINE_SECRET", "synthetic")
    monkeypatch.setenv("PYTHONPATH", str(hook))
    for name, implementation in implementations():
        root = tmp_path / name
        root.mkdir()
        fixture, reconciler, candidate, evidence = current_policy_fixture(root)
        named = root / "policy-reconciliation-input.json"
        named.write_bytes(evidence.read_bytes())
        work = root / "output"
        work.mkdir()
        profile = root / "profile.json"
        _write(profile, {})
        context = {
            "profile_schema_version": "6.8",
            "candidate_path": str(candidate),
            "project_directory": str(root),
            "dependency_outputs": {"collection": [{"locator": str(named)}]},
            "profile_locator": str(profile),
            "reader_limit": 1,
            "provider_checkpoint_root": str(root / "checkpoints"),
        }
        implementation.run_policy_reconciliation(context, work)
        logs = (work / "stdout.log").read_text() + (
            work / "independent-verifier.json"
        ).read_text()
        assert "AMBIENT_SECRET=True" not in logs


def test_policy_preflight_children_receive_minimal_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_name = "POLICY_REVIEW_SYNTHETIC_SECRET"
    monkeypatch.setenv(secret_name, "synthetic-only")
    template = (
        Path(__file__).resolve().parents[2]
        / "portable-firmware-campaign/.agents/skills/firmware-campaign-bootstrap/assets/project-profile.example.json"
    )
    for name, implementation in implementations():
        root = tmp_path / name
        root.mkdir()
        candidate = root / "candidate.db"
        with sqlite3.connect(candidate) as database:
            database.execute("CREATE TABLE technical(value TEXT)")
        profile = json.loads(template.read_text())
        for component in profile["project"]["components"]:
            component["source_checkout_required"] = False
        profile_path = root / "profile.json"
        implementation.atomic_json(profile_path, profile)
        calls = []

        def discovery(command, **kwargs):
            calls.append(kwargs.get("env"))
            return json.dumps({"contract_version": "6.8.0", "skills": []})

        with patch.object(
            implementation.subprocess, "check_output", side_effect=discovery
        ):
            implementation.verify_profile(profile_path, candidate, {}, {})
        assert calls and all(
            environment is not None and secret_name not in environment
            for environment in calls
        )
        checkout = root / "checkout"
        checkout.mkdir()
        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        (checkout / "source.c").write_text("int value;\n")
        subprocess.run(["git", "-C", str(checkout), "add", "source.c"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(checkout),
                "-c",
                "user.name=Runtime Test",
                "-c",
                "user.email=runtime@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
            check=True,
        )
        calls.clear()
        original_check_output = subprocess.check_output
        original_run = subprocess.run

        def checked_output(command, **kwargs):
            calls.append(kwargs.get("env"))
            return original_check_output(command, **kwargs)

        def checked_run(command, **kwargs):
            calls.append(kwargs.get("env"))
            return original_run(command, **kwargs)

        with (
            patch.object(
                implementation.subprocess, "check_output", side_effect=checked_output
            ),
            patch.object(implementation.subprocess, "run", side_effect=checked_run),
        ):
            implementation.checkout_state(checkout)
        assert len(calls) >= 3 and all(
            environment is not None and secret_name not in environment
            for environment in calls
        )


def test_policy_only_interruption_preserves_queued_review(tmp_path: Path) -> None:
    for name, implementation in implementations():
        root = tmp_path / name
        root.mkdir()
        fixture, reconciler, candidate, evidence = current_policy_fixture(root)
        request_file = root / "review.txt"
        request_file.write_text("review remains required\n")
        request = {
            "trigger_kind": "NEW_COUNTEREVIDENCE",
            "affected_axes": ["TECHNICAL_APPLICABILITY"],
            "rationale": "review changed evidence",
            "evidence": {
                "locator": request_file.name,
                "sha256": fixture.sha(request_file),
            },
        }
        evidence_value = json.loads(evidence.read_text())
        evidence_value["roots"][0]["technical_reopen_requests"] = [request]
        evidence.write_bytes(fixture.canonical(evidence_value) + b"\n")
        profile_path = root / "profile.json"
        _write(profile_path, {})
        stages = [
            {"stage_id": "source", "phase": "SOURCE_COLLECTION", "depends_on": []},
            {
                "stage_id": "policy",
                "phase": "POLICY_RECONCILIATION",
                "depends_on": ["source"],
                "builtin": "POLICY_PRECEDENCE_RECONCILIATION",
                "required_outputs": sorted(
                    implementation.V68_OUTPUTS["policy-reconciliation"]
                ),
            },
            {
                "stage_id": "report",
                "phase": "POPULATION_SCOPED_REPORTING",
                "depends_on": ["policy"],
            },
        ]
        profile = {
            "schema_version": "6.8",
            "project": {"project_id": "fixture"},
            "automation": {
                "campaign_reader_limit": 1,
                "provider_worker_configuration_limit": 1,
                "stages": stages,
            },
        }
        identity = {
            "locator": str(profile_path),
            "sha256": implementation.file_hash(profile_path),
        }
        state = root / "state"
        prior = {}
        for stage in stages:
            prior[stage["stage_id"]] = _receipt(state, stage["stage_id"])[
                "receipt_sha256"
            ]
        folder = next((state / "stages/source").iterdir())
        named = folder / "policy-reconciliation-input.json"
        named.write_bytes(evidence.read_bytes())
        receipt = json.loads((folder / "receipt.json").read_text())
        receipt.pop("receipt_sha256")
        receipt["outputs"].append(
            {
                "locator": named.name,
                "sha256": implementation.file_hash(named),
                "size": named.stat().st_size,
            }
        )
        receipt["receipt_sha256"] = implementation.object_hash(receipt)
        implementation.atomic_json(folder / "receipt.json", receipt)
        prior["source"] = receipt["receipt_sha256"]
        workflow = {
            "format_version": implementation.FORMAT,
            "profile_sha256": identity["sha256"],
            "candidate": implementation.candidate_state(candidate),
            "stages": prior,
        }
        workflow["workflow_sha256"] = implementation.object_hash(workflow)
        implementation.atomic_json(state / "workflow.json", workflow)
        bundle = _bundle(root, "fixture")
        args = argparse.Namespace(
            candidate=str(candidate),
            ticket_selector=[],
            confluence_selector=[],
            project_profile=profile_path,
            source=[],
            source_path=[],
            credential_env=[],
            state=str(state),
            policy_only=True,
            policy_refresh_bundle=bundle,
        )
        real_execute = implementation.execute_stage

        def interrupted(stage, *values, **kwargs):
            if stage["phase"] == "POPULATION_SCOPED_REPORTING":
                raise RuntimeError("synthetic interruption after policy commit")
            return real_execute(stage, *values, **kwargs)

        with (
            patch.object(implementation, "parse_bindings", return_value={}),
            patch.object(implementation, "source_paths", return_value={}),
            patch.object(
                implementation, "verify_profile", return_value=(profile, identity)
            ),
            patch.object(implementation, "execute_stage", side_effect=interrupted),
        ):
            with pytest.raises(RuntimeError, match="synthetic interruption"):
                implementation.run(args)
        with sqlite3.connect(candidate) as database:
            assert database.execute(
                "SELECT status FROM policy_technical_reopen_queue"
            ).fetchone() == ("QUEUED",)
        with (
            patch.object(implementation, "parse_bindings", return_value={}),
            patch.object(implementation, "source_paths", return_value={}),
            patch.object(
                implementation, "verify_profile", return_value=(profile, identity)
            ),
            patch.object(
                implementation,
                "execute_stage",
                side_effect=lambda stage, *values, **kwargs: (
                    real_execute(stage, *values, **kwargs)
                    if stage["phase"] == "POLICY_RECONCILIATION"
                    else {
                        "stage_id": stage["stage_id"],
                        "stage_identity": "resumed-report",
                        "status": "COMPLETE",
                        "receipt_sha256": "resumed-report",
                        "outputs": [],
                    }
                ),
            ),
        ):
            implementation.run(args)
        with sqlite3.connect(candidate) as database:
            assert database.execute(
                "SELECT status FROM policy_technical_reopen_queue"
            ).fetchone() == ("QUEUED",)
