from __future__ import annotations

import json
import importlib.util
import argparse
import fcntl
from pathlib import Path
import shutil
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from metis_firmware_campaign import autonomous_campaign as campaign
from metis_firmware_campaign import technical_state_correction as correction


STANDALONE = (
    Path(__file__).resolve().parents[2]
    / "portable-firmware-campaign/.agents/skills/firmware-finding-pipeline/scripts/autonomous_campaign.py"
)


def implementations():
    sys.path.insert(0, str(STANDALONE.parent))
    spec = importlib.util.spec_from_file_location(
        "technical_correction_standalone", STANDALONE
    )
    standalone = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(standalone)
    return (("metis", campaign), ("standalone", standalone))


def write_record(path: Path, value: dict, identity: str = "content_hash") -> None:
    value = dict(value)
    value[identity] = correction.object_hash(value)
    correction.atomic_json(path, value)


def queue_row(root: str, evidence: Path, index: int) -> dict:
    body = {
        "root_id": root,
        "trigger_kind": "EXACT_DUPLICATE_OR_VARIANT",
        "evidence_locator": str(evidence),
        "evidence_hash": correction.file_hash(evidence),
        "affected_axes_json": '["DEDUPLICATION"]',
        "rationale": f"existing request {index}",
        "status": "QUEUED",
        "resolution_evidence_locator": None,
        "resolution_evidence_hash": None,
        "resolution_rationale": None,
        "resolution_content_hash": None,
    }
    digest = correction.object_hash(body)
    return {"queue_id": f"v68:reopen:{digest[:24]}", **body, "content_hash": digest}


def stage_receipt(state: Path) -> dict:
    stage_id = "provider"
    identity = "2" * 64
    directory = state / "stages" / stage_id / identity
    directory.mkdir(parents=True)
    output = directory / "provider-output.json"
    output.write_text("{}\n")
    context = {
        "format_version": campaign.FORMAT,
        "project_id": "fixture",
        "profile_sha256": "1" * 64,
        "stage_id": stage_id,
        "phase": "METIS_FULL_SCAN",
        "adapter_sha256": "3" * 64,
        "source_bindings": {},
        "source_checkouts": {},
        "selectors": {},
        "input_files": [],
        "dependencies": {},
    }
    identity = campaign.object_hash(context)
    final = state / "stages" / stage_id / identity
    directory.rename(final)
    campaign.atomic_json(final / "context.json", context)
    body = {
        "stage_id": stage_id,
        "phase": "METIS_FULL_SCAN",
        "stage_identity": identity,
        "status": "COMPLETE",
        "input_sha256": identity,
        "outputs": [
            {
                "locator": output.name,
                "sha256": campaign.file_hash(final / output.name),
                "size": 3,
            }
        ],
        "candidate_before": {"exists": False},
        "candidate_after": {"exists": False},
    }
    write_record(final / "receipt.json", body, "receipt_sha256")
    return campaign.completed_receipt(state, stage_id, campaign.object_hash(body))


def policy_queue_receipt(state: Path, requests: list[dict]) -> dict:
    stage_id = "policy"
    identity = correction.object_hash(
        {"stage_id": stage_id, "requests": [row["queue_id"] for row in requests]}
    )
    directory = state / "stages" / stage_id / identity
    directory.mkdir(parents=True)
    output = directory / "TECHNICAL-REOPEN-QUEUE.json"
    write_record(
        output,
        {
            "format_version": correction.QUEUE_INDEX_FORMAT,
            "requests": requests,
        },
    )
    body = {
        "stage_id": stage_id,
        "phase": "POLICY_RECONCILIATION",
        "stage_identity": identity,
        "status": "COMPLETE",
        "input_sha256": identity,
        "outputs": [
            {
                "locator": output.name,
                "sha256": campaign.file_hash(output),
                "size": output.stat().st_size,
            }
        ],
        "candidate_before": {"exists": False},
        "candidate_after": {"exists": False},
    }
    write_record(directory / "receipt.json", body, "receipt_sha256")
    return {**body, "_receipt_directory": str(directory)}


def fixture(root: Path) -> dict:
    root.mkdir()
    candidate = root / "candidate.db"
    evidence = {}
    for purpose in correction.REQUIRED_BLOCKERS:
        path = root / f"{purpose.lower()}-blocker.json"
        path.write_text(json.dumps({"test_only": purpose}) + "\n")
        evidence[purpose] = path
    old = root / "existing.json"
    old.write_text("existing\n")
    with sqlite3.connect(candidate) as db:
        db.executescript(
            "CREATE TABLE validation_run(validation_run_id TEXT PRIMARY KEY,project_id TEXT,authorization_status TEXT,reproduction_level TEXT,rca_workflow_status TEXT,authorization_workflow_status TEXT,reproduction_workflow_status TEXT,workflow_blocker TEXT);"
            "CREATE TABLE validation_run_root(validation_run_id TEXT,root_id TEXT);"
            "CREATE TABLE policy_technical_reopen_queue(queue_id TEXT PRIMARY KEY,root_id TEXT,trigger_kind TEXT,evidence_locator TEXT,evidence_hash TEXT,affected_axes_json TEXT,rationale TEXT,status TEXT,resolution_evidence_locator TEXT,resolution_evidence_hash TEXT,resolution_rationale TEXT,resolution_content_hash TEXT,content_hash TEXT);"
            "CREATE TABLE campaign_subject(record_id TEXT,technical_class TEXT,programme_scope TEXT,reproduction_level TEXT);"
            "CREATE TABLE programme_scope_separation(assessment_id TEXT,root_id TEXT,programme_scope TEXT,owner_eligibility TEXT,submission_ready INTEGER);"
            "INSERT INTO validation_run VALUES('validation:TFM-ROOT-H43PTPSY','fixture','NOT_REQUESTED','NOT_REPRODUCED','NOT_APPLICABLE','NOT_APPLICABLE','NOT_APPLICABLE',NULL);"
            "INSERT INTO validation_run_root VALUES('validation:TFM-ROOT-H43PTPSY','TFM-ROOT-H43PTPSY');"
            "INSERT INTO campaign_subject VALUES('record','VALID_VULNERABILITY','IN_SCOPE','NOT_REPRODUCED');"
            "INSERT INTO programme_scope_separation VALUES('scope','TFM-ROOT-H43PTPSY','IN_SCOPE','UNRESOLVED',0);"
        )
        columns = [
            item[1]
            for item in db.execute("PRAGMA table_info(policy_technical_reopen_queue)")
        ]
        for index in range(8):
            row = queue_row(f"other-{index}", old, index)
            db.execute(
                f"INSERT INTO policy_technical_reopen_queue VALUES({','.join('?' for _ in columns)})",
                tuple(row[name] for name in columns),
            )
    profile_path = root / "profile.json"
    write_record(
        profile_path,
        {
            "schema_version": "6.8",
            "project": {"project_id": "fixture"},
            "automation": {"stages": []},
        },
    )
    profile = {
        "schema_version": "6.8",
        "project": {"project_id": "fixture"},
        "automation": {
            "stages": [{"stage_id": "provider", "phase": "METIS_FULL_SCAN"}]
        },
    }
    identity = {
        "locator": str(profile_path),
        "sha256": campaign.file_hash(profile_path),
    }
    state = root / "state"
    receipt = stage_receipt(state)
    profile["automation"]["stages"][0]["input_files"] = []
    workflow = {
        "format_version": campaign.FORMAT,
        "project_id": "fixture",
        "profile_sha256": identity["sha256"],
        "candidate": campaign.candidate_state(candidate),
        "stages": {"provider": receipt["receipt_sha256"]},
        "statuses": {"provider": "COMPLETE"},
        "technical_candidate_lineage_sha256": campaign.technical_candidate_lineage(
            candidate
        ),
        "technical_input_lineage_sha256": campaign.technical_input_lineage(
            profile, root
        ),
        "technical_lineage_version": campaign.TECHNICAL_LINEAGE_VERSION,
        "execution_mode": "POLICY_ONLY",
        "provider_phase_dispatches_permitted": 0,
    }
    write_record(state / "workflow.json", workflow, "workflow_sha256")
    prior = json.loads((state / "workflow.json").read_text())
    prior["_locator"] = str(state / "workflow.json")
    budget = state / "provider-budget.json"
    budget.write_text(
        json.dumps({"requests_started": 4092, "requests_completed": 4069, "errors": 23})
        + "\n"
    )
    receipt_path = Path(receipt["_receipt_directory"]) / "receipt.json"
    context_path = Path(receipt["_receipt_directory"]) / "context.json"
    output_path = Path(receipt["_receipt_directory"]) / "provider-output.json"
    entries = [
        {
            "kind": "PROVIDER_BUDGET",
            "locator": str(budget),
            "sha256": campaign.file_hash(budget),
            "size": budget.stat().st_size,
        },
        {
            "kind": "PROVIDER_RECEIPT",
            "locator": str(receipt_path),
            "sha256": campaign.file_hash(receipt_path),
            "size": receipt_path.stat().st_size,
        },
        {
            "kind": "PROVIDER_CONTEXT",
            "locator": str(context_path),
            "sha256": campaign.file_hash(context_path),
            "size": context_path.stat().st_size,
        },
        {
            "kind": "PROVIDER_OUTPUT",
            "locator": str(output_path),
            "sha256": campaign.file_hash(output_path),
            "size": output_path.stat().st_size,
        },
    ]
    inventory_projection = {"roots": [str(receipt_path.parent)], "entries": entries}
    inventory = {
        "format_version": correction.INVENTORY_FORMAT,
        "project_id": "fixture",
        "roots": inventory_projection["roots"],
        "entries": entries,
        "counters": {
            "requests_started": 4092,
            "requests_completed": 4069,
            "errors": 23,
        },
        "inventory_sha256": correction.object_hash(inventory_projection),
        "entries_sha256": correction.object_hash(inventory_projection),
    }
    inventory_path = root / "provider-inventory.json"
    write_record(inventory_path, inventory)
    before_columns, before_row = correction._row(
        sqlite3.connect(candidate),
        "validation_run",
        "validation_run_id",
        "validation:TFM-ROOT-H43PTPSY",
    )
    blocker = json.dumps(
        {
            purpose: {"locator": str(path), "sha256": campaign.file_hash(path)}
            for purpose, path in evidence.items()
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    after_row = {
        **before_row,
        "rca_workflow_status": "BLOCKED",
        "authorization_workflow_status": "BLOCKED",
        "reproduction_workflow_status": "BLOCKED",
        "workflow_blocker": blocker,
    }
    queue_body = {
        "root_id": "TFM-ROOT-H43PTPSY",
        "trigger_kind": "EXACT_DUPLICATE_OR_VARIANT",
        "evidence_locator": str(evidence["RCA"]),
        "evidence_hash": campaign.file_hash(evidence["RCA"]),
        "affected_axes_json": '["DEDUPLICATION","REPRODUCTION"]',
        "rationale": "test-only unresolved RCA and reproduction review",
        "status": "QUEUED",
        "resolution_evidence_locator": None,
        "resolution_evidence_hash": None,
        "resolution_rationale": None,
        "resolution_content_hash": None,
    }
    queue_hash = correction.object_hash(queue_body)
    queue = {
        "queue_id": f"v68:reopen:{queue_hash[:24]}",
        **queue_body,
        "content_hash": queue_hash,
    }
    staged = root / "expected.db"
    shutil.copy2(candidate, staged)
    correction._apply_database(
        staged,
        {
            "target": {
                "root_id": "TFM-ROOT-H43PTPSY",
                "validation_run_id": "validation:TFM-ROOT-H43PTPSY",
            },
            "validation_run_after": after_row,
            "queue_addition": queue,
            "base": {"unresolved_queue_count": 8},
        },
        before_columns,
        list(queue),
    )
    correction_body = {
        "format_version": correction.CORRECTION_FORMAT,
        "control_revision": correction.CONTROL_REVISION,
        "project_id": "fixture",
        "base": {
            "candidate": campaign.candidate_state(candidate),
            "workflow_sha256": prior["workflow_sha256"],
            "workflow_file_sha256": campaign.file_hash(state / "workflow.json"),
            "profile_sha256": identity["sha256"],
            "technical_candidate_lineage_sha256": campaign.technical_candidate_lineage(
                candidate
            ),
            "technical_input_lineage_sha256": workflow[
                "technical_input_lineage_sha256"
            ],
            "provider_inventory_sha256": inventory["inventory_sha256"],
            "provider_counters": inventory["counters"],
            "unresolved_queue_count": 8,
        },
        "target": {
            "root_id": "TFM-ROOT-H43PTPSY",
            "validation_run_id": "validation:TFM-ROOT-H43PTPSY",
        },
        "validation_run_before": before_row,
        "validation_run_after": after_row,
        "queue_addition": queue,
        "evidence": [
            {
                "purpose": purpose,
                "locator": str(path),
                "sha256": campaign.file_hash(path),
                "size": path.stat().st_size,
            }
            for purpose, path in evidence.items()
        ],
        "provider_inventory": {
            "locator": str(inventory_path),
            "sha256": campaign.file_hash(inventory_path),
            "size": inventory_path.stat().st_size,
        },
        "provider_invariants_after": {
            "inventory_sha256": inventory["inventory_sha256"],
            "counters": inventory["counters"],
        },
        "technical_candidate_lineage_after": campaign.technical_candidate_lineage(
            staged
        ),
    }
    correction_path = root / "correction.json"
    write_record(correction_path, correction_body)
    decision = root / "human-approval.txt"
    decision.write_text("TEST-ONLY approval of the exact fixture correction\n")
    approval_path = root / "approval.json"
    write_record(
        approval_path,
        {
            "format_version": correction.APPROVAL_FORMAT,
            "control_revision": correction.CONTROL_REVISION,
            "project_id": "fixture",
            "decision": "APPROVE_EXACT_TECHNICAL_STATE_CORRECTION",
            "correction_content_hash": json.loads(correction_path.read_text())[
                "content_hash"
            ],
            "authorized_by": "TEST FIXTURE HUMAN",
            "authority": "TEST ONLY",
            "approval_id": "fixture-approval",
            "authorization_record": {
                "locator": str(decision),
                "sha256": campaign.file_hash(decision),
                "size": decision.stat().st_size,
            },
        },
    )
    return locals()


def invoke(data: dict, implementation=campaign) -> dict:
    module = implementation.technical_state_correction
    return module.apply_with_lock(
        correction_path=data["correction_path"],
        approval_path=data["approval_path"],
        project_id="fixture",
        project=data["root"],
        state=data["state"],
        candidate=data["candidate"],
        profile=data["profile"],
        profile_identity=data["identity"],
        prior_workflow=data["prior"],
        receipts={"provider": data["receipt"]},
        current_technical_inputs=data["workflow"]["technical_input_lineage_sha256"],
        technical_lineage=implementation.technical_candidate_lineage,
        candidate_state=implementation.candidate_state,
    )


def test_explicit_technical_state_correction_and_policy_admission(
    tmp_path: Path,
) -> None:
    for name, implementation in implementations():
        data = fixture(tmp_path / name)
        before_receipt = (
            Path(data["receipt"]["_receipt_directory"]) / "receipt.json"
        ).read_bytes()
        result = invoke(data, implementation)
        assert result["result"] == "TECHNICAL_STATE_CORRECTION_COMPLETED"
        assert invoke(data, implementation)["result"] == "REUSED"
        assert (
            before_receipt
            == (
                Path(data["receipt"]["_receipt_directory"]) / "receipt.json"
            ).read_bytes()
        )
        workflow = json.loads((data["state"] / "workflow.json").read_text())
        workflow["_locator"] = str(data["state"] / "workflow.json")
        with patch.object(implementation, "policy_state_is_current", return_value=True):
            assert (
                implementation.policy_only_technical_admission(
                    data["profile"],
                    data["identity"],
                    workflow,
                    data["state"],
                    data["candidate"],
                    {"provider": data["receipt"]},
                    data["workflow"]["technical_input_lineage_sha256"],
                )
                == data["correction_body"]["technical_candidate_lineage_after"]
            )
        with sqlite3.connect(data["candidate"]) as db:
            assert (
                db.execute(
                    "SELECT count(*) FROM policy_technical_reopen_queue WHERE status='QUEUED'"
                ).fetchone()[0]
                == 9
            )


def test_interrupted_correction_recovers_exact_prepared_successor(
    tmp_path: Path,
) -> None:
    for name, implementation in implementations():
        data = fixture(tmp_path / name)
        module = implementation.technical_state_correction
        original = module.os.replace
        fired = False

        def interrupt(source, destination):
            nonlocal fired
            original(source, destination)
            if (
                not fired
                and Path(destination) == data["candidate"]
                and Path(source).name == "candidate-stage.db"
            ):
                fired = True
                raise RuntimeError("test-only interruption")

        with (
            patch.object(module.os, "replace", side_effect=interrupt),
            pytest.raises(RuntimeError),
        ):
            invoke(data, implementation)
        recovered = module.recover(
            data["state"],
            data["candidate"],
            data["identity"],
            implementation.candidate_state,
            implementation.restore_candidate,
            implementation.technical_candidate_lineage,
        )
        assert recovered[0]["result"] == "TECHNICAL_STATE_CORRECTION_COMPLETED"
        assert (
            module.recover(
                data["state"],
                data["candidate"],
                data["identity"],
                implementation.candidate_state,
                implementation.restore_candidate,
                implementation.technical_candidate_lineage,
            )
            == []
        )
        assert implementation.candidate_state(
            data["candidate"]
        ) == implementation.candidate_state(data["staged"])
        with sqlite3.connect(data["candidate"]) as db:
            assert (
                db.execute(
                    "SELECT count(*) FROM policy_technical_reopen_queue WHERE status='QUEUED'"
                ).fetchone()[0]
                == 9
            )


def test_correction_rejects_stale_or_broadened_delta(tmp_path: Path) -> None:
    data = fixture(tmp_path / "negative")
    raw = json.loads(data["correction_path"].read_text())
    raw.pop("content_hash")
    raw["validation_run_after"]["authorization_status"] = "COMPLETE"
    write_record(data["correction_path"], raw)
    with pytest.raises(
        correction.CorrectionError, match="approval does not authorize|allowlist"
    ):
        invoke(data)


def test_transition_rejects_expired_policy_and_changed_prerequisites(
    tmp_path: Path,
) -> None:
    data = fixture(tmp_path / "negative-transition")
    invoke(data)
    workflow = json.loads((data["state"] / "workflow.json").read_text())
    workflow["_locator"] = str(data["state"] / "workflow.json")
    with (
        patch.object(campaign, "policy_state_is_current", return_value=False),
        pytest.raises(campaign.ContractError, match="expired"),
    ):
        campaign.policy_only_technical_admission(
            data["profile"],
            data["identity"],
            workflow,
            data["state"],
            data["candidate"],
            {"provider": data["receipt"]},
            data["workflow"]["technical_input_lineage_sha256"],
        )
    context = Path(data["receipt"]["_receipt_directory"]) / "context.json"
    context.write_text("changed\n")
    with (
        patch.object(campaign, "policy_state_is_current", return_value=True),
        pytest.raises(
            campaign.ContractError,
            match="provider prerequisite .* changed|retained stage context",
        ),
    ):
        campaign.policy_only_technical_admission(
            data["profile"],
            data["identity"],
            workflow,
            data["state"],
            data["candidate"],
            {"provider": data["receipt"]},
            data["workflow"]["technical_input_lineage_sha256"],
        )


@pytest.mark.parametrize(
    "mutation", ["shared-run", "scope", "queue", "evidence", "provider"]
)
def test_precondition_and_prerequisite_mutations_are_rejected(
    tmp_path: Path, mutation: str
) -> None:
    data = fixture(tmp_path / mutation)
    if mutation == "shared-run":
        with sqlite3.connect(data["candidate"]) as db:
            db.execute(
                "INSERT INTO validation_run_root VALUES(?,?)",
                ("validation:TFM-ROOT-H43PTPSY", "second-root"),
            )
    elif mutation == "scope":
        with sqlite3.connect(data["candidate"]) as db:
            db.execute("UPDATE campaign_subject SET programme_scope='OOS'")
    elif mutation == "queue":
        with sqlite3.connect(data["candidate"]) as db:
            db.execute(
                "DELETE FROM policy_technical_reopen_queue WHERE queue_id=(SELECT min(queue_id) FROM policy_technical_reopen_queue)"
            )
    elif mutation == "evidence":
        next(iter(data["evidence"].values())).write_text("changed\n")
    else:
        (
            Path(data["receipt"]["_receipt_directory"]) / "provider-output.json"
        ).write_text("changed\n")
    with pytest.raises(correction.CorrectionError):
        invoke(data)
    assert not list(data["state"].glob("technical-state-corrections/*/transition.json"))


def test_approval_and_lock_are_required(tmp_path: Path) -> None:
    data = fixture(tmp_path / "approval")
    data["decision"].write_text("changed approval evidence\n")
    with pytest.raises(
        correction.CorrectionError, match="recorded human authorization changed"
    ):
        invoke(data)
    data = fixture(tmp_path / "lock")
    lock_path = data["state"] / "authoritative-integrator.lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(correction.CorrectionError, match="active writer"):
            invoke(data)


@pytest.mark.parametrize("case", ["missing", "conflict"])
def test_recovery_rejects_missing_or_conflicting_material_without_replay(
    tmp_path: Path, case: str
) -> None:
    data = fixture(tmp_path / case)
    original = correction.os.replace

    def interrupt(source, destination):
        if (
            Path(destination) == data["candidate"]
            and Path(source).name == "candidate-stage.db"
        ):
            raise RuntimeError("test-only pre-promotion interruption")
        original(source, destination)

    with (
        patch.object(correction.os, "replace", side_effect=interrupt),
        pytest.raises(RuntimeError),
    ):
        invoke(data)
    before = campaign.candidate_state(data["candidate"])
    control = next(data["state"].glob(".technical-state-correction-*"))
    if case == "missing":
        (control / "candidate-stage.db").unlink()
    else:
        pending = json.loads((control / "technical-state-pending.json").read_text())
        final = Path(pending["transition_directory"])
        final.mkdir(parents=True)
        (final / "conflict").write_text("conflict\n")
    with pytest.raises(correction.CorrectionError):
        correction.recover(
            data["state"],
            data["candidate"],
            data["identity"],
            campaign.candidate_state,
            campaign.restore_candidate,
            campaign.technical_candidate_lineage,
        )
    assert campaign.candidate_state(data["candidate"]) == before
    with sqlite3.connect(data["candidate"]) as db:
        assert (
            db.execute(
                "SELECT count(*) FROM policy_technical_reopen_queue WHERE status='QUEUED'"
            ).fetchone()[0]
            == 8
        )


def test_invalid_prepared_transition_restores_candidate_and_workflow(
    tmp_path: Path,
) -> None:
    for name, implementation in implementations():
        data = fixture(tmp_path / name)
        module = implementation.technical_state_correction
        original = module.os.replace
        fired = False

        def interrupt(source, destination):
            nonlocal fired
            original(source, destination)
            if not fired and Path(destination) == data["state"] / "workflow.json":
                fired = True
                raise RuntimeError("test-only post-workflow interruption")

        before_candidate = implementation.candidate_state(data["candidate"])
        before_workflow = (data["state"] / "workflow.json").read_bytes()
        with (
            patch.object(module.os, "replace", side_effect=interrupt),
            pytest.raises(RuntimeError),
        ):
            invoke(data, implementation)
        transition = next(
            data["state"].glob("technical-state-corrections/*/transition.json")
        )
        transition.write_text("conflicting transition\n")
        with pytest.raises(module.CorrectionError):
            module.recover(
                data["state"],
                data["candidate"],
                data["identity"],
                implementation.candidate_state,
                implementation.restore_candidate,
                implementation.technical_candidate_lineage,
            )
        assert implementation.candidate_state(data["candidate"]) == before_candidate
        assert (data["state"] / "workflow.json").read_bytes() == before_workflow


@pytest.mark.parametrize("kind", ["regular", "live-symlink", "dangling-symlink"])
def test_recovery_archive_conflict_rejects_before_authoritative_mutation(
    tmp_path: Path, kind: str
) -> None:
    for name, implementation in implementations():
        data = fixture(tmp_path / name)
        module = implementation.technical_state_correction
        original = module.os.replace

        def interrupt(source, destination):
            if (
                Path(destination) == data["candidate"]
                and Path(source).name == "candidate-stage.db"
            ):
                raise RuntimeError("test-only pre-promotion interruption")
            original(source, destination)

        with (
            patch.object(module.os, "replace", side_effect=interrupt),
            pytest.raises(RuntimeError),
        ):
            invoke(data, implementation)
        before_candidate = implementation.candidate_state(data["candidate"])
        before_workflow = (data["state"] / "workflow.json").read_bytes()
        control = next(data["state"].glob(".technical-state-correction-*"))
        conflict = control / "transition-prepared/control"
        if kind == "regular":
            conflict.write_text("conflict\n")
        else:
            target = data["root"] / "target"
            if kind == "live-symlink":
                target.write_text("target\n")
            conflict.symlink_to(target)
        for _ in range(2):
            with pytest.raises(module.CorrectionError):
                module.recover(
                    data["state"],
                    data["candidate"],
                    data["identity"],
                    implementation.candidate_state,
                    implementation.restore_candidate,
                    implementation.technical_candidate_lineage,
                )
            assert implementation.candidate_state(data["candidate"]) == before_candidate
            assert (data["state"] / "workflow.json").read_bytes() == before_workflow


@pytest.mark.parametrize(
    "kind", ["directory", "regular", "live-symlink", "dangling-symlink"]
)
def test_recovery_record_conflict_rejects_before_authoritative_mutation(
    tmp_path: Path, kind: str
) -> None:
    for name, implementation in implementations():
        data = fixture(tmp_path / name)
        module = implementation.technical_state_correction
        original = module.os.replace

        def interrupt(source, destination):
            if (
                Path(destination) == data["candidate"]
                and Path(source).name == "candidate-stage.db"
            ):
                raise RuntimeError("test-only pre-promotion interruption")
            original(source, destination)

        with (
            patch.object(module.os, "replace", side_effect=interrupt),
            pytest.raises(RuntimeError),
        ):
            invoke(data, implementation)
        before_candidate = implementation.candidate_state(data["candidate"])
        before_workflow = (data["state"] / "workflow.json").read_bytes()
        control = next(data["state"].glob(".technical-state-correction-*"))
        conflict = control / "transition-prepared/recovery.json"
        if kind == "directory":
            conflict.mkdir()
        elif kind == "regular":
            conflict.write_text("conflicting recovery record\n")
        else:
            target = data["root"] / "recovery-target"
            if kind == "live-symlink":
                target.write_text("target\n")
            conflict.symlink_to(target)
        for _ in range(2):
            with pytest.raises(module.CorrectionError, match="recovery record"):
                module.recover(
                    data["state"],
                    data["candidate"],
                    data["identity"],
                    implementation.candidate_state,
                    implementation.restore_candidate,
                    implementation.technical_candidate_lineage,
                )
            assert implementation.candidate_state(data["candidate"]) == before_candidate
            assert (data["state"] / "workflow.json").read_bytes() == before_workflow
            assert module.entry_kind(conflict) == {
                "directory": "DIRECTORY",
                "regular": "REGULAR_FILE",
                "live-symlink": "SYMLINK",
                "dangling-symlink": "SYMLINK",
            }[kind]


def test_exact_recovery_record_is_reused_after_interruption(tmp_path: Path) -> None:
    for name, implementation in implementations():
        data = fixture(tmp_path / name)
        module = implementation.technical_state_correction
        original = module.os.replace
        candidate_interrupted = False

        def interrupt_candidate(source, destination):
            nonlocal candidate_interrupted
            if (
                not candidate_interrupted
                and Path(destination) == data["candidate"]
                and Path(source).name == "candidate-stage.db"
            ):
                candidate_interrupted = True
                raise RuntimeError("test-only pre-promotion interruption")
            original(source, destination)

        with (
            patch.object(module.os, "replace", side_effect=interrupt_candidate),
            pytest.raises(RuntimeError),
        ):
            invoke(data, implementation)
        archive_interrupted = False

        def interrupt_archive(source, destination):
            nonlocal archive_interrupted
            if not archive_interrupted and Path(destination).name == "control":
                archive_interrupted = True
                raise RuntimeError("test-only post-recovery-record interruption")
            original(source, destination)

        with (
            patch.object(module.os, "replace", side_effect=interrupt_archive),
            pytest.raises(RuntimeError),
        ):
            module.recover(
                data["state"],
                data["candidate"],
                data["identity"],
                implementation.candidate_state,
                implementation.restore_candidate,
                implementation.technical_candidate_lineage,
            )
        recovery = next(
            data["state"].glob("technical-state-corrections/*/recovery.json")
        )
        recovery_bytes = recovery.read_bytes()
        with patch.object(
            module,
            "atomic_json",
            side_effect=AssertionError("valid recovery record was rewritten"),
        ):
            result = module.recover(
                data["state"],
                data["candidate"],
                data["identity"],
                implementation.candidate_state,
                implementation.restore_candidate,
                implementation.technical_candidate_lineage,
            )
        assert result[0]["result"] == "TECHNICAL_STATE_CORRECTION_COMPLETED"
        assert recovery.read_bytes() == recovery_bytes


def test_expired_transition_can_enter_fresh_policy_replacement_lane(
    tmp_path: Path,
) -> None:
    for name, implementation in implementations():
        data = fixture(tmp_path / name)
        invoke(data, implementation)
        current = json.loads((data["state"] / "workflow.json").read_text())
        current["_locator"] = str(data["state"] / "workflow.json")
        with (
            patch.object(implementation, "policy_state_is_current", return_value=False),
            pytest.raises(implementation.ContractError, match="expired"),
        ):
            implementation.policy_only_technical_admission(
                data["profile"],
                data["identity"],
                current,
                data["state"],
                data["candidate"],
                {"provider": data["receipt"]},
                data["workflow"]["technical_input_lineage_sha256"],
            )
        with patch.object(
            implementation, "policy_state_is_current", return_value=False
        ):
            now = datetime.now(timezone.utc) - timedelta(seconds=1)
            policy = data["root"] / "fresh-policy.json"
            tickets = data["root"] / "fresh-tickets.json"
            policy.write_text("{}\n")
            tickets.write_text("{}\n")
            replacement_path = data["root"] / "fresh-replacement.json"
            replacement_path.write_text(
                json.dumps(
                    {
                        "format_version": implementation.POLICY_REFRESH_FORMAT,
                        "project_id": "fixture",
                        "sources": [
                            {
                                "source_id": kind,
                                "source_kind": kind,
                                "source_locator": f"https://fixture.invalid/{kind}",
                                "retrieval_status": "SUCCESS",
                                "collection_scope": "FULL",
                                "retrieved_at": now.isoformat(),
                                "expires_at": (now + timedelta(minutes=5)).isoformat(),
                                "evidence": {
                                    "locator": path.name,
                                    "sha256": implementation.file_hash(path),
                                },
                            }
                            for kind, path in (
                                ("PROGRAMME_POLICY", policy),
                                ("CURRENT_TICKETS", tickets),
                            )
                        ],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
            replacement = implementation.policy_refresh_bundle(
                replacement_path, "fixture"
            )
            assert implementation.policy_only_technical_admission(
                data["profile"],
                data["identity"],
                current,
                data["state"],
                data["candidate"],
                {"provider": data["receipt"]},
                data["workflow"]["technical_input_lineage_sha256"],
                verified_policy_replacement=replacement,
            )


@pytest.mark.parametrize("change", ["add-unrelated", "resolve-correction"])
def test_policy_queue_evolution_preserves_transition_admission(
    tmp_path: Path, change: str
) -> None:
    for name, implementation in implementations():
        data = fixture(tmp_path / name)
        invoke(data, implementation)
        with sqlite3.connect(data["candidate"]) as db:
            if change == "add-unrelated":
                queued = queue_row("unrelated", data["old"], 100)
                db.execute(
                    "INSERT INTO policy_technical_reopen_queue VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(queued.values()),
                )
            else:
                queue_id = data["queue"]["queue_id"]
                locator = str(data["old"])
                digest = implementation.file_hash(data["old"])
                rationale = "evidence-backed completion"
                resolution = implementation.object_hash(
                    {
                        "queue_id": queue_id,
                        "status": "RESOLVED",
                        "evidence_locator": locator,
                        "evidence_hash": digest,
                        "rationale": rationale,
                    }
                )
                db.execute(
                    "UPDATE policy_technical_reopen_queue SET status='RESOLVED',resolution_evidence_locator=?,resolution_evidence_hash=?,resolution_rationale=?,resolution_content_hash=? WHERE queue_id=?",
                    (locator, digest, rationale, resolution, queue_id),
                )
        current = json.loads((data["state"] / "workflow.json").read_text())
        current.pop("workflow_sha256")
        current["execution_mode"] = "POLICY_ONLY"
        current["candidate"] = implementation.candidate_state(data["candidate"])
        write_record(data["state"] / "workflow.json", current, "workflow_sha256")
        current = json.loads((data["state"] / "workflow.json").read_text())
        current["_locator"] = str(data["state"] / "workflow.json")
        with patch.object(implementation, "policy_state_is_current", return_value=True):
            assert implementation.policy_only_technical_admission(
                data["profile"],
                data["identity"],
                current,
                data["state"],
                data["candidate"],
                {"provider": data["receipt"]},
                data["workflow"]["technical_input_lineage_sha256"],
            )


@pytest.mark.parametrize("source", ["transition", "later-policy-receipt"])
def test_committed_queue_history_rejects_unexplained_deletion(
    tmp_path: Path, source: str
) -> None:
    for name, implementation in implementations():
        data = fixture(tmp_path / name)
        invoke(data, implementation)
        receipts = {"provider": data["receipt"]}
        if source == "later-policy-receipt":
            later = queue_row("later-policy-root", data["old"], 100)
            with sqlite3.connect(data["candidate"]) as db:
                columns = [
                    row[1]
                    for row in db.execute(
                        "PRAGMA table_info(policy_technical_reopen_queue)"
                    )
                ]
                db.execute(
                    f"INSERT INTO policy_technical_reopen_queue VALUES({','.join('?' for _ in columns)})",
                    tuple(later[column] for column in columns),
                )
                rows = [
                    dict(zip(columns, row))
                    for row in db.execute(
                        "SELECT * FROM policy_technical_reopen_queue ORDER BY queue_id"
                    )
                ]
            policy = policy_queue_receipt(data["state"], rows)
            data["profile"]["automation"]["stages"].append(
                {"stage_id": "policy", "phase": "POLICY_RECONCILIATION"}
            )
            receipts["policy"] = policy
            delete_id = later["queue_id"]
            current = json.loads((data["state"] / "workflow.json").read_text())
            current.pop("workflow_sha256")
            current["execution_mode"] = "POLICY_ONLY"
            current["candidate"] = implementation.candidate_state(
                data["candidate"]
            )
            write_record(data["state"] / "workflow.json", current, "workflow_sha256")
            current = json.loads((data["state"] / "workflow.json").read_text())
            current["_locator"] = str(data["state"] / "workflow.json")
            with patch.object(
                implementation, "policy_state_is_current", return_value=True
            ):
                assert implementation.policy_only_technical_admission(
                    data["profile"],
                    data["identity"],
                    current,
                    data["state"],
                    data["candidate"],
                    receipts,
                    data["workflow"]["technical_input_lineage_sha256"],
                )
        else:
            with sqlite3.connect(data["candidate"]) as db:
                delete_id = db.execute(
                    "SELECT queue_id FROM policy_technical_reopen_queue "
                    "WHERE root_id='other-0'"
                ).fetchone()[0]
        with sqlite3.connect(data["candidate"]) as db:
            db.execute(
                "DELETE FROM policy_technical_reopen_queue WHERE queue_id=?",
                (delete_id,),
            )
        current = json.loads((data["state"] / "workflow.json").read_text())
        current.pop("workflow_sha256")
        current["execution_mode"] = "POLICY_ONLY"
        current["candidate"] = implementation.candidate_state(data["candidate"])
        write_record(data["state"] / "workflow.json", current, "workflow_sha256")
        current = json.loads((data["state"] / "workflow.json").read_text())
        current["_locator"] = str(data["state"] / "workflow.json")
        with (
            patch.object(implementation, "policy_state_is_current", return_value=True),
            pytest.raises(implementation.ContractError, match="committed.*changed"),
        ):
            implementation.policy_only_technical_admission(
                data["profile"],
                data["identity"],
                current,
                data["state"],
                data["candidate"],
                receipts,
                data["workflow"]["technical_input_lineage_sha256"],
            )


def test_relative_approval_binding_rejected_before_mutation(tmp_path: Path) -> None:
    for name, implementation in implementations():
        data = fixture(tmp_path / name)
        approval = json.loads(data["approval_path"].read_text())
        approval.pop("content_hash")
        approval["authorization_record"]["locator"] = data["decision"].name
        write_record(data["approval_path"], approval)
        candidate_before = implementation.candidate_state(data["candidate"])
        workflow_before = (data["state"] / "workflow.json").read_bytes()
        with pytest.raises(
            implementation.technical_state_correction.CorrectionError,
            match="absolute",
        ):
            invoke(data, implementation)
        assert implementation.candidate_state(data["candidate"]) == candidate_before
        assert (data["state"] / "workflow.json").read_bytes() == workflow_before


def test_run_mode_is_nonexecuting_in_both_coordinators(tmp_path: Path) -> None:
    for name, implementation in implementations():
        data = fixture(tmp_path / name)
        arguments = argparse.Namespace(
            project_profile=data["profile_path"],
            candidate=str(data["candidate"]),
            state=str(data["state"]),
            source=[],
            source_path=[],
            ticket_selector=[],
            confluence_selector=[],
            credential_env=[],
            policy_only=False,
            policy_refresh_bundle=None,
            technical_state_correction=data["correction_path"],
            technical_state_approval=data["approval_path"],
        )
        with (
            patch.object(implementation, "parse_bindings", return_value={}),
            patch.object(implementation, "source_paths", return_value={}),
            patch.object(
                implementation,
                "verify_profile",
                return_value=(data["profile"], data["identity"]),
            ),
            patch.object(implementation, "policy_state_is_current", return_value=True),
            patch.object(
                implementation,
                "execute_stage",
                side_effect=AssertionError("provider or stage dispatch attempted"),
            ),
        ):
            result = implementation.run(arguments)
        assert result["result"] == "TECHNICAL_STATE_CORRECTION_COMPLETED"
