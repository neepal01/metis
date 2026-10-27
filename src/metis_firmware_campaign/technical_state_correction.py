# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Explicit, non-executing correction of a narrowly allowlisted technical state."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
from pathlib import Path
from typing import Callable


CORRECTION_FORMAT = "firmware-technical-state-correction-v1"
APPROVAL_FORMAT = "firmware-technical-state-correction-approval-v1"
INVENTORY_FORMAT = "firmware-provider-checkpoint-inventory-v1"
TRANSITION_FORMAT = "firmware-technical-state-transition-v2"
PENDING_FORMAT = "firmware-technical-state-pending-v1"
CONTROL_REVISION = "6.9.0-REVIEW"
ALLOWED_VALIDATION_FIELDS = {
    "rca_workflow_status",
    "authorization_workflow_status",
    "reproduction_workflow_status",
    "workflow_blocker",
}
REQUIRED_BLOCKERS = {"RCA", "AUTHORIZATION", "FVP_REPRODUCTION"}
ALLOWED_QUEUE_AXES = {"DEDUPLICATION", "REPRODUCTION"}
MUTABLE_POLICY_PHASES = {
    "CURRENT_TICKET_COLLECTION",
    "THREAT_POLICY_COLLECTION",
    "POLICY_RECONCILIATION",
    "EXISTING_REPORT_FOLLOWUP",
    "PACKAGE_EXPORT",
    "POPULATION_SCOPED_REPORTING",
    "PACKAGE_AND_SEAL",
}
QUEUE_INDEX_FORMAT = "firmware-technical-reopen-queue-v6.8"
IMMUTABLE_QUEUE_FIELDS = (
    "queue_id",
    "root_id",
    "trigger_kind",
    "evidence_locator",
    "evidence_hash",
    "affected_axes_json",
    "rationale",
    "content_hash",
)
RESOLUTION_QUEUE_FIELDS = (
    "resolution_evidence_locator",
    "resolution_evidence_hash",
    "resolution_rationale",
    "resolution_content_hash",
)


class CorrectionError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def object_hash(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise CorrectionError(f"{label} must be a regular non-symlink file: {path}")
    return path


def entry_kind(path: Path) -> str | None:
    """Inspect a persistent directory entry without following symlinks."""
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return None
    if stat.S_ISDIR(mode):
        return "DIRECTORY"
    if stat.S_ISREG(mode):
        return "REGULAR_FILE"
    if stat.S_ISLNK(mode):
        return "SYMLINK"
    return "UNSUPPORTED"


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def _record(path: Path, expected_format: str, label: str) -> dict:
    path = regular(path.resolve(), label)
    value = json.loads(path.read_text())
    claimed = value.pop("content_hash", None)
    if claimed != object_hash(value) or value.get("format_version") != expected_format:
        raise CorrectionError(f"{label} identity mismatch")
    value["content_hash"] = claimed
    value["_locator"] = str(path)
    value["_sha256"] = file_hash(path)
    value["_size"] = path.stat().st_size
    return value


def _workflow(path: Path, label: str) -> dict:
    path = regular(path.resolve(), label)
    value = json.loads(path.read_text())
    claimed = value.pop("workflow_sha256", None)
    if (
        claimed != object_hash(value)
        or value.get("format_version") != "firmware-autonomous-campaign-v1"
    ):
        raise CorrectionError(f"{label} identity mismatch")
    value["workflow_sha256"] = claimed
    value["_locator"] = str(path)
    value["_file_sha256"] = file_hash(path)
    return value


def _bound_artifact(base: Path, value: dict, label: str) -> dict:
    if set(value) != {"locator", "sha256", "size"}:
        raise CorrectionError(f"invalid {label} binding")
    if not Path(value["locator"]).is_absolute():
        raise CorrectionError(f"{label} locator must be absolute")
    path = regular(Path(value["locator"]).resolve(), label)
    if file_hash(path) != value["sha256"] or path.stat().st_size != value["size"]:
        raise CorrectionError(f"{label} changed")
    return {**value, "resolved_locator": str(path)}


def _candidate_state(path: Path) -> dict:
    if not path.exists():
        return {"exists": False}
    regular(path, "candidate database")
    return {"exists": True, "sha256": file_hash(path), "size": path.stat().st_size}


def _row(
    db: sqlite3.Connection, table: str, key: str, value: str
) -> tuple[list[str], dict]:
    columns = [item[1] for item in db.execute(f'PRAGMA table_info("{table}")')]
    if not columns:
        raise CorrectionError(f"candidate lacks required table: {table}")
    rows = db.execute(f'SELECT * FROM "{table}" WHERE "{key}"=?', (value,)).fetchall()
    if len(rows) != 1:
        raise CorrectionError(f"candidate does not contain exactly one {table} row")
    return columns, dict(zip(columns, rows[0]))


def _table_projection(db: sqlite3.Connection, table: str) -> dict:
    columns = [item[1] for item in db.execute(f'PRAGMA table_info("{table}")')]
    if not columns:
        raise CorrectionError(f"candidate lacks required table: {table}")
    select = ",".join(f'"{item}"' for item in columns)
    order = ",".join(str(index + 1) for index in range(len(columns)))
    rows = db.execute(f'SELECT {select} FROM "{table}" ORDER BY {order}').fetchall()

    def typed(item: object) -> dict:
        if item is None:
            return {"type": "NULL"}
        if isinstance(item, bytes):
            return {"type": "BLOB", "hex": item.hex()}
        if isinstance(item, str):
            return {"type": "TEXT", "value": item}
        if isinstance(item, int):
            return {"type": "INTEGER", "value": item}
        if isinstance(item, float):
            return {"type": "REAL", "hex": item.hex()}
        raise CorrectionError(f"unsupported SQLite value in {table}")

    return {"columns": columns, "rows": [[typed(item) for item in row] for row in rows]}


def _table_rows(db: sqlite3.Connection, table: str) -> tuple[list[str], list[dict]]:
    columns = [item[1] for item in db.execute(f'PRAGMA table_info("{table}")')]
    select = ",".join(f'"{item}"' for item in columns)
    order = ",".join(str(index + 1) for index in range(len(columns)))
    rows = db.execute(f'SELECT {select} FROM "{table}" ORDER BY {order}').fetchall()
    return columns, [dict(zip(columns, row)) for row in rows]


def _candidate_projection(candidate: Path, excluded: set[str] | None = None) -> dict:
    excluded = excluded or set()
    with sqlite3.connect(
        f"file:{candidate.resolve()}?mode=ro&immutable=1", uri=True
    ) as db:
        tables = sorted(
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            if not row[0].startswith("sqlite_") and row[0] not in excluded
        )
        return {table: _table_projection(db, table) for table in tables}


def _verify_inventory(binding: dict, base: Path) -> tuple[dict, dict]:
    bound = _bound_artifact(base, binding, "provider checkpoint inventory")
    inventory = _record(
        Path(bound["resolved_locator"]),
        INVENTORY_FORMAT,
        "provider checkpoint inventory",
    )
    if inventory["_sha256"] != bound["sha256"]:
        raise CorrectionError("provider checkpoint inventory hash mismatch")
    required = {
        "project_id",
        "roots",
        "entries",
        "counters",
        "inventory_sha256",
        "entries_sha256",
    }
    body = {
        key: value
        for key, value in inventory.items()
        if not key.startswith("_") and key != "content_hash"
    }
    if set(body) != required | {"format_version"}:
        raise CorrectionError("provider checkpoint inventory has unexpected fields")
    entries = inventory.get("entries")
    if not isinstance(entries, list) or not entries:
        raise CorrectionError("provider checkpoint inventory is empty")
    observed = []
    for entry in entries:
        if set(entry) != {"kind", "locator", "sha256", "size"}:
            raise CorrectionError("invalid provider inventory entry")
        observed.append(
            {
                "kind": entry["kind"],
                **_bound_artifact(
                    Path(inventory["_locator"]).parent,
                    {key: entry[key] for key in ("locator", "sha256", "size")},
                    f"provider prerequisite {entry['kind']}",
                ),
            }
        )
    counters = inventory["counters"]
    if set(counters) != {"requests_started", "requests_completed", "errors"} or any(
        not isinstance(value, int) or value < 0 for value in counters.values()
    ):
        raise CorrectionError("provider inventory counters are invalid")
    projection = [
        {
            "kind": source["kind"],
            "locator": source["locator"],
            "sha256": source["sha256"],
            "size": source["size"],
        }
        for source in entries
    ]
    roots = inventory["roots"]
    if not isinstance(roots, list) or not roots or len(set(roots)) != len(roots):
        raise CorrectionError("provider inventory roots are invalid")
    census = set()
    for value in roots:
        root = (
            Path(value)
            if Path(value).is_absolute()
            else Path(inventory["_locator"]).parent / value
        ).resolve()
        if root.is_symlink() or not root.is_dir():
            raise CorrectionError("provider inventory root is unavailable")
        for item in root.rglob("*"):
            if item.is_symlink() or (not item.is_file() and not item.is_dir()):
                raise CorrectionError(
                    "provider inventory contains an unsupported entry"
                )
            if item.is_file():
                census.add(str(item.resolve()))
    declared = {item["resolved_locator"] for item in observed}
    if not census <= declared:
        raise CorrectionError("provider inventory omits a checkpoint-root file")
    if inventory["entries_sha256"] != object_hash(
        {"roots": roots, "entries": projection}
    ):
        raise CorrectionError("provider inventory projection mismatch")
    budgets = [item for item in observed if item["kind"] == "PROVIDER_BUDGET"]
    if len(budgets) != 1:
        raise CorrectionError(
            "provider inventory must contain exactly one budget ledger"
        )
    ledger = json.loads(Path(budgets[0]["resolved_locator"]).read_text())
    if {key: ledger.get(key) for key in counters} != counters:
        raise CorrectionError("provider budget counters differ from the inventory")
    if (
        not isinstance(inventory["inventory_sha256"], str)
        or len(inventory["inventory_sha256"]) != 64
        or any(
            value not in "0123456789abcdef" for value in inventory["inventory_sha256"]
        )
    ):
        raise CorrectionError("provider inventory identity is invalid")
    return inventory, {
        "inventory_sha256": inventory["inventory_sha256"],
        "entries_sha256": inventory["entries_sha256"],
        "counters": counters,
        "roots": roots,
        "entries": projection,
        "verified_files": observed,
    }


def _receipt_provenance(profile: dict, receipts: dict[str, dict]) -> list[dict]:
    provider_phases = {
        item["stage_id"]
        for item in profile["automation"]["stages"]
        if item["phase"].startswith("METIS_")
    }
    result = []
    for stage_id in sorted(provider_phases):
        receipt = receipts[stage_id]
        result.append(
            {
                "stage_id": stage_id,
                "receipt_sha256": receipt["receipt_sha256"],
                "stage_identity": receipt["stage_identity"],
                "input_sha256": receipt["input_sha256"],
                "candidate_before": receipt.get("candidate_before"),
                "candidate_after": receipt.get("candidate_after"),
                "outputs": receipt.get("outputs", []),
            }
        )
    return result


def _all_receipt_provenance(profile: dict, receipts: dict[str, dict]) -> list[dict]:
    result = []
    retained = {
        item["stage_id"]
        for item in profile["automation"]["stages"]
        if item["phase"] not in MUTABLE_POLICY_PHASES
    }
    for stage_id in sorted(set(receipts) & retained):
        receipt = receipts[stage_id]
        directory = Path(receipt["_receipt_directory"])
        context = directory / "context.json"
        result.append(
            {
                "stage_id": stage_id,
                "receipt_sha256": receipt["receipt_sha256"],
                "receipt_file_sha256": file_hash(
                    regular(directory / "receipt.json", "retained stage receipt")
                ),
                "context_file_sha256": file_hash(
                    regular(context, "retained stage context")
                )
                if context.exists()
                else None,
                "outputs": [
                    {
                        **item,
                        "observed_sha256": file_hash(
                            regular(
                                directory / item["locator"], "retained stage output"
                            )
                        ),
                    }
                    for item in receipt.get("outputs", [])
                ],
            }
        )
    return result


def _require_provider_files(receipts: dict[str, dict], inventory: dict) -> None:
    present = {item["resolved_locator"] for item in inventory["verified_files"]}
    for receipt in receipts.values():
        directory = Path(receipt["_receipt_directory"]).resolve()
        required = {str((directory / "receipt.json").resolve())}
        if (directory / "context.json").exists():
            required.add(str((directory / "context.json").resolve()))
        required |= {
            str((directory / item["locator"]).resolve())
            for item in receipt.get("outputs", [])
        }
        if not required <= present:
            raise CorrectionError(
                f"provider inventory omits retained receipt/context/output: {receipt['stage_id']}"
            )


def _queue_row(
    queue: dict, root_id: str, columns: list[str], evidence: list[dict]
) -> dict:
    if set(queue) != set(columns):
        raise CorrectionError("queue addition does not bind the complete row")
    if queue.get("root_id") != root_id or queue.get("status") != "QUEUED":
        raise CorrectionError(
            "queue addition is not an unresolved request for the target root"
        )
    try:
        axes = json.loads(queue["affected_axes_json"])
    except (TypeError, json.JSONDecodeError) as error:
        raise CorrectionError("queue affected axes are invalid") from error
    if (
        not isinstance(axes, list)
        or sorted(set(axes)) != axes
        or not axes
        or not set(axes) <= ALLOWED_QUEUE_AXES
    ):
        raise CorrectionError(
            "technical-state correction queue axes are outside the allowlist"
        )
    resolution = [name for name in columns if name.startswith("resolution_")]
    if any(queue.get(name) is not None for name in resolution):
        raise CorrectionError("new queue request is already resolved")
    hashes = {item["sha256"] for item in evidence}
    if queue.get("evidence_hash") not in hashes:
        raise CorrectionError("queue addition is not bound to correction evidence")
    body = {
        key: value
        for key, value in queue.items()
        if key not in {"queue_id", "content_hash"}
    }
    if (
        queue.get("content_hash") != object_hash(body)
        or queue.get("queue_id") != f"v68:reopen:{queue['content_hash'][:24]}"
    ):
        raise CorrectionError("queue addition identity mismatch")
    return queue


def _queue_commitment(row: dict) -> dict:
    if not all(name in row for name in IMMUTABLE_QUEUE_FIELDS):
        raise CorrectionError("technical reopen request is incomplete")
    return {name: row[name] for name in IMMUTABLE_QUEUE_FIELDS}


def _queue_commitments(candidate: Path) -> list[dict]:
    with sqlite3.connect(
        f"file:{candidate.resolve()}?mode=ro&immutable=1", uri=True
    ) as db:
        _, rows = _table_rows(db, "policy_technical_reopen_queue")
    result = [_queue_commitment(row) for row in rows]
    return sorted(result, key=lambda row: row["queue_id"])


def _verify_committed_queue(
    candidate: Path,
    commitments: list[dict],
    evidence_project: Path,
    *,
    exact: bool = False,
) -> None:
    expected = {}
    for commitment in commitments:
        if set(commitment) != set(IMMUTABLE_QUEUE_FIELDS):
            raise CorrectionError("committed technical reopen request is invalid")
        prior = expected.setdefault(commitment["queue_id"], commitment)
        if prior != commitment:
            raise CorrectionError("conflicting committed technical reopen requests")
    with sqlite3.connect(
        f"file:{candidate.resolve()}?mode=ro&immutable=1", uri=True
    ) as db:
        columns, rows = _table_rows(db, "policy_technical_reopen_queue")
    present = {row["queue_id"]: row for row in rows}
    if exact and set(present) != set(expected):
        raise CorrectionError("technical-state committed queue differs")
    for queue_id, commitment in expected.items():
        observed = present.get(queue_id)
        if observed is None or _queue_commitment(observed) != commitment:
            raise CorrectionError("committed technical reopen request changed")
        normalized = dict(observed)
        if observed["status"] == "QUEUED":
            if any(observed[name] is not None for name in RESOLUTION_QUEUE_FIELDS):
                raise CorrectionError(
                    "queued technical reopen request contains resolution fields"
                )
        elif observed["status"] in {"RESOLVED", "SUPERSEDED"}:
            locator = observed["resolution_evidence_locator"]
            path = (
                Path(locator)
                if Path(str(locator)).is_absolute()
                else evidence_project / str(locator)
            ).resolve()
            try:
                path.relative_to(evidence_project.resolve())
            except ValueError as error:
                raise CorrectionError(
                    "technical reopen resolution evidence escapes project"
                ) from error
            if (
                file_hash(regular(path, "technical reopen resolution evidence"))
                != observed["resolution_evidence_hash"]
                or not isinstance(observed["resolution_rationale"], str)
                or not observed["resolution_rationale"].strip()
                or observed["resolution_content_hash"]
                != object_hash(
                    {
                        "queue_id": observed["queue_id"],
                        "status": observed["status"],
                        "evidence_locator": locator,
                        "evidence_hash": observed["resolution_evidence_hash"],
                        "rationale": observed["resolution_rationale"],
                    }
                )
            ):
                raise CorrectionError(
                    "technical reopen request resolution evidence differs"
                )
        else:
            raise CorrectionError("technical reopen request status is invalid")
        normalized.update(
            status="QUEUED",
            resolution_evidence_locator=None,
            resolution_evidence_hash=None,
            resolution_rationale=None,
            resolution_content_hash=None,
        )
        if normalized.get("content_hash") != object_hash(
            {key: value for key, value in normalized.items() if key not in {"queue_id", "content_hash"}}
        ) or normalized.get("queue_id") != f"v68:reopen:{normalized['content_hash'][:24]}":
            raise CorrectionError("technical reopen request identity differs")


def _policy_receipt_queue_commitments(profile: dict, receipts: dict[str, dict]) -> list[dict]:
    commitments = []
    for stage in profile["automation"]["stages"]:
        if stage["phase"] != "POLICY_RECONCILIATION":
            continue
        receipt = receipts[stage["stage_id"]]
        directory = Path(receipt["_receipt_directory"]).resolve()
        outputs = [
            item
            for item in receipt.get("outputs", [])
            if Path(item["locator"]).name == "TECHNICAL-REOPEN-QUEUE.json"
        ]
        if not outputs:
            continue
        if len(outputs) != 1:
            raise CorrectionError("policy receipt has ambiguous technical queue index")
        item = outputs[0]
        path = (directory / item["locator"]).resolve()
        try:
            path.relative_to(directory)
        except ValueError as error:
            raise CorrectionError("policy queue index escapes its receipt") from error
        path = regular(path, "policy technical queue index")
        if file_hash(path) != item["sha256"] or path.stat().st_size != item["size"]:
            raise CorrectionError("policy technical queue index changed")
        index = json.loads(path.read_text())
        claimed = index.pop("content_hash", None)
        if (
            set(index) != {"format_version", "requests"}
            or index["format_version"] != QUEUE_INDEX_FORMAT
            or claimed != object_hash(index)
            or not isinstance(index["requests"], list)
        ):
            raise CorrectionError("policy technical queue index identity differs")
        commitments.extend(_queue_commitment(row) for row in index["requests"])
    return commitments


def load_bundle(
    correction_path: Path, approval_path: Path, project_id: str
) -> tuple[dict, dict, dict, dict]:
    correction = _record(
        correction_path, CORRECTION_FORMAT, "technical-state correction"
    )
    expected = {
        "format_version",
        "control_revision",
        "project_id",
        "base",
        "target",
        "validation_run_before",
        "validation_run_after",
        "queue_addition",
        "evidence",
        "provider_inventory",
        "provider_invariants_after",
        "technical_candidate_lineage_after",
    }
    body = {
        key for key in correction if not key.startswith("_") and key != "content_hash"
    }
    if (
        body != expected
        or correction.get("control_revision") != CONTROL_REVISION
        or correction.get("project_id") != project_id
    ):
        raise CorrectionError("technical-state correction contract mismatch")
    base = correction["base"]
    if set(base) != {
        "candidate",
        "workflow_sha256",
        "workflow_file_sha256",
        "profile_sha256",
        "technical_candidate_lineage_sha256",
        "technical_input_lineage_sha256",
        "provider_inventory_sha256",
        "provider_counters",
        "unresolved_queue_count",
    }:
        raise CorrectionError("technical-state correction base is incomplete")
    target = correction["target"]
    if set(target) != {"root_id", "validation_run_id"} or not all(
        isinstance(value, str) and value for value in target.values()
    ):
        raise CorrectionError("technical-state correction target is invalid")
    evidence = correction["evidence"]
    if (
        not isinstance(evidence, list)
        or len(evidence) != len(REQUIRED_BLOCKERS)
        or {item.get("purpose") for item in evidence} != REQUIRED_BLOCKERS
    ):
        raise CorrectionError(
            "technical-state correction lacks RCA/authorization/FVP evidence"
        )
    bound_evidence = []
    for item in evidence:
        if set(item) != {"purpose", "locator", "sha256", "size"}:
            raise CorrectionError("technical-state correction evidence is invalid")
        bound_evidence.append(
            {
                "purpose": item["purpose"],
                **_bound_artifact(
                    Path(correction["_locator"]).parent,
                    {key: item[key] for key in ("locator", "sha256", "size")},
                    f"{item['purpose']} blocker evidence",
                ),
            }
        )
    inventory, inventory_projection = _verify_inventory(
        correction["provider_inventory"], Path(correction["_locator"]).parent
    )
    approval = _record(
        approval_path, APPROVAL_FORMAT, "technical-state correction approval"
    )
    approval_body = {
        key for key in approval if not key.startswith("_") and key != "content_hash"
    }
    if approval_body != {
        "format_version",
        "control_revision",
        "project_id",
        "decision",
        "correction_content_hash",
        "authorized_by",
        "authority",
        "approval_id",
        "authorization_record",
    } or any(
        not isinstance(approval.get(key), str) or not approval[key].strip()
        for key in ("authorized_by", "authority", "approval_id")
    ):
        raise CorrectionError("technical-state correction approval is incomplete")
    if (
        approval["control_revision"] != CONTROL_REVISION
        or approval["project_id"] != project_id
        or approval["decision"] != "APPROVE_EXACT_TECHNICAL_STATE_CORRECTION"
        or approval["correction_content_hash"] != correction["content_hash"]
    ):
        raise CorrectionError("approval does not authorize this exact correction")
    _bound_artifact(
        Path(approval["_locator"]).parent,
        approval["authorization_record"],
        "recorded human authorization",
    )
    return correction, approval, {"evidence": bound_evidence}, inventory_projection


def _verify_before(
    candidate: Path,
    profile: dict,
    profile_identity: dict,
    prior_workflow: dict,
    correction: dict,
    receipts: dict[str, dict],
    current_technical_inputs: str,
    technical_lineage: Callable[[Path], str],
) -> tuple[dict, list[str], list[str]]:
    base = correction["base"]
    if (
        _candidate_state(candidate) != base["candidate"]
        or prior_workflow.get("workflow_sha256") != base["workflow_sha256"]
    ):
        raise CorrectionError(
            "technical-state correction base candidate/workflow is stale"
        )
    if (
        file_hash(Path(prior_workflow["_locator"])) != base["workflow_file_sha256"]
        or profile_identity["sha256"] != base["profile_sha256"]
    ):
        raise CorrectionError("technical-state correction base files changed")
    if (
        technical_lineage(candidate) != base["technical_candidate_lineage_sha256"]
        or prior_workflow.get("technical_candidate_lineage_sha256")
        != base["technical_candidate_lineage_sha256"]
    ):
        raise CorrectionError(
            "technical-state correction base technical lineage changed"
        )
    if (
        current_technical_inputs != base["technical_input_lineage_sha256"]
        or prior_workflow.get("technical_input_lineage_sha256")
        != current_technical_inputs
    ):
        raise CorrectionError("technical-state correction changed technical inputs")
    if prior_workflow.get("profile_sha256") != profile_identity["sha256"]:
        raise CorrectionError("technical-state correction changed profile")
    stages = {item["stage_id"] for item in profile["automation"]["stages"]}
    if set(receipts) != stages or set(prior_workflow.get("stages", {})) != stages:
        raise CorrectionError(
            "technical-state correction lacks complete prerequisite receipts"
        )
    retained = _receipt_provenance(profile, receipts)
    with sqlite3.connect(
        f"file:{candidate.resolve()}?mode=ro&immutable=1", uri=True
    ) as db:
        validation_columns, validation = _row(
            db,
            "validation_run",
            "validation_run_id",
            correction["target"]["validation_run_id"],
        )
        queue_columns = [
            item[1]
            for item in db.execute('PRAGMA table_info("policy_technical_reopen_queue")')
        ]
        mappings = db.execute(
            "SELECT root_id FROM validation_run_root WHERE validation_run_id=? ORDER BY root_id",
            (correction["target"]["validation_run_id"],),
        ).fetchall()
        if mappings != [(correction["target"]["root_id"],)]:
            raise CorrectionError(
                "technical-state correction target is not associated with exactly one root"
            )
        before_queue_count = db.execute(
            "SELECT count(*) FROM policy_technical_reopen_queue WHERE status='QUEUED'"
        ).fetchone()[0]
    if validation != correction["validation_run_before"] or set(validation) != set(
        correction["validation_run_after"]
    ):
        raise CorrectionError("technical-state correction before-values differ")
    changed = {
        key
        for key in validation
        if validation[key] != correction["validation_run_after"][key]
    }
    if changed != ALLOWED_VALIDATION_FIELDS:
        raise CorrectionError(
            "technical-state correction changes fields outside its allowlist"
        )
    for key in ALLOWED_VALIDATION_FIELDS - {"workflow_blocker"}:
        if (
            validation[key] != "NOT_APPLICABLE"
            or correction["validation_run_after"][key] != "BLOCKED"
        ):
            raise CorrectionError(
                "technical-state workflow transition must be NOT_APPLICABLE to BLOCKED"
            )
    blocker = correction["validation_run_after"]["workflow_blocker"]
    try:
        blocker_value = json.loads(blocker)
    except (TypeError, json.JSONDecodeError) as error:
        raise CorrectionError("workflow blocker is not structured evidence") from error
    expected_blocker = {
        item["purpose"]: {"locator": item["locator"], "sha256": item["sha256"]}
        for item in correction["evidence"]
    }
    if validation["workflow_blocker"] is not None or blocker_value != expected_blocker:
        raise CorrectionError("workflow blocker does not bind declared evidence")
    _queue_row(
        correction["queue_addition"],
        correction["target"]["root_id"],
        queue_columns,
        correction["evidence"],
    )
    if before_queue_count != correction["base"]["unresolved_queue_count"]:
        raise CorrectionError(
            "technical-state correction unresolved queue base differs"
        )
    return (
        {"retained_receipts": retained, "unresolved_before": before_queue_count},
        validation_columns,
        queue_columns,
    )


def _apply_database(
    candidate: Path,
    correction: dict,
    validation_columns: list[str],
    queue_columns: list[str],
) -> None:
    untouched = _candidate_projection(
        candidate, {"validation_run", "policy_technical_reopen_queue"}
    )
    with sqlite3.connect(
        f"file:{candidate.resolve()}?mode=ro&immutable=1", uri=True
    ) as db:
        _, validation_before = _table_rows(db, "validation_run")
        _, queue_before = _table_rows(db, "policy_technical_reopen_queue")
    with sqlite3.connect(candidate) as db:
        run_id = correction["target"]["validation_run_id"]
        assignments = ",".join(
            f'"{name}"=?' for name in sorted(ALLOWED_VALIDATION_FIELDS)
        )
        values = [
            correction["validation_run_after"][name]
            for name in sorted(ALLOWED_VALIDATION_FIELDS)
        ]
        db.execute(
            f"UPDATE validation_run SET {assignments} WHERE validation_run_id=?",
            (*values, run_id),
        )
        if db.execute("SELECT changes()").fetchone()[0] != 1:
            raise CorrectionError(
                "technical-state correction did not update exactly one validation run"
            )
        queue = correction["queue_addition"]
        db.execute(
            f"INSERT INTO policy_technical_reopen_queue({','.join(f'{name}' for name in queue_columns)}) VALUES({','.join('?' for _ in queue_columns)})",
            tuple(queue[name] for name in queue_columns),
        )
        db.commit()
    with sqlite3.connect(
        f"file:{candidate.resolve()}?mode=ro&immutable=1", uri=True
    ) as db:
        columns, after = _row(
            db,
            "validation_run",
            "validation_run_id",
            correction["target"]["validation_run_id"],
        )
        if columns != validation_columns or after != correction["validation_run_after"]:
            raise CorrectionError("technical-state correction successor row differs")
        queue = db.execute(
            "SELECT * FROM policy_technical_reopen_queue WHERE queue_id=?",
            (correction["queue_addition"]["queue_id"],),
        ).fetchall()
        unresolved = db.execute(
            "SELECT count(*) FROM policy_technical_reopen_queue WHERE status='QUEUED'"
        ).fetchone()[0]
        if (
            len(queue) != 1
            or dict(zip(queue_columns, queue[0])) != correction["queue_addition"]
            or unresolved != correction["base"]["unresolved_queue_count"] + 1
        ):
            raise CorrectionError("technical-state correction queue delta differs")
        _, validation_after = _table_rows(db, "validation_run")
        _, queue_after = _table_rows(db, "policy_technical_reopen_queue")
    expected_validation = [
        correction["validation_run_after"]
        if row["validation_run_id"] == correction["target"]["validation_run_id"]
        else row
        for row in validation_before
    ]
    expected_queue = sorted(
        [*queue_before, correction["queue_addition"]],
        key=lambda row: tuple(str(row[name]) for name in queue_columns),
    )
    if validation_after != expected_validation or queue_after != expected_queue:
        raise CorrectionError("technical-state correction changed an unexpected row")
    if (
        _candidate_projection(
            candidate, {"validation_run", "policy_technical_reopen_queue"}
        )
        != untouched
    ):
        raise CorrectionError(
            "technical-state correction changed an unexpected candidate table"
        )


def _transition_directory(state: Path, transition_id: str) -> Path:
    if not re.fullmatch(r"technical-state:[0-9a-f]{24}", transition_id):
        raise CorrectionError("technical-state transition identifier is invalid")
    return state.resolve() / "technical-state-corrections" / transition_id


def _pending(control: Path) -> dict:
    marker = regular(
        control / "technical-state-pending.json", "technical-state pending commitment"
    )
    value = _record(marker, PENDING_FORMAT, "technical-state pending commitment")
    required = {
        "format_version",
        "control_revision",
        "transition_id",
        "transition_sha256",
        "base_candidate",
        "successor_candidate",
        "base_workflow_sha256",
        "base_workflow_file_sha256",
        "successor_workflow_sha256",
        "transition_directory",
    }
    if {
        key for key in value if not key.startswith("_") and key != "content_hash"
    } != required or value["control_revision"] != CONTROL_REVISION:
        raise CorrectionError("technical-state pending commitment is invalid")
    return value


def _recovery_record_value(pending: dict) -> dict:
    body = {
        "format_version": PENDING_FORMAT,
        "result": "EXACT_PREPARED_TRANSITION_COMPLETED",
        "pending_content_hash": pending["content_hash"],
    }
    return {**body, "content_hash": object_hash(body)}


def _verified_transition_directory(
    directory: Path, pending: dict, candidate_state: Callable[[Path], dict]
) -> dict:
    directory = directory.resolve()
    transition = _record(
        directory / "transition.json", TRANSITION_FORMAT, "technical-state transition"
    )
    if (
        transition["content_hash"] != pending["transition_sha256"]
        or transition["transition_id"] != pending["transition_id"]
    ):
        raise CorrectionError(
            "technical-state transition conflicts with pending commitment"
        )
    commitments = transition.get("committed_reopen_requests")
    if not isinstance(commitments, list) or not commitments:
        raise CorrectionError("technical-state transition lacks queue commitments")
    successor = regular(
        directory / "candidate-successor.db", "prepared correction successor"
    )
    predecessor = regular(
        directory / "candidate-predecessor.db", "prepared correction predecessor"
    )
    workflow = _workflow(
        directory / "workflow-successor.json", "prepared correction workflow"
    )
    if (
        candidate_state(successor) != pending["successor_candidate"]
        or candidate_state(predecessor) != pending["base_candidate"]
        or workflow["workflow_sha256"] != pending["successor_workflow_sha256"]
    ):
        raise CorrectionError(
            "technical-state prepared successor conflicts with commitment"
        )
    return transition


def _verify_successor_database(
    candidate: Path,
    correction: dict,
    *,
    immediate_postcondition: bool = True,
    evidence_project: Path | None = None,
) -> None:
    with sqlite3.connect(
        f"file:{candidate.resolve()}?mode=ro&immutable=1", uri=True
    ) as db:
        _, after = _row(
            db,
            "validation_run",
            "validation_run_id",
            correction["target"]["validation_run_id"],
        )
        if after != correction["validation_run_after"]:
            raise CorrectionError("technical-state transition row differs")
        mappings = db.execute(
            "SELECT root_id FROM validation_run_root WHERE validation_run_id=? ORDER BY root_id",
            (correction["target"]["validation_run_id"],),
        ).fetchall()
        if mappings != [(correction["target"]["root_id"],)]:
            raise CorrectionError("technical-state transition target mapping differs")
        queue_columns = [
            item[1]
            for item in db.execute('PRAGMA table_info("policy_technical_reopen_queue")')
        ]
        queue = db.execute(
            "SELECT * FROM policy_technical_reopen_queue WHERE queue_id=?",
            (correction["queue_addition"]["queue_id"],),
        ).fetchall()
        if len(queue) != 1:
            raise CorrectionError("technical-state transition queue differs")
        observed = dict(zip(queue_columns, queue[0]))
        if immediate_postcondition:
            unresolved = db.execute(
                "SELECT count(*) FROM policy_technical_reopen_queue WHERE status='QUEUED'"
            ).fetchone()[0]
            if (
                observed != correction["queue_addition"]
                or unresolved != correction["base"]["unresolved_queue_count"] + 1
            ):
                raise CorrectionError("technical-state transition queue differs")
        else:
            normalized = dict(observed)
            if observed["status"] == "QUEUED":
                if any(
                    observed[name] is not None
                    for name in (
                        "resolution_evidence_locator",
                        "resolution_evidence_hash",
                        "resolution_rationale",
                        "resolution_content_hash",
                    )
                ):
                    raise CorrectionError(
                        "queued technical-state request contains resolution fields"
                    )
            elif observed["status"] in {"RESOLVED", "SUPERSEDED"}:
                if evidence_project is None:
                    raise CorrectionError(
                        "resolved technical-state request lacks evidence project"
                    )
                locator = observed["resolution_evidence_locator"]
                path = (
                    Path(locator)
                    if Path(str(locator)).is_absolute()
                    else evidence_project / str(locator)
                ).resolve()
                try:
                    path.relative_to(evidence_project.resolve())
                except ValueError as error:
                    raise CorrectionError(
                        "technical-state resolution evidence escapes project"
                    ) from error
                if (
                    file_hash(regular(path, "technical-state resolution evidence"))
                    != observed["resolution_evidence_hash"]
                    or not isinstance(observed["resolution_rationale"], str)
                    or not observed["resolution_rationale"].strip()
                    or observed["resolution_content_hash"]
                    != object_hash(
                        {
                            "queue_id": observed["queue_id"],
                            "status": observed["status"],
                            "evidence_locator": locator,
                            "evidence_hash": observed["resolution_evidence_hash"],
                            "rationale": observed["resolution_rationale"],
                        }
                    )
                ):
                    raise CorrectionError(
                        "technical-state request resolution evidence differs"
                    )
            else:
                raise CorrectionError("technical-state request status is invalid")
            normalized.update(
                status="QUEUED",
                resolution_evidence_locator=None,
                resolution_evidence_hash=None,
                resolution_rationale=None,
                resolution_content_hash=None,
            )
            if normalized != correction["queue_addition"]:
                raise CorrectionError("technical-state transition queue differs")


def recover(
    state: Path,
    candidate: Path,
    profile_identity: dict,
    candidate_state: Callable[[Path], dict],
    restore_candidate: Callable[[Path, dict, Path], dict],
    technical_lineage: Callable[[Path], str],
) -> list[dict]:
    state = state.resolve()
    lock_path = state / "authoritative-integrator.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise CorrectionError(
                "technical-state recovery blocked by active writer lock"
            ) from error
        recovered = []
        for marker in sorted(
            state.glob(".technical-state-correction-*/technical-state-pending.json")
        ):
            control = marker.parent.resolve()
            try:
                control.relative_to(state)
            except ValueError as error:
                raise CorrectionError(
                    "technical-state correction control escapes state"
                ) from error
            pending = _pending(control)
            predecessor = regular(
                control / "candidate-prior.db", "technical-state predecessor candidate"
            )
            predecessor_workflow = regular(
                control / "workflow-prior.json", "technical-state predecessor workflow"
            )
            if (
                candidate_state(predecessor) != pending["base_candidate"]
                or file_hash(predecessor_workflow)
                != pending["base_workflow_file_sha256"]
                or _workflow(
                    predecessor_workflow, "technical-state predecessor workflow"
                )["workflow_sha256"]
                != pending["base_workflow_sha256"]
            ):
                raise CorrectionError("technical-state predecessor material differs")
            correction_root = state / "technical-state-corrections"
            root_kind = entry_kind(correction_root)
            if root_kind not in {None, "DIRECTORY"}:
                raise CorrectionError("technical-state transition root is invalid")
            final = _transition_directory(state, pending["transition_id"])
            if Path(pending["transition_directory"]) != final:
                raise CorrectionError(
                    "technical-state transition escapes its state root"
                )
            preparation = control / "transition-prepared"
            preparation_kind = entry_kind(preparation)
            final_kind = entry_kind(final)
            if preparation_kind not in {None, "DIRECTORY"}:
                raise CorrectionError("technical-state preparation is invalid")
            if final_kind not in {None, "DIRECTORY"}:
                raise CorrectionError("technical-state transition destination is invalid")
            if preparation_kind and final_kind:
                raise CorrectionError(
                    "conflicting technical-state transition copies exist"
                )
            source = preparation if preparation_kind else final
            if entry_kind(source / "control") is not None:
                raise CorrectionError("conflicting correction recovery archive")
            recovery_value = _recovery_record_value(pending)
            recovery_path = source / "recovery.json"
            recovery_kind = entry_kind(recovery_path)
            recovery_reusable = False
            if recovery_kind is not None:
                if source != final or recovery_kind != "REGULAR_FILE":
                    raise CorrectionError(
                        "conflicting correction recovery record"
                    )
                existing_recovery = json.loads(
                    regular(
                        recovery_path, "technical-state recovery record"
                    ).read_text()
                )
                if existing_recovery != recovery_value:
                    raise CorrectionError(
                        "conflicting correction recovery record"
                    )
                recovery_reusable = True
            workflow_path = state / "workflow.json"
            current = candidate_state(candidate)
            existing = _workflow(workflow_path, "campaign workflow")
            if current not in (
                pending["base_candidate"],
                pending["successor_candidate"],
            ):
                raise CorrectionError(
                    "authoritative candidate conflicts with pending correction"
                )
            if existing["workflow_sha256"] not in {
                pending["base_workflow_sha256"],
                pending["successor_workflow_sha256"],
            }:
                raise CorrectionError(
                    "campaign workflow conflicts with pending correction"
                )
            try:
                transition = _verified_transition_directory(
                    source, pending, candidate_state
                )
                correction, approval, _evidence, provider = load_bundle(
                    source / "correction.json",
                    source / "approval.json",
                    transition["project_id"],
                )
                if (
                    correction["content_hash"]
                    != transition["correction"]["content_hash"]
                    or correction["_sha256"] != transition["correction"]["file_sha256"]
                    or approval["content_hash"]
                    != transition["approval"]["content_hash"]
                    or approval["_sha256"] != transition["approval"]["file_sha256"]
                ):
                    raise CorrectionError(
                        "pending technical-state approval chain differs"
                    )
                if (
                    technical_lineage(source / "candidate-successor.db")
                    != transition["technical_candidate_lineage_after"]
                    or correction["technical_candidate_lineage_after"]
                    != transition["technical_candidate_lineage_after"]
                ):
                    raise CorrectionError("pending technical-state lineage differs")
                if (
                    provider != transition["provider_inventory_before"]
                    or provider != transition["provider_inventory_after"]
                ):
                    raise CorrectionError("pending provider inventory differs")
                _verify_successor_database(
                    source / "candidate-successor.db", correction
                )
                _verify_committed_queue(
                    source / "candidate-successor.db",
                    transition["committed_reopen_requests"],
                    Path(profile_identity["locator"]).parent,
                    exact=True,
                )
            except (CorrectionError, FileNotFoundError, json.JSONDecodeError) as error:
                if candidate_state(candidate) == pending["successor_candidate"]:
                    restore_candidate(
                        candidate,
                        pending["base_candidate"],
                        predecessor,
                    )
                if (
                    _workflow(workflow_path, "campaign workflow")["workflow_sha256"]
                    == pending["successor_workflow_sha256"]
                ):
                    descriptor, name = tempfile.mkstemp(
                        dir=state,
                        prefix=".technical-state-workflow-restore.",
                        suffix=".json",
                    )
                    os.close(descriptor)
                    replacement = Path(name)
                    try:
                        shutil.copy2(predecessor_workflow, replacement)
                        if (
                            file_hash(replacement)
                            != pending["base_workflow_file_sha256"]
                        ):
                            raise CorrectionError(
                                "technical-state workflow restore copy differs"
                            )
                        os.replace(replacement, workflow_path)
                    finally:
                        replacement.unlink(missing_ok=True)
                raise CorrectionError(
                    "prepared technical-state transition is invalid"
                ) from error
            if existing["workflow_sha256"] != pending["successor_workflow_sha256"]:
                workflow_stage = regular(
                    control / "workflow-stage.json", "technical-state staged workflow"
                )
                if file_hash(workflow_stage) != file_hash(
                    source / "workflow-successor.json"
                ):
                    raise CorrectionError("technical-state staged workflow differs")
            current = candidate_state(candidate)
            if current == pending["base_candidate"]:
                staged = regular(
                    control / "candidate-stage.db", "technical-state staged candidate"
                )
                if candidate_state(staged) != pending["successor_candidate"]:
                    raise CorrectionError(
                        "technical-state staged candidate is unavailable"
                    )
                os.replace(staged, candidate)
            elif current != pending["successor_candidate"]:
                raise CorrectionError(
                    "authoritative candidate conflicts with pending correction"
                )
            if source == preparation:
                final.parent.mkdir(parents=True, exist_ok=True)
                if entry_kind(final) is not None:
                    raise CorrectionError(
                        "conflicting technical-state transition exists"
                    )
                os.replace(preparation, final)
            if (
                _workflow(workflow_path, "campaign workflow")["workflow_sha256"]
                != pending["successor_workflow_sha256"]
            ):
                os.replace(workflow_stage, workflow_path)
            if candidate_state(candidate) != pending["successor_candidate"]:
                raise CorrectionError("technical-state recovery failed")
            if not recovery_reusable:
                atomic_json(final / "recovery.json", recovery_value)
            archive = final / "control"
            if entry_kind(archive) is not None:
                raise CorrectionError("conflicting correction recovery archive")
            os.replace(control, archive)
            recovered.append(
                {
                    "result": "TECHNICAL_STATE_CORRECTION_COMPLETED",
                    "transition_id": transition["transition_id"],
                    "candidate_sha256": pending["successor_candidate"]["sha256"],
                }
            )
        return recovered


def verify_transition(
    state: Path,
    candidate: Path,
    profile: dict,
    profile_identity: dict,
    workflow: dict,
    receipts: dict[str, dict],
    current_technical_inputs: str,
    technical_lineage: Callable[[Path], str],
) -> dict:
    binding = workflow.get("technical_state_transition")
    if set(binding or {}) != {"transition_id", "locator", "sha256"}:
        raise CorrectionError("workflow does not contain a technical-state transition")
    transition = _record(
        Path(binding["locator"]), TRANSITION_FORMAT, "technical-state transition"
    )
    transition_directory = _transition_directory(state, binding["transition_id"])
    if entry_kind(transition_directory.parent) != "DIRECTORY" or entry_kind(
        transition_directory
    ) != "DIRECTORY":
        raise CorrectionError("workflow technical-state transition directory is invalid")
    expected_locator = transition_directory / "transition.json"
    if Path(binding["locator"]) != expected_locator:
        raise CorrectionError("workflow technical-state transition escapes state")
    if (
        transition["transition_id"] != binding["transition_id"]
        or transition["content_hash"] != binding["sha256"]
    ):
        raise CorrectionError("workflow technical-state transition identity mismatch")
    if workflow.get("execution_mode") == "TECHNICAL_STATE_CORRECTION" and (
        transition["successor_candidate"] != _candidate_state(candidate)
        or workflow.get("candidate") != transition["successor_candidate"]
    ):
        raise CorrectionError("technical-state transition candidate differs")
    if (
        transition["technical_candidate_lineage_after"] != technical_lineage(candidate)
        or workflow.get("technical_candidate_lineage_sha256")
        != transition["technical_candidate_lineage_after"]
    ):
        raise CorrectionError("technical-state transition lineage differs")
    if (
        transition["technical_input_lineage_sha256"] != current_technical_inputs
        or workflow.get("technical_input_lineage_sha256") != current_technical_inputs
    ):
        raise CorrectionError("technical-state transition input lineage differs")
    if (
        workflow.get("profile_sha256") != profile_identity["sha256"]
        or transition["profile_sha256"] != profile_identity["sha256"]
    ):
        raise CorrectionError("technical-state transition profile differs")
    base_workflow = transition.get("base_workflow", {})
    if (
        set(base_workflow) != {"locator", "file_sha256", "workflow_sha256"}
        or file_hash(
            regular(Path(base_workflow["locator"]), "retained predecessor workflow")
        )
        != base_workflow["file_sha256"]
        or _workflow(Path(base_workflow["locator"]), "retained predecessor workflow")[
            "workflow_sha256"
        ]
        != base_workflow["workflow_sha256"]
    ):
        raise CorrectionError("technical-state predecessor workflow changed")
    correction, approval, _evidence, projection = load_bundle(
        Path(transition["correction"]["locator"]),
        Path(transition["approval"]["locator"]),
        transition["project_id"],
    )
    if (
        correction["content_hash"] != transition["correction"]["content_hash"]
        or correction["_sha256"] != transition["correction"]["file_sha256"]
        or approval["content_hash"] != transition["approval"]["content_hash"]
        or approval["_sha256"] != transition["approval"]["file_sha256"]
        or approval["correction_content_hash"] != correction["content_hash"]
    ):
        raise CorrectionError("technical-state transition approval chain differs")
    if (
        projection != transition["provider_inventory_before"]
        or projection != transition["provider_inventory_after"]
    ):
        raise CorrectionError("technical-state transition provider inventory changed")
    if (
        correction["base"]["provider_inventory_sha256"]
        != projection["inventory_sha256"]
        or correction["base"]["provider_counters"] != projection["counters"]
        or correction["provider_invariants_after"]
        != {
            "inventory_sha256": projection["inventory_sha256"],
            "counters": projection["counters"],
        }
    ):
        raise CorrectionError("technical-state transition provider base differs")
    if (
        _receipt_provenance(profile, receipts)
        != transition["retained_provider_receipts"]
    ):
        raise CorrectionError("retained provider receipt provenance changed")
    if (
        _all_receipt_provenance(profile, receipts)
        != transition["retained_prerequisites"]
    ):
        raise CorrectionError("retained receipt/context/output provenance changed")
    snapshot = transition_directory / "candidate-successor.db"
    if _candidate_state(snapshot) != transition["successor_candidate"]:
        raise CorrectionError("technical-state transition snapshot changed")
    _verify_successor_database(snapshot, correction)
    commitments = transition.get("committed_reopen_requests")
    if not isinstance(commitments, list) or not commitments:
        raise CorrectionError("technical-state transition lacks queue commitments")
    _verify_committed_queue(
        snapshot,
        commitments,
        Path(profile_identity["locator"]).parent,
        exact=True,
    )
    _verify_successor_database(
        candidate,
        correction,
        immediate_postcondition=False,
        evidence_project=Path(profile_identity["locator"]).parent,
    )
    _verify_committed_queue(
        candidate,
        [*commitments, *_policy_receipt_queue_commitments(profile, receipts)],
        Path(profile_identity["locator"]).parent,
    )
    return transition


def apply(
    *,
    correction_path: Path,
    approval_path: Path,
    project_id: str,
    project: Path,
    state: Path,
    candidate: Path,
    profile: dict,
    profile_identity: dict,
    prior_workflow: dict,
    receipts: dict[str, dict],
    current_technical_inputs: str,
    technical_lineage: Callable[[Path], str],
    candidate_state: Callable[[Path], dict],
) -> dict:
    correction, approval, _evidence, provider_before = load_bundle(
        correction_path, approval_path, project_id
    )
    if not bool(correction.get("base")):
        raise CorrectionError("technical-state correction lacks a base")
    inventory_sha = provider_before["inventory_sha256"]
    if (
        correction["base"]["provider_inventory_sha256"] != inventory_sha
        or correction["base"]["provider_counters"] != provider_before["counters"]
        or correction["provider_invariants_after"]
        != {"inventory_sha256": inventory_sha, "counters": provider_before["counters"]}
    ):
        raise CorrectionError("technical-state correction provider base differs")
    _require_provider_files(
        {
            key: value
            for key, value in receipts.items()
            if key
            in {
                item["stage_id"]
                for item in profile["automation"]["stages"]
                if item["phase"].startswith("METIS_")
            }
        },
        provider_before,
    )
    transition_id = f"technical-state:{correction['content_hash'][:24]}"
    final = _transition_directory(state, transition_id)
    root_kind = entry_kind(final.parent)
    if root_kind not in {None, "DIRECTORY"}:
        raise CorrectionError("technical-state transition root is invalid")
    final_kind = entry_kind(final)
    if final_kind is not None and final_kind != "DIRECTORY":
        raise CorrectionError("technical-state transition destination is invalid")
    if final_kind == "DIRECTORY":
        workflow = _workflow(state / "workflow.json", "campaign workflow")
        transition = verify_transition(
            state,
            candidate,
            profile,
            profile_identity,
            workflow,
            receipts,
            current_technical_inputs,
            technical_lineage,
        )
        return {
            "result": "REUSED",
            "transition_id": transition["transition_id"],
            "candidate": candidate_state(candidate),
            "workflow_sha256": workflow["workflow_sha256"],
        }
    prepared, validation_columns, queue_columns = _verify_before(
        candidate,
        profile,
        profile_identity,
        prior_workflow,
        correction,
        receipts,
        current_technical_inputs,
        technical_lineage,
    )
    descriptor = tempfile.mkdtemp(dir=state, prefix=".technical-state-correction-")
    control = Path(descriptor)
    preparation = control / "transition-prepared"
    preparation.mkdir()
    try:
        shutil.copy2(candidate, control / "candidate-prior.db")
        shutil.copy2(candidate, control / "candidate-stage.db")
        shutil.copy2(prior_workflow["_locator"], control / "workflow-prior.json")
        _apply_database(
            control / "candidate-stage.db",
            correction,
            validation_columns,
            queue_columns,
        )
        after_lineage = technical_lineage(control / "candidate-stage.db")
        if after_lineage != correction["technical_candidate_lineage_after"]:
            raise CorrectionError("technical-state successor lineage differs")
        provider_inventory, provider_after = _verify_inventory(
            correction["provider_inventory"], Path(correction["_locator"]).parent
        )
        if provider_after != provider_before:
            raise CorrectionError(
                "provider checkpoints changed while preparing correction"
            )
        successor = candidate_state(control / "candidate-stage.db")
        shutil.copy2(
            control / "candidate-prior.db", preparation / "candidate-predecessor.db"
        )
        shutil.copy2(
            control / "candidate-stage.db", preparation / "candidate-successor.db"
        )
        shutil.copy2(
            prior_workflow["_locator"], preparation / "workflow-predecessor.json"
        )
        shutil.copy2(correction["_locator"], preparation / "correction.json")
        shutil.copy2(approval["_locator"], preparation / "approval.json")
        retained = prepared["retained_receipts"]
        transition = {
            "format_version": TRANSITION_FORMAT,
            "control_revision": CONTROL_REVISION,
            "transition_id": transition_id,
            "project_id": project_id,
            "profile_sha256": profile_identity["sha256"],
            "base_candidate": correction["base"]["candidate"],
            "successor_candidate": successor,
            "base_workflow_sha256": prior_workflow["workflow_sha256"],
            "base_workflow_file_sha256": correction["base"]["workflow_file_sha256"],
            "base_workflow": {
                "locator": str(final / "workflow-predecessor.json"),
                "file_sha256": correction["base"]["workflow_file_sha256"],
                "workflow_sha256": prior_workflow["workflow_sha256"],
            },
            "correction": {
                "locator": str(final / "correction.json"),
                "content_hash": correction["content_hash"],
                "file_sha256": correction["_sha256"],
            },
            "approval": {
                "locator": str(final / "approval.json"),
                "content_hash": approval["content_hash"],
                "file_sha256": approval["_sha256"],
                "authorization_claim": "RECORDED_DECISION; NOT_CRYPTOGRAPHIC_PROOF_BY_HASH_ALONE",
            },
            "root_id": correction["target"]["root_id"],
            "validation_run_id": correction["target"]["validation_run_id"],
            "validation_run_before": correction["validation_run_before"],
            "validation_run_after": correction["validation_run_after"],
            "queue_addition": correction["queue_addition"],
            "committed_reopen_requests": _queue_commitments(
                control / "candidate-stage.db"
            ),
            "technical_candidate_lineage_before": correction["base"][
                "technical_candidate_lineage_sha256"
            ],
            "technical_candidate_lineage_after": after_lineage,
            "technical_input_lineage_sha256": current_technical_inputs,
            "provider_inventory_before": provider_before,
            "provider_inventory_after": provider_after,
            "retained_provider_receipts": retained,
            "retained_prerequisites": _all_receipt_provenance(profile, receipts),
        }
        transition["content_hash"] = object_hash(transition)
        atomic_json(preparation / "transition.json", transition)
        successor_workflow = {
            key: value
            for key, value in prior_workflow.items()
            if not key.startswith("_") and key != "workflow_sha256"
        }
        successor_workflow.update(
            {
                "candidate": successor,
                "technical_candidate_lineage_sha256": after_lineage,
                "technical_input_lineage_sha256": current_technical_inputs,
                "technical_lineage_version": prior_workflow[
                    "technical_lineage_version"
                ],
                "execution_mode": "TECHNICAL_STATE_CORRECTION",
                "provider_phase_dispatches_permitted": 0,
                "base_workflow_sha256": prior_workflow["workflow_sha256"],
                "technical_state_transition": {
                    "transition_id": transition_id,
                    "locator": str(final / "transition.json"),
                    "sha256": transition["content_hash"],
                },
            }
        )
        successor_workflow["workflow_sha256"] = object_hash(successor_workflow)
        atomic_json(preparation / "workflow-successor.json", successor_workflow)
        atomic_json(control / "workflow-stage.json", successor_workflow)
        pending = {
            "format_version": PENDING_FORMAT,
            "control_revision": CONTROL_REVISION,
            "transition_id": transition_id,
            "transition_sha256": transition["content_hash"],
            "base_candidate": correction["base"]["candidate"],
            "successor_candidate": successor,
            "base_workflow_sha256": prior_workflow["workflow_sha256"],
            "base_workflow_file_sha256": correction["base"]["workflow_file_sha256"],
            "successor_workflow_sha256": successor_workflow["workflow_sha256"],
            "transition_directory": str(final),
        }
        pending["content_hash"] = object_hash(pending)
        atomic_json(control / "technical-state-pending.json", pending)
        os.replace(control / "candidate-stage.db", candidate)
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(preparation, final)
        os.replace(control / "workflow-stage.json", state / "workflow.json")
        os.replace(control, final / "control")
        return {
            "result": "TECHNICAL_STATE_CORRECTION_COMPLETED",
            "transition_id": transition_id,
            "candidate": successor,
            "workflow_sha256": successor_workflow["workflow_sha256"],
        }
    except BaseException:
        # Prepared state is deliberately retained for the next locked recovery.
        raise


def apply_with_lock(**arguments) -> dict:
    """Serialize an explicit correction with ordinary authoritative writers."""
    state = Path(arguments["state"]).resolve()
    lock_path = state / "authoritative-integrator.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise CorrectionError(
                "technical-state correction blocked by active writer lock"
            ) from error
        return apply(**arguments)
