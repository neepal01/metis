"""Offline, approval-bound adjudication of existing scanner records.

This module never invokes an adapter.  It validates an immutable predecessor,
prepared successor and complete reviewed cohort, then publishes the exact
successor under the campaign writer lock.  Provider outputs are prerequisites,
not receipts for the successor.
"""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from typing import Callable

from metis_firmware_campaign import technical_state_correction as state_control


CONTROL_REVISION = "6.11.0-REVIEW"
ADJUDICATION_FORMAT = "firmware-downstream-technical-adjudication-v1"
COHORT_FORMAT = "firmware-downstream-technical-cohort-v1"
APPROVAL_FORMAT = "firmware-downstream-technical-approval-v1"
REVIEW_FORMAT = "firmware-downstream-technical-review-v1"
EVIDENCE_FORMAT = "firmware-downstream-technical-evidence-v1"
DEDUP_FORMAT = "firmware-downstream-deduplication-v1"
TRANSITION_FORMAT = "firmware-downstream-technical-transition-v1"
PENDING_FORMAT = "firmware-downstream-technical-pending-v1"
TECHNICAL_LINEAGE_VERSION = "sqlite-typed-v2"

ALLOWED_INSERT_TABLES = {
    "call_edge",
    "call_path",
    "campaign_record_root",
    "code_location",
    "fingerprint",
    "fp_no_bug_audit",
    "review_binding",
    "review_run",
    "root",
    "root_fingerprint_field",
    "root_property_relation",
    "root_threat_assessment",
    "terminal_decision_capsule",
}
ALLOWED_SUBJECT_FIELDS = {"technical_class", "decision_status"}
TERMINAL_CLASSES = {"VALID_VULNERABILITY", "HARDENING", "NO_BUG"}
PROOF_FIELDS = {
    "attacker_source", "input_delivery", "missing_control", "controlled_object",
    "security_sink", "concrete_effect", "boundary_configuration",
}
DEDUP_LAYERS = {
    "PROJECT_FINDINGS", "PROJECT_REPRODUCERS", "PROMOTED_ROOTS",
    "HISTORICAL_TICKETS_POCS", "CURRENT_TICKETS",
}
EXACT_COMPARISONS = {
    "attacker_source", "entry_flow", "missing_control", "sink", "effect",
    "source", "configuration", "boundary", "dependencies",
}
COUNTEREVIDENCE_CATEGORIES = {
    "CHECK_DOMINATES_SINK", "PRODUCER_CANNOT_GENERATE",
    "GOVERNED_BUILD_EXCLUDES_PATH", "ARCHITECTURE_OR_INTEGER_WIDTH_DISPROVES",
    "OBJECT_LIFETIME_REMAINS_VALID", "SCANNER_WRONG_OBJECT_OR_API",
    "CLAIMED_OPERATION_SINK_OR_EFFECT_ABSENT",
}
INVALIDATED_DOWNSTREAM_PHASES = {
    "PACKET_VALIDATION", "ANALYSIS_INTEGRATION", "AUTHORITATIVE_INTEGRATION", "REPRODUCTION",
    "SEVERITY_CALIBRATION", "POLICY_RECONCILIATION",
    "EXISTING_REPORT_FOLLOWUP", "PACKAGE_EXPORT",
    "POPULATION_RECONCILIATION", "POPULATION_SCOPED_REPORTING",
    "EVIDENCE_PACKAGE_SEAL", "PACKAGE_AND_SEAL",
}


class AdjudicationError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def object_hash(value: object) -> str:
    import hashlib

    return hashlib.sha256(canonical(value)).hexdigest()


def file_hash(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular(path: Path, label: str) -> Path:
    kind = state_control.entry_kind(path)
    if kind != "REGULAR_FILE":
        raise AdjudicationError(f"{label} must be a regular nonsymlink file")
    return path


def atomic_json(path: Path, value: object) -> None:
    state_control.atomic_json(path, value)


def _record(path: Path, expected: str, label: str) -> dict:
    path = regular(path.resolve(), label)
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get("format_version") != expected:
        raise AdjudicationError(f"unsupported {label} format")
    claimed = value.pop("content_hash", None)
    if claimed != object_hash(value):
        raise AdjudicationError(f"{label} content hash mismatch")
    value["content_hash"] = claimed
    value["_locator"] = str(path)
    value["_sha256"] = file_hash(path)
    return value


def _bound(base: Path, binding: dict, label: str) -> dict:
    if set(binding) != {"locator", "sha256", "size"}:
        raise AdjudicationError(f"invalid {label} binding")
    locator = Path(binding["locator"])
    if not locator.is_absolute():
        raise AdjudicationError(f"{label} binding must use an absolute locator")
    locator = regular(locator.resolve(), label)
    observed = {"sha256": file_hash(locator), "size": locator.stat().st_size}
    if observed != {key: binding[key] for key in observed}:
        raise AdjudicationError(f"{label} binding changed")
    return {**binding, "resolved_locator": str(locator)}


def _typed(value: object) -> dict:
    if value is None:
        return {"type": "NULL"}
    if isinstance(value, bytes):
        return {"type": "BLOB", "hex": value.hex()}
    if isinstance(value, str):
        return {"type": "TEXT", "value": value}
    if isinstance(value, int):
        return {"type": "INTEGER", "value": value}
    if isinstance(value, float):
        return {"type": "REAL", "hex": value.hex()}
    raise AdjudicationError("unsupported SQLite storage class")


def _typed_row(columns: list[str], row: tuple) -> dict:
    return {column: _typed(value) for column, value in zip(columns, row)}


def _tables(candidate: Path) -> dict[str, dict]:
    regular(candidate.resolve(), "candidate database")
    with sqlite3.connect(f"file:{candidate.resolve()}?mode=ro&immutable=1", uri=True) as db:
        result = {}
        catalogue = list(
            db.execute("SELECT name,sql FROM sqlite_master WHERE type='table'")
        )
        names = sorted(
            name
            for name, _sql in catalogue
            if not name.startswith("sqlite_")
        )
        for table in names:
            info = db.execute(f'PRAGMA table_info("{table}")').fetchall()
            columns = [item[1] for item in info]
            primary = [item[1] for item in sorted(info, key=lambda item: item[5]) if item[5]]
            if not primary:
                primary = columns
            select = ",".join(f'"{item}"' for item in columns)
            rows = db.execute(f'SELECT {select} FROM "{table}"').fetchall()
            indexed = {}
            ordered = sorted(rows, key=lambda row: canonical(_typed_row(columns, row)))
            for ordinal, row in enumerate(ordered):
                raw = dict(zip(columns, row))
                identity = {item: _typed(raw[item]) for item in primary}
                if primary == columns:
                    identity = {"row": identity, "ordinal": ordinal}
                key = object_hash(identity)
                if key in indexed:
                    raise AdjudicationError(f"candidate {table} has ambiguous rows")
                indexed[key] = {"raw": raw, "typed": _typed_row(columns, row)}
            result[table] = {"columns": columns, "primary": primary, "rows": indexed}
        return result


def _row_hash(row: dict) -> str:
    return object_hash(row["typed"])


def _diff(predecessor: Path, successor: Path) -> dict:
    before, after = _tables(predecessor), _tables(successor)
    if set(before) != set(after):
        raise AdjudicationError("adjudication may not change candidate schema")
    result = {}
    for table in sorted(before):
        if before[table]["columns"] != after[table]["columns"]:
            raise AdjudicationError(f"adjudication changed {table} columns")
        old, new = before[table]["rows"], after[table]["rows"]
        inserted = [new[key] for key in sorted(set(new) - set(old))]
        deleted = [old[key] for key in sorted(set(old) - set(new))]
        updated = [
            (old[key], new[key])
            for key in sorted(set(old) & set(new))
            if old[key]["typed"] != new[key]["typed"]
        ]
        if inserted or deleted or updated:
            result[table] = {"inserted": inserted, "deleted": deleted, "updated": updated}
    return result


def _subject_rows(candidate: Path, import_id: str) -> dict[str, dict]:
    with sqlite3.connect(f"file:{candidate.resolve()}?mode=ro&immutable=1", uri=True) as db:
        columns = [row[1] for row in db.execute('PRAGMA table_info("campaign_subject")')]
        rows = db.execute(
            'SELECT * FROM "campaign_subject" WHERE import_id=?', (import_id,)
        ).fetchall()
    return {
        dict(zip(columns, row))["record_id"]: {
            "raw": dict(zip(columns, row)),
            "typed": _typed_row(columns, row),
        }
        for row in rows
    }


def _root_exists(tables: dict, root_id: str) -> bool:
    return any(
        item["raw"].get("root_id") == root_id
        for table in ("root",)
        for item in tables.get(table, {}).get("rows", {}).values()
    )


def _build_commitments(tables: dict, build_id: object) -> tuple[str, str]:
    builds = [
        row["raw"]
        for row in tables.get("build_capsule", {}).get("rows", {}).values()
        if row["raw"].get("build_id") == build_id
    ]
    if len(builds) != 1:
        raise AdjudicationError("terminal capsule references an unavailable build")
    configuration = builds[0].get("configuration_hash")
    dependencies = sorted(
        (
            {
                key: row["raw"].get(key)
                for key in (
                    "binding_id", "dependency_kind", "locator", "content_hash",
                    "status", "reason"
                )
            }
            for row in tables.get("exact_build_binding", {}).get("rows", {}).values()
            if row["raw"].get("build_id") == build_id
        ),
        key=canonical,
    )
    if (
        not _contains_hash(configuration)
        or not dependencies
        or any(
            not item["binding_id"]
            or not item["dependency_kind"]
            or not item["locator"]
            or not _contains_hash(item["content_hash"])
            or not item["status"]
            or not item["reason"]
            for item in dependencies
        )
    ):
        raise AdjudicationError("terminal capsule build dependency manifest is invalid")
    return configuration, object_hash(
        {"build_id": build_id, "dependencies": dependencies}
    )


def _inserted(diff: dict, table: str) -> list[dict]:
    return diff.get(table, {}).get("inserted", [])


def _bind_review(base: Path, binding: dict, entry: dict, role: str) -> dict:
    artifact = _bound(base, binding, f"{role.lower()} review evidence")
    review = _record(Path(artifact["resolved_locator"]), REVIEW_FORMAT, f"{role.lower()} review")
    if review["_sha256"] != artifact["sha256"] or any(
        review.get(key) != value
        for key, value in {
            "project_id": entry["project_id"],
            "record_id": entry["record_id"],
            "technical_class": entry["technical_class"],
            "review_role": role,
            "subject_row_sha256": entry["before_row_sha256"],
        }.items()
    ):
        raise AdjudicationError(f"{role.lower()} review does not assess the exact decision")
    if not review.get("reviewer_identity") or not review.get("reviewed_at"):
        raise AdjudicationError(f"{role.lower()} review lacks human/model provenance")
    return review


def _source_ranges(value: object) -> bool:
    required = {
        "component_id", "revision", "path", "start_line", "end_line", "content_hash"
    }
    return (
        isinstance(value, list)
        and bool(value)
        and all(
            isinstance(item, dict)
            and set(item) == required
            and isinstance(item["component_id"], str)
            and bool(item["component_id"])
            and isinstance(item["revision"], str)
            and bool(item["revision"])
            and isinstance(item["path"], str)
            and bool(item["path"])
            and isinstance(item["start_line"], int)
            and isinstance(item["end_line"], int)
            and 1 <= item["start_line"] <= item["end_line"]
            and isinstance(item["content_hash"], str)
            and len(item["content_hash"]) == 64
            and not (set(item["content_hash"]) - set("0123456789abcdef"))
            for item in value
        )
    )


def _contains_hash(value: object) -> bool:
    if isinstance(value, dict):
        return any(_contains_hash(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_hash(item) for item in value)
    return isinstance(value, str) and len(value) == 64 and not (
        set(value) - set("0123456789abcdef")
    )


def _verify_decisive_sources(
    ranges: object,
    source_checkouts: dict[str, str] | None,
    source_revisions: dict[str, str] | None,
) -> list[dict]:
    if not _source_ranges(ranges) or not source_checkouts or not source_revisions:
        raise AdjudicationError("terminal decision lacks verified exact-source bindings")
    result = {}
    for item in ranges:
        component = item["component_id"]
        if component not in source_checkouts or item["revision"] != source_revisions.get(component):
            raise AdjudicationError("decisive source component/revision differs")
        checkout = Path(source_checkouts[component]).resolve()
        if state_control.entry_kind(checkout) != "DIRECTORY":
            raise AdjudicationError("decisive source checkout is unavailable")
        source = (checkout / item["path"]).resolve()
        try:
            source.relative_to(checkout)
        except ValueError as error:
            raise AdjudicationError("decisive source escapes its checkout") from error
        source = regular(source, "decisive source")
        identity = {
            "component_id": component,
            "revision": item["revision"],
            "path": item["path"],
            "resolved_locator": str(source),
            "sha256": file_hash(source),
            "size": source.stat().st_size,
        }
        if identity["sha256"] != item["content_hash"]:
            raise AdjudicationError("decisive source bytes differ")
        if len(source.read_text(errors="replace").splitlines()) < item["end_line"]:
            raise AdjudicationError("decisive source range exceeds the source file")
        result[(component, item["path"])] = identity
    return [result[key] for key in sorted(result)]


def _verify_source_inventory(
    inventory: object,
    source_checkouts: dict[str, str] | None,
    source_revisions: dict[str, str] | None,
) -> None:
    if not isinstance(inventory, list) or not inventory:
        raise AdjudicationError("adjudication transition lacks decisive source inventory")
    observed = []
    for item in inventory:
        if not isinstance(item, dict) or set(item) != {
            "component_id", "revision", "path", "resolved_locator", "sha256", "size"
        }:
            raise AdjudicationError("adjudication source inventory is invalid")
        component = item["component_id"]
        if source_revisions is not None and item["revision"] != source_revisions.get(component):
            raise AdjudicationError("adjudication source inventory component/revision differs")
        if source_checkouts is None:
            source = Path(item["resolved_locator"]).resolve()
        else:
            if component not in source_checkouts:
                raise AdjudicationError("adjudication source inventory component differs")
            checkout = Path(source_checkouts[component]).resolve()
            source = (checkout / item["path"]).resolve()
            try:
                source.relative_to(checkout)
            except ValueError as error:
                raise AdjudicationError("decisive source escapes its checkout") from error
        source = regular(source, "decisive source")
        observed.append({**item, "resolved_locator": str(source.resolve()), "sha256": file_hash(source), "size": source.stat().st_size})
    if observed != inventory:
        raise AdjudicationError("adjudication decisive source bytes changed")


def _review_set_hash(record_id: str, reviews: list[tuple[str, str, dict]]) -> str:
    return object_hash(
        {
            "record_id": record_id,
            "reviews": [
                {"role": role, "review_id": review_id, "sha256": review["_sha256"]}
                for role, review_id, review in reviews
            ],
        }
    )


def _validate_successor(
    predecessor: Path,
    successor: Path,
    cohort: dict,
    project_id: str,
    source_checkouts: dict[str, str] | None = None,
    source_revisions: dict[str, str] | None = None,
) -> dict:
    with sqlite3.connect(successor) as db:
        integrity = db.execute("PRAGMA integrity_check").fetchone()
        if integrity != ("ok",) or db.execute("PRAGMA foreign_key_check").fetchone():
            raise AdjudicationError("prepared successor failed SQLite integrity checks")
    diff = _diff(predecessor, successor)
    unexpected = set(diff) - ({"campaign_subject"} | ALLOWED_INSERT_TABLES)
    if unexpected:
        raise AdjudicationError(f"adjudication changes forbidden tables: {sorted(unexpected)}")
    for table in set(diff) - {"campaign_subject"}:
        if diff[table]["deleted"] or diff[table]["updated"]:
            raise AdjudicationError(f"adjudication may only add {table} rows")
    if diff.get("campaign_subject", {}).get("deleted") or diff.get(
        "campaign_subject", {}
    ).get("inserted"):
        raise AdjudicationError("adjudication may not add or remove campaign subjects")

    population = cohort.get("scanner_population")
    if not isinstance(population, dict) or set(population) != {
        "import_id", "record_count", "record_ids_sha256", "records"
    }:
        raise AdjudicationError("adjudication cohort lacks a complete scanner population")
    entries = population["records"]
    if not isinstance(entries, list) or len(entries) != population["record_count"]:
        raise AdjudicationError("scanner population count differs")
    before_rows = _subject_rows(predecessor, population["import_id"])
    after_rows = _subject_rows(successor, population["import_id"])
    ids = [entry.get("record_id") for entry in entries]
    if (
        set(before_rows) != set(after_rows)
        or set(ids) != set(before_rows)
        or len(ids) != len(set(ids))
        or object_hash(sorted(ids)) != population["record_ids_sha256"]
    ):
        raise AdjudicationError("scanner population does not bind the exact import")
    selected = {entry["record_id"]: entry for entry in entries if entry.get("action") == "ADJUDICATE"}
    if not selected or any(entry.get("action") not in {"ADJUDICATE", "RETAIN"} for entry in entries):
        raise AdjudicationError("cohort must explicitly classify every scanner record")
    changed = {}
    for old, new in diff.get("campaign_subject", {}).get("updated", []):
        changed[new["raw"]["record_id"]] = (old, new)
    if set(changed) != set(selected):
        raise AdjudicationError("selected records differ from changed subjects")

    base = Path(cohort["_locator"]).parent
    predecessor_tables = _tables(predecessor)
    successor_tables = _tables(successor)
    created_roots = {
        row["raw"].get("root_id") for row in _inserted(diff, "root")
    }
    if None in created_roots:
        raise AdjudicationError("new root material lacks a root identity")
    rooted_tables = (
        "fingerprint", "code_location", "call_path", "root_fingerprint_field",
        "root_property_relation", "root_threat_assessment",
    )
    for table in rooted_tables:
        inserted_roots = {
            row["raw"].get("root_id") for row in _inserted(diff, table)
        }
        if inserted_roots - created_roots:
            raise AdjudicationError(f"{table} inserts collateral root material")
        if created_roots and table in successor_tables and inserted_roots != created_roots:
            raise AdjudicationError("new roots lack complete promotion material")
    call_paths = {
        row["raw"].get("call_path_id") for row in _inserted(diff, "call_path")
    }
    call_edges = {
        row["raw"].get("call_path_id") for row in _inserted(diff, "call_edge")
    }
    if call_edges - call_paths or (call_paths and "call_edge" in successor_tables and call_edges != call_paths):
        raise AdjudicationError("call-edge insert is not bound to a new root path")
    existing_fingerprints = {
        row["raw"].get("fingerprint_hash")
        for row in predecessor_tables.get("root_fingerprint_field", {}).get("rows", {}).values()
    }
    new_fingerprints_by_root = {
        row["raw"].get("root_id"): row["raw"].get("fingerprint_hash")
        for row in _inserted(diff, "root_fingerprint_field")
    }
    new_fingerprints = set(new_fingerprints_by_root.values())
    if existing_fingerprints & new_fingerprints:
        raise AdjudicationError("related variants may not reuse an exact fingerprint")
    mapping_rows = [row["raw"] for row in _inserted(diff, "campaign_record_root")]
    mapping = {
        row.get("record_id"): row
        for row in mapping_rows
    }
    capsules = {
        row["raw"].get("record_id"): row["raw"]
        for row in _inserted(diff, "terminal_decision_capsule")
    }
    audits = {
        row["raw"].get("record_id"): row["raw"]
        for row in _inserted(diff, "fp_no_bug_audit")
    }
    bindings = [row["raw"] for row in _inserted(diff, "review_binding")]
    inserted_runs = [row["raw"] for row in _inserted(diff, "review_run")]
    runs = [row["raw"] for row in successor_tables.get("review_run", {}).get("rows", {}).values()]
    review_runs = {row.get("review_id"): row for row in runs}
    expected_review_ids = {
        entry.get(kind)
        for entry in selected.values()
        for kind in ("primary_review_id", "blind_review_id")
        if entry.get(kind)
    }
    if not expected_review_ids or {
        row.get("review_id") for row in inserted_runs
    } != expected_review_ids:
        raise AdjudicationError("review-run insert is not bound to the selected cohort")
    expected_positive_roots = {
        entry.get("root_disposition", {}).get("root_id")
        for entry in selected.values()
        if entry.get("technical_class") != "NO_BUG"
        and entry.get("root_disposition", {}).get("kind") in {"RELATED_VARIANT", "NOVEL"}
    }
    expected_created_count = sum(
        entry.get("technical_class") != "NO_BUG"
        and entry.get("root_disposition", {}).get("kind") in {"RELATED_VARIANT", "NOVEL"}
        for entry in selected.values()
    )
    if created_roots != expected_positive_roots:
        raise AdjudicationError("created roots differ from the reviewed dispositions")
    if len(created_roots) != expected_created_count:
        raise AdjudicationError("related variants may not merge into one new root")
    positive_ids = {
        record_id for record_id, entry in selected.items()
        if entry.get("technical_class") != "NO_BUG"
    }
    if (
        len(mapping_rows) != len(positive_ids)
        or len(capsules) != len(selected)
        or set(mapping) != positive_ids
        or set(capsules) != set(selected)
    ):
        raise AdjudicationError("inserted record/root evidence differs from the selected cohort")
    no_bug_ids = {
        record_id for record_id, entry in selected.items()
        if entry.get("technical_class") == "NO_BUG"
    }
    if set(audits) != no_bug_ids:
        raise AdjudicationError("NO_BUG audits differ from the selected cohort")
    capsule_ids = {row.get("capsule_id") for row in capsules.values()}
    allowed_review_subjects = {
        "SCANNER_RECORD": set(selected),
        "EVIDENCE_CAPSULE": capsule_ids,
        "ROOT": created_roots,
    }
    if any(
        row.get("review_id") not in expected_review_ids
        or row.get("subject_id") not in allowed_review_subjects.get(row.get("subject_kind"), set())
        for row in bindings
    ):
        raise AdjudicationError("review-binding insert is not bound to selected cohort material")

    decisive_source_files = {}
    for record_id, entry in selected.items():
        old, new = changed[record_id]
        if entry.get("project_id") != project_id:
            raise AdjudicationError("cohort entry project differs")
        if _row_hash(old) != entry.get("before_row_sha256") or _row_hash(new) != entry.get("after_row_sha256"):
            raise AdjudicationError("cohort row commitment differs")
        changed_fields = {
            key for key in old["raw"] if old["raw"][key] != new["raw"][key]
        }
        if not changed_fields or not changed_fields <= ALLOWED_SUBJECT_FIELDS:
            raise AdjudicationError("scanner subject change exceeds the allowlist")
        if old["raw"].get("technical_class") != "DEFERRED" or old["raw"].get("decision_status") != "NON_TERMINAL":
            raise AdjudicationError("selected scanner subject has unexpected predecessor values")
        technical_class = new["raw"].get("technical_class")
        if technical_class not in TERMINAL_CLASSES or new["raw"].get("decision_status") != "TERMINAL":
            raise AdjudicationError("selected scanner subject lacks a terminal adjudication")
        if entry.get("technical_class") != technical_class:
            raise AdjudicationError("cohort technical decision differs")
        technical = _bound(base, entry.get("technical_evidence", {}), "technical evidence")
        evidence = _record(Path(technical["resolved_locator"]), EVIDENCE_FORMAT, "technical evidence")
        if evidence["_sha256"] != technical["sha256"] or any(
            evidence.get(key) != value
            for key, value in {
                "project_id": project_id,
                "record_id": record_id,
                "technical_class": technical_class,
            }.items()
        ):
            raise AdjudicationError("technical evidence does not bind the exact decision")
        if evidence.get("exact_path_build_applicable") is not True or evidence.get("unknowns_blocking_applicability") != []:
            raise AdjudicationError("terminal decision lacks exact-path applicability")
        for source in _verify_decisive_sources(
            evidence.get("decisive_sources"), source_checkouts, source_revisions
        ):
            decisive_source_files[(source["component_id"], source["path"])] = source
        proof = evidence.get("proof")
        counterevidence = evidence.get("counterevidence")
        if proof is not None and (
            not isinstance(proof, dict)
            or set(proof) != PROOF_FIELDS
            or any(not isinstance(value, str) or not value.strip() for value in proof.values())
        ):
            raise AdjudicationError("technical evidence has an incomplete proof tuple")
        if technical_class == "VALID_VULNERABILITY" and proof is None:
            raise AdjudicationError("valid vulnerability lacks a complete proof tuple")
        if technical_class == "NO_BUG" and (
            proof is not None or not isinstance(counterevidence, str) or not counterevidence.strip()
        ):
            raise AdjudicationError("NO_BUG lacks exact counterevidence")
        primary_review = _bind_review(base, entry.get("primary_review", {}), entry, "PRIMARY")
        reviewed = [("PRIMARY", entry.get("primary_review_id"), primary_review)]
        if technical_class == "NO_BUG":
            blind_review = _bind_review(base, entry.get("blind_review", {}), entry, "BLIND")
            reviewed.append(("BLIND", entry.get("blind_review_id"), blind_review))
        capsule = capsules.get(record_id)
        if not capsule or capsule.get("terminal_decision") != technical_class:
            raise AdjudicationError("selected decision lacks its new evidence capsule")
        capsule_body = {key: value for key, value in capsule.items() if key not in {"capsule_id", "content_hash"}}
        if capsule.get("content_hash") != object_hash(capsule_body):
            raise AdjudicationError("technical evidence capsule hash is invalid")
        configuration, dependency_manifest = _build_commitments(
            successor_tables, capsule.get("build_id")
        )
        if capsule.get("configuration_hash") != configuration:
            raise AdjudicationError("terminal capsule build/configuration differs")
        if capsule.get("dependency_manifest_hash") != dependency_manifest:
            raise AdjudicationError("terminal capsule dependency manifest differs")
        decisive = json.loads(capsule.get("decisive_sources_json", "null"))
        if not _source_ranges(decisive) or evidence.get("decisive_sources") != decisive:
            raise AdjudicationError("capsule and evidence disagree on decisive source ranges")
        reopen = json.loads(capsule.get("reopen_conditions_json", "null"))
        if not isinstance(reopen, list) or not reopen or any(
            not isinstance(item, str) or not item.strip() for item in reopen
        ):
            raise AdjudicationError("terminal decision lacks explicit reopen conditions")
        if capsule.get("review_set_hash") != _review_set_hash(record_id, reviewed):
            raise AdjudicationError("terminal capsule review-set commitment differs")
        proof_value = capsule.get("proof_tuple_json")
        proof = json.loads(proof_value) if isinstance(proof_value, str) else None
        if technical_class in {"VALID_VULNERABILITY", "HARDENING"}:
            if (
                not isinstance(proof, dict)
                or set(proof) != PROOF_FIELDS
                or any(not isinstance(value, str) or not value.strip() for value in proof.values())
                or evidence.get("proof") != proof
            ):
                raise AdjudicationError("valid vulnerability lacks a bound complete proof tuple")
        elif technical_class == "NO_BUG":
            if proof is not None or not capsule.get("counterevidence") or evidence.get("counterevidence") != capsule.get("counterevidence"):
                raise AdjudicationError("NO_BUG lacks hash-bound counterevidence")
        primary = next((x for x in bindings if x.get("review_id") == entry.get("primary_review_id") and x.get("subject_kind") == "SCANNER_RECORD" and x.get("subject_id") == record_id), None)
        primary_run = review_runs.get(entry.get("primary_review_id"))
        if not primary or not primary_run or primary.get("evidence_hash") != primary_review["_sha256"] or primary.get("subject_hash") != entry["before_row_sha256"] or primary_run.get("role") != "INDEPENDENT_REVIEWER" or primary_run.get("independent") != 1 or primary_run.get("conclusion") != technical_class:
            raise AdjudicationError("primary review provenance is not persisted")
        primary_capsule = next((x for x in bindings if x.get("review_id") == entry.get("primary_review_id") and x.get("subject_kind") == "EVIDENCE_CAPSULE" and x.get("subject_id") == capsule.get("capsule_id")), None)
        if not primary_capsule or primary_capsule.get("subject_hash") != capsule.get("content_hash") or primary_capsule.get("evidence_hash") != primary_review["_sha256"]:
            raise AdjudicationError("terminal capsule lacks bound primary-review provenance")
        if technical_class == "NO_BUG":
            blind = next((x for x in bindings if x.get("review_id") == entry.get("blind_review_id") and x.get("subject_kind") == "SCANNER_RECORD" and x.get("subject_id") == record_id), None)
            blind_run = review_runs.get(entry.get("blind_review_id"))
            if not blind or not blind_run or blind.get("evidence_hash") != blind_review["_sha256"] or blind.get("subject_hash") != entry["before_row_sha256"] or blind_run.get("role") != "SAME_MODEL_REVIEW" or blind_run.get("independent") != 0:
                raise AdjudicationError("NO_BUG lacks hash-bound blind review provenance")
            blind_capsule = next((x for x in bindings if x.get("review_id") == entry.get("blind_review_id") and x.get("subject_kind") == "EVIDENCE_CAPSULE" and x.get("subject_id") == capsule.get("capsule_id")), None)
            if not blind_capsule or blind_capsule.get("subject_hash") != capsule.get("content_hash") or blind_capsule.get("evidence_hash") != blind_review["_sha256"]:
                raise AdjudicationError("NO_BUG capsule lacks bound blind-review provenance")
            audit = audits.get(record_id)
            if not audit or audit.get("primary_decision") != "NO_BUG" or audit.get("blind_decision") != "NO_BUG" or audit.get("integrator_decision") != "NO_BUG":
                raise AdjudicationError("NO_BUG lacks the required independent review audit")
            if (
                audit.get("primary_review_id") != entry.get("primary_review_id")
                or audit.get("blind_review_id") != entry.get("blind_review_id")
                or audit.get("decisive_source_manifest_hash") != object_hash(decisive)
                or audit.get("build_id") != capsule.get("build_id")
                or audit.get("configuration_hash") != capsule.get("configuration_hash")
                or audit.get("counterevidence_category") not in COUNTEREVIDENCE_CATEGORIES
            ):
                raise AdjudicationError("NO_BUG audit does not bind the reviewed evidence")
        disposition = entry.get("root_disposition")
        if technical_class == "NO_BUG":
            if disposition != {"kind": "NONE"} or record_id in mapping or capsule.get("root_id") is not None:
                raise AdjudicationError("NO_BUG must not create or reuse a root")
        else:
            if not isinstance(disposition, dict) or not disposition.get("root_id"):
                raise AdjudicationError("positive decision lacks a root disposition")
            root_id = disposition["root_id"]
            mapping_row = mapping.get(record_id, {})
            if (
                mapping_row.get("root_id") != root_id
                or mapping_row.get("relationship") != disposition.get("kind")
                or capsule.get("root_id") != root_id
            ):
                raise AdjudicationError("record/root mapping differs from the reviewed decision")
            dedup = _bound(base, disposition.get("evidence", {}), "deduplication evidence")
            dedup_record = _record(Path(dedup["resolved_locator"]), DEDUP_FORMAT, "deduplication evidence")
            if dedup_record["_sha256"] != dedup["sha256"] or any(
                dedup_record.get(key) != value
                for key, value in {
                    "project_id": project_id,
                    "record_id": record_id,
                    "root_id": root_id,
                    "relation": disposition.get("kind"),
                }.items()
            ):
                raise AdjudicationError("deduplication evidence does not bind the exact record/root decision")
            if disposition.get("kind") == "EXACT_DUPLICATE":
                layers = dedup_record.get("five_layer_dedup", {}).get("layers", {})
                comparisons = dedup_record.get("comparisons", {})
                if (
                    dedup_record.get("five_layer_dedup", {}).get("status") != "COMPLETE"
                    or set(layers) != DEDUP_LAYERS
                    or any(not _contains_hash(value) for value in layers.values())
                    or dedup_record.get("RCA_DISTINCT") is not False
                    or set(comparisons) != EXACT_COMPARISONS
                    or any(value != "MATCH" for value in comparisons.values())
                ):
                    raise AdjudicationError("exact duplicate lacks five-layer exact-RCA comparison")
                if not _root_exists(predecessor_tables, root_id) or root_id in created_roots:
                    raise AdjudicationError("exact duplicate does not reuse an existing root")
                existing = {
                    row["raw"].get("fingerprint_hash")
                    for row in predecessor_tables.get("root_fingerprint_field", {}).get("rows", {}).values()
                    if row["raw"].get("root_id") == root_id
                }
                if dedup_record.get("fingerprint_hash") not in existing:
                    raise AdjudicationError("exact-duplicate evidence lacks the retained root fingerprint")
            elif disposition.get("kind") in {"RELATED_VARIANT", "NOVEL"}:
                layers = dedup_record.get("five_layer_dedup", {}).get("layers", {})
                if (
                    dedup_record.get("five_layer_dedup", {}).get("status") != "COMPLETE"
                    or set(layers) != DEDUP_LAYERS
                    or any(not _contains_hash(value) for value in layers.values())
                    or dedup_record.get("RCA_DISTINCT") is not True
                ):
                    raise AdjudicationError("new root lacks complete five-layer RCA-distinct comparison")
                if root_id not in created_roots or _root_exists(predecessor_tables, root_id):
                    raise AdjudicationError("related or novel finding did not create a distinct root")
                if (
                    dedup_record.get("fingerprint_hash")
                    != new_fingerprints_by_root.get(root_id)
                ):
                    raise AdjudicationError("related/novel evidence lacks the promoted root fingerprint")
                new_root = next(
                    row for row in _inserted(diff, "root")
                    if row["raw"].get("root_id") == root_id
                )
                if new_root["raw"].get("project_id") != project_id or new_root["raw"].get("current_decision", new_root["raw"].get("technical_class")) != technical_class:
                    raise AdjudicationError("promoted root decision differs from reviewed result")
                root_review = next((x for x in bindings if x.get("review_id") == entry.get("primary_review_id") and x.get("subject_kind") == "ROOT" and x.get("subject_id") == root_id), None)
                if not root_review or root_review.get("subject_hash") != _row_hash(new_root) or root_review.get("evidence_hash") != primary_review["_sha256"]:
                    raise AdjudicationError("promoted root lacks bound review provenance")
            else:
                raise AdjudicationError("unsupported deduplication disposition")

    for entry in entries:
        if entry["record_id"] not in selected:
            row = before_rows[entry["record_id"]]
            if entry.get("before_row_sha256") != _row_hash(row) or row["typed"] != after_rows[entry["record_id"]]["typed"]:
                raise AdjudicationError("unselected scanner record changed")
    return {
        "population_count": len(entries),
        "selected_count": len(selected),
        "selected_record_ids": sorted(selected),
        "changed_tables": {table: {key: len(value) for key, value in changes.items()} for table, changes in diff.items()},
        "decisive_source_files": [decisive_source_files[key] for key in sorted(decisive_source_files)],
    }


def _load_bundle(
    adjudication_path: Path, approval_path: Path, project_id: str
) -> tuple[dict, dict, dict, dict]:
    adjudication = _record(
        adjudication_path, ADJUDICATION_FORMAT, "technical adjudication"
    )
    required = {
        "format_version", "control_revision", "project_id", "base", "cohort",
        "prepared_successor", "provider_inventory", "content_hash",
    }
    if set(key for key in adjudication if not key.startswith("_")) != required:
        raise AdjudicationError("technical adjudication has unexpected fields")
    if adjudication["control_revision"] != CONTROL_REVISION or adjudication["project_id"] != project_id:
        raise AdjudicationError("technical adjudication identity mismatch")
    base = Path(adjudication["_locator"]).parent
    cohort_binding = _bound(base, adjudication["cohort"], "reviewed decision cohort")
    cohort = _record(Path(cohort_binding["resolved_locator"]), COHORT_FORMAT, "reviewed decision cohort")
    if cohort["_sha256"] != cohort_binding["sha256"] or cohort.get("project_id") != project_id:
        raise AdjudicationError("reviewed decision cohort identity mismatch")
    approval = _record(approval_path, APPROVAL_FORMAT, "technical adjudication approval")
    successor = _bound(base, adjudication["prepared_successor"], "prepared successor")
    try:
        inventory, provider = state_control._verify_inventory(
            adjudication["provider_inventory"], base
        )
    except state_control.CorrectionError as error:
        raise AdjudicationError(str(error)) from error
    if approval.get("authorization_type") != "RECORDED_HUMAN_APPROVAL" or not approval.get("approver_identity") or not approval.get("approved_at") or approval.get("decision") != "AUTHORIZE_EXACT_DOWNSTREAM_TECHNICAL_ADJUDICATION":
        raise AdjudicationError("explicit human approval is required")
    expected = {
        "project_id": project_id,
        "adjudication_content_hash": adjudication["content_hash"],
        "cohort_content_hash": cohort["content_hash"],
        "cohort_file_sha256": cohort["_sha256"],
        "base_candidate_sha256": adjudication["base"].get("candidate_sha256"),
        "prepared_successor_sha256": successor["sha256"],
    }
    if any(approval.get(key) != value for key, value in expected.items()):
        raise AdjudicationError("approval does not cover the exact adjudication")
    return adjudication, approval, cohort, {"successor": successor, "provider": provider, "inventory": inventory}


def _candidate_state(path: Path) -> dict:
    return state_control._candidate_state(path)


def _workflow(path: Path) -> dict:
    return state_control._workflow(path, "campaign workflow")


def _transition_dir(state: Path, transition_id: str) -> Path:
    return state / "technical-adjudication-transitions" / transition_id


def _verify_provider(
    profile: dict, receipts: dict[str, dict], provider: dict
) -> tuple[list[dict], list[dict]]:
    provider_receipts = {
        key: value
        for key, value in receipts.items()
        if key in {
            item["stage_id"]
            for item in profile["automation"]["stages"]
            if item["phase"].startswith("METIS_")
        }
    }
    try:
        state_control._require_provider_files(provider_receipts, provider)
        return (
            state_control._receipt_provenance(profile, receipts),
            state_control._all_receipt_provenance(profile, receipts),
        )
    except state_control.CorrectionError as error:
        raise AdjudicationError(str(error)) from error


def _transition(
    directory: Path,
    candidate: Path,
    profile: dict,
    profile_identity: dict,
    workflow: dict,
    receipts: dict[str, dict],
    current_inputs: str,
    technical_lineage: Callable[[Path], str],
    source_checkouts: dict[str, str] | None,
    source_revisions: dict[str, str] | None,
    active_candidate: Path | None = None,
    seen: set[str] | None = None,
) -> dict:
    value = _record(directory / "transition.json", TRANSITION_FORMAT, "technical adjudication transition")
    active_candidate = candidate if active_candidate is None else active_candidate
    seen = set() if seen is None else seen
    if value.get("transition_id") in seen:
        raise AdjudicationError("technical adjudication transition chain contains a cycle")
    seen.add(value["transition_id"])
    binding = workflow.get("technical_adjudication_transition")
    if not isinstance(binding, dict) or set(binding) != {"transition_id", "locator", "sha256", "file_sha256"}:
        raise AdjudicationError("workflow lacks the technical adjudication transition")
    if Path(binding["locator"]) != directory / "transition.json" or binding["transition_id"] != value["transition_id"] or binding["sha256"] != value["content_hash"] or binding["file_sha256"] != file_hash(directory / "transition.json"):
        raise AdjudicationError("workflow adjudication binding differs")
    expected_archive = {
        **value["published_material"],
        "transition.json": {"sha256": binding["file_sha256"], "size": (directory / "transition.json").stat().st_size},
    }
    if _directory_inventory(directory, "published adjudication transition") != expected_archive:
        raise AdjudicationError("published adjudication transition bytes changed")
    adjudication, approval, cohort, material = _load_bundle(
        directory / "adjudication.json", directory / "approval.json", value["project_id"]
    )
    predecessor = regular(directory / "candidate-predecessor.db", "adjudication predecessor")
    successor = regular(directory / "candidate-successor.db", "adjudication successor")
    if _candidate_state(successor) != value["successor_candidate"]:
        raise AdjudicationError("adjudication successor candidate changed")
    if _candidate_state(predecessor) != value["base_candidate"]:
        raise AdjudicationError("adjudication predecessor candidate changed")
    if adjudication["base"].get("candidate_sha256") != value["base_candidate"]["sha256"] or adjudication["base"].get("technical_candidate_lineage_sha256") != value["technical_candidate_lineage_before"]:
        raise AdjudicationError("adjudication base commitment changed")
    if (
        adjudication["_sha256"] != value["adjudication_file_sha256"]
        or approval["content_hash"] != value["approval_content_hash"]
        or approval["_sha256"] != value["approval_file_sha256"]
        or cohort["_sha256"] != value["cohort_file_sha256"]
    ):
        raise AdjudicationError("adjudication approval or cohort bytes changed")
    if technical_lineage(successor) != value["technical_candidate_lineage_after"] or technical_lineage(candidate) != value["technical_candidate_lineage_after"]:
        raise AdjudicationError("adjudication technical lineage changed")
    if current_inputs != value["technical_input_lineage_sha256"] or adjudication["base"].get("technical_input_lineage_sha256") != current_inputs:
        raise AdjudicationError("adjudication technical input lineage changed")
    if profile_identity["sha256"] != value["profile_sha256"] or workflow.get("profile_sha256") != value["profile_sha256"]:
        raise AdjudicationError("adjudication profile binding changed")
    provider_receipts, retained = _verify_provider(profile, receipts, material["provider"])
    if provider_receipts != value["retained_provider_receipts"] or retained != value["retained_prerequisites"] or material["provider"] != value["provider_inventory_before"] or material["provider"] != value["provider_inventory_after"]:
        raise AdjudicationError("adjudication provider prerequisites changed")
    summary = _validate_successor(
        predecessor, successor, cohort, value["project_id"],
        source_checkouts, source_revisions,
    )
    if summary != value["candidate_delta"]:
        raise AdjudicationError("adjudication candidate delta changed")
    _verify_source_inventory(
        value.get("decisive_source_files"), source_checkouts, source_revisions
    )
    base_workflow_path = regular(
        directory / "workflow-predecessor.json", "adjudication predecessor workflow"
    )
    if (
        _file_identity(base_workflow_path, "adjudication predecessor workflow")
        != value.get("base_workflow_file")
    ):
        raise AdjudicationError("adjudication predecessor workflow bytes changed")
    base_workflow = _workflow(base_workflow_path)
    if base_workflow["workflow_sha256"] != value.get("base_workflow_sha256"):
        raise AdjudicationError("adjudication predecessor workflow identity changed")
    if base_workflow.get("technical_candidate_lineage_sha256") != value.get(
        "technical_candidate_lineage_before"
    ):
        raise AdjudicationError("adjudication predecessor workflow lineage changed")
    if base_workflow.get("technical_state_transition") != workflow.get(
        "technical_state_transition"
    ):
        raise AdjudicationError("adjudication dropped its predecessor transition")
    previous_binding = base_workflow.get("technical_adjudication_transition")
    if previous_binding:
        if not isinstance(previous_binding, dict):
            raise AdjudicationError("technical adjudication predecessor binding is invalid")
        previous_directory = _transition_dir(
            directory.parent.parent, previous_binding.get("transition_id", "")
        )
        previous = _transition(
            previous_directory,
            predecessor,
            profile,
            profile_identity,
            base_workflow,
            receipts,
            current_inputs,
            technical_lineage,
            source_checkouts,
            source_revisions,
            active_candidate,
            seen,
        )
        if (
            previous.get("technical_candidate_lineage_after")
            != value["technical_candidate_lineage_before"]
            or previous.get("technical_input_lineage_sha256")
            != value["technical_input_lineage_sha256"]
        ):
            raise AdjudicationError("technical adjudication predecessor chain differs")
    elif base_workflow.get("technical_state_transition"):
        try:
            state_control.verify_transition(
                directory.parent.parent,
                active_candidate,
                profile,
                profile_identity,
                base_workflow,
                receipts,
                current_inputs,
                technical_lineage,
                descendant_base={
                    "candidate": value["base_candidate"],
                    "technical_candidate_lineage_sha256": value[
                        "technical_candidate_lineage_before"
                    ],
                    "workflow_sha256": value["base_workflow_sha256"],
                },
            )
        except state_control.CorrectionError as error:
            raise AdjudicationError(str(error)) from error
    execution_mode = workflow.get("execution_mode")
    if execution_mode not in {"TECHNICAL_ADJUDICATION", "POLICY_ONLY"} or workflow.get("provider_phase_dispatches_permitted") != 0:
        raise AdjudicationError("adjudication workflow permits execution")
    if execution_mode == "TECHNICAL_ADJUDICATION":
        if _candidate_state(candidate) != value["successor_candidate"]:
            raise AdjudicationError("adjudication successor candidate changed")
        for key in ("current_policy_evidence", "campaign_complete", "submission_ready"):
            if workflow.get(key) is not False:
                raise AdjudicationError("adjudication workflow overstates downstream readiness")
    return value


def _validate_destination(path: Path, label: str) -> None:
    kind = state_control.entry_kind(path)
    if kind not in {None, "DIRECTORY"}:
        raise AdjudicationError(f"{label} destination is invalid")


def _test_interrupt(phase: str) -> None:
    if os.environ.get("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT") == phase:
        raise AdjudicationError(f"test-only interruption: {phase}")


def _file_identity(path: Path, label: str) -> dict:
    regular(path, label)
    return {"sha256": file_hash(path), "size": path.stat().st_size}


def _directory_inventory(path: Path, label: str) -> dict[str, dict]:
    if state_control.entry_kind(path) != "DIRECTORY":
        raise AdjudicationError(f"{label} is not a directory")
    result = {}
    for root, directories, files in os.walk(path, followlinks=False):
        root_path = Path(root)
        for name in directories:
            item = root_path / name
            if state_control.entry_kind(item) != "DIRECTORY":
                raise AdjudicationError(f"{label} contains a non-directory entry")
            result[str(item.relative_to(path)) + "/"] = {"kind": "DIRECTORY"}
        for name in files:
            item = root_path / name
            result[str(item.relative_to(path))] = _file_identity(item, label)
    return result


def _external_prerequisites(
    adjudication: dict,
    approval_path: Path,
    cohort: dict,
    material: dict,
    profile: dict,
    receipts: dict[str, dict],
    prior_workflow: dict,
) -> list[dict]:
    """Snapshot every external file whose prior verification authorizes publication."""

    files: dict[str, dict] = {}

    def add(path: Path, label: str) -> None:
        path = regular(path.resolve(), label)
        files[str(path)] = {"locator": str(path), **_file_identity(path, label)}

    def add_bound_artifacts(value: object, base: Path, label: str) -> None:
        if isinstance(value, dict):
            if {"locator", "sha256", "size"}.issubset(value):
                locator = Path(value["locator"])
                if locator.is_absolute():
                    binding = _bound(
                        base,
                        {key: value[key] for key in ("locator", "sha256", "size")},
                        label,
                    )
                    add(Path(binding["resolved_locator"]), label)
                    return
            for child in value.values():
                add_bound_artifacts(child, base, label)
        elif isinstance(value, list):
            for child in value:
                add_bound_artifacts(child, base, label)

    transition_directories: set[Path] = set()

    def add_transition_chain(workflow: object) -> None:
        if not isinstance(workflow, dict):
            return
        for key in ("technical_state_transition", "technical_adjudication_transition"):
            binding = workflow.get(key)
            if not isinstance(binding, dict) or not binding.get("locator"):
                continue
            locator = Path(binding["locator"])
            # A production predecessor has already passed its dedicated
            # verifier. Tests may substitute it without constructing an
            # archive, in which case there is no external archive to retain.
            if state_control.entry_kind(locator) != "REGULAR_FILE":
                continue
            directory = locator.resolve().parent
            if directory in transition_directories:
                continue
            transition_directories.add(directory)
            for relative in _directory_inventory(
                directory, f"predecessor {key}"
            ):
                if relative.endswith("/"):
                    continue
                path = directory / relative
                add(path, f"predecessor {key}")
                if path.suffix == ".json":
                    try:
                        add_bound_artifacts(
                            json.loads(path.read_text()),
                            path.parent,
                            f"predecessor {key} bound artifact",
                        )
                    except json.JSONDecodeError:
                        pass
            if key == "technical_adjudication_transition":
                predecessor_workflow = directory / "workflow-predecessor.json"
                if state_control.entry_kind(predecessor_workflow) == "REGULAR_FILE":
                    try:
                        add_transition_chain(_workflow(predecessor_workflow))
                    except state_control.CorrectionError as error:
                        raise AdjudicationError(str(error)) from error

    for path, label in (
        (Path(adjudication["_locator"]), "adjudication artifact"),
        (approval_path, "adjudication approval"),
        (Path(cohort["_locator"]), "adjudication cohort"),
        (Path(material["successor"]["resolved_locator"]), "prepared successor"),
        (Path(material["inventory"]["_locator"]), "provider inventory"),
    ):
        add(path, label)

    cohort_base = Path(cohort["_locator"]).parent
    for entry in cohort["scanner_population"]["records"]:
        if entry.get("action") != "ADJUDICATE":
            continue
        for key in ("technical_evidence", "primary_review", "blind_review"):
            binding = entry.get(key)
            if isinstance(binding, dict):
                add(Path(_bound(cohort_base, binding, key)["resolved_locator"]), key)
        disposition = entry.get("root_disposition")
        if isinstance(disposition, dict) and isinstance(disposition.get("evidence"), dict):
            add(
                Path(_bound(cohort_base, disposition["evidence"], "deduplication evidence")["resolved_locator"]),
                "deduplication evidence",
            )

    for item in material["provider"]["verified_files"]:
        add(Path(item["resolved_locator"]), f"provider prerequisite {item['kind']}")

    retained = {
        item["stage_id"]
        for item in profile["automation"]["stages"]
        if item["phase"] not in state_control.MUTABLE_POLICY_PHASES
    }
    for stage_id in sorted(set(receipts) & retained):
        receipt = receipts[stage_id]
        directory = Path(receipt["_receipt_directory"])
        add(directory / "receipt.json", f"retained receipt {stage_id}")
        if state_control.entry_kind(directory / "context.json") is not None:
            add(directory / "context.json", f"retained context {stage_id}")
        for output in receipt.get("outputs", []):
            add(directory / output["locator"], f"retained output {stage_id}")

    add_transition_chain(prior_workflow)
    return [files[key] for key in sorted(files)]


def _verify_external_prerequisites(items: object) -> None:
    if not isinstance(items, list) or not items:
        raise AdjudicationError("pending adjudication lacks external prerequisites")
    locators = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {"locator", "sha256", "size"}:
            raise AdjudicationError("pending external prerequisite is invalid")
        locator = Path(item["locator"])
        if not locator.is_absolute():
            raise AdjudicationError("pending external prerequisite locator is not absolute")
        locator = regular(locator.resolve(), "pending external prerequisite")
        if _file_identity(locator, "pending external prerequisite") != {
            "sha256": item["sha256"],
            "size": item["size"],
        }:
            raise AdjudicationError("pending external prerequisite changed")
        locators.append(str(locator))
    if len(locators) != len(set(locators)) or locators != sorted(locators):
        raise AdjudicationError("pending external prerequisite inventory is ambiguous")


def _preflight_pending_publication(
    control: Path,
    candidate: Path,
    state: Path,
    pending: dict,
    candidate_state: Callable[[Path], dict],
    source_checkouts: dict[str, str] | None,
    source_revisions: dict[str, str] | None,
) -> tuple[dict, dict, Path]:
    if state_control.entry_kind(candidate) != "REGULAR_FILE":
        raise AdjudicationError("candidate publication destination is invalid")
    if state_control.entry_kind(state / "workflow.json") != "REGULAR_FILE":
        raise AdjudicationError("workflow publication destination is invalid")
    current_candidate = candidate_state(candidate)
    current_workflow = _workflow(state / "workflow.json")
    before, after = pending["base_candidate"], pending["successor_candidate"]
    if current_candidate != before and current_candidate != after:
        raise AdjudicationError("candidate differs from both prepared adjudication states")
    if current_workflow["workflow_sha256"] not in {
        pending["base_workflow_sha256"], pending["successor_workflow_sha256"]
    }:
        raise AdjudicationError("workflow differs from both prepared adjudication states")
    current_workflow_identity = _file_identity(state / "workflow.json", "workflow publication destination")
    expected_current_workflow = (
        pending["base_workflow_file"]
        if current_workflow["workflow_sha256"] == pending["base_workflow_sha256"]
        else pending["workflow_publication"]
    )
    if current_workflow_identity != expected_current_workflow:
        raise AdjudicationError("workflow publication destination bytes differ")
    _verify_source_inventory(
        pending.get("decisive_source_files"), source_checkouts, source_revisions
    )
    _verify_external_prerequisites(pending.get("external_prerequisites"))

    for name, expected in (
        ("candidate-predecessor.db", before), ("candidate-successor.db", after)
    ):
        if candidate_state(regular(control / name, f"pending {name}")) != expected:
            raise AdjudicationError("pending adjudication material changed")
    if current_candidate == before:
        publication = regular(control / "candidate-publish.db", "candidate publication bytes")
        if candidate_state(publication) != after or _file_identity(publication, "candidate publication bytes") != pending["candidate_publication"]:
            raise AdjudicationError("candidate publication bytes differ")
    elif state_control.entry_kind(control / "candidate-publish.db") not in {None, "REGULAR_FILE"}:
        raise AdjudicationError("candidate publication staging is invalid")
    if current_workflow["workflow_sha256"] == pending["base_workflow_sha256"]:
        publication = regular(control / "workflow-publish.json", "workflow publication bytes")
        if _workflow(publication)["workflow_sha256"] != pending["successor_workflow_sha256"] or _file_identity(publication, "workflow publication bytes") != pending["workflow_publication"]:
            raise AdjudicationError("workflow publication bytes differ")
    elif state_control.entry_kind(control / "workflow-publish.json") not in {None, "REGULAR_FILE"}:
        raise AdjudicationError("workflow publication staging is invalid")

    final = _transition_dir(state, pending["transition_id"])
    _validate_destination(final.parent, "transition root")
    _validate_destination(final, "transition")
    if state_control.entry_kind(final) == "DIRECTORY":
        if _directory_inventory(final, "published transition") != pending["transition_publication"]:
            raise AdjudicationError("published adjudication transition conflicts")
    else:
        publish = control / "transition-publish"
        if _directory_inventory(publish, "transition publication") != pending["transition_publication"]:
            raise AdjudicationError("transition publication bytes differ")
    return current_candidate, current_workflow, final


def _publish_pending(
    control: Path,
    candidate: Path,
    state: Path,
    candidate_state: Callable[[Path], dict],
    source_checkouts: dict[str, str] | None,
    source_revisions: dict[str, str] | None,
) -> dict:
    pending = _record(control / "pending.json", PENDING_FORMAT, "technical adjudication pending commit")
    successor = regular(control / "candidate-successor.db", "pending successor")
    predecessor = regular(control / "candidate-predecessor.db", "pending predecessor")
    successor_workflow = regular(control / "workflow-successor.json", "pending successor workflow")
    predecessor_workflow = regular(control / "workflow-predecessor.json", "pending predecessor workflow")
    current_candidate, current_workflow, final = _preflight_pending_publication(
        control, candidate, state, pending, candidate_state,
        source_checkouts, source_revisions,
    )
    before, _after = candidate_state(predecessor), candidate_state(successor)
    predecessor_value, successor_value = _workflow(predecessor_workflow), _workflow(successor_workflow)
    if current_workflow["workflow_sha256"] not in {predecessor_value["workflow_sha256"], successor_value["workflow_sha256"]}:
        raise AdjudicationError("workflow differs from both prepared adjudication states")
    if current_candidate == before:
        os.replace(control / "candidate-publish.db", candidate)
        if os.environ.get("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT") == "AFTER_CANDIDATE":
            raise AdjudicationError("test-only interruption after candidate publication")
    if state_control.entry_kind(final) is None:
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(control / "transition-publish", final)
    else:
        recorded = _record(final / "transition.json", TRANSITION_FORMAT, "published adjudication transition")
        if recorded["content_hash"] != pending["transition_sha256"]:
            raise AdjudicationError("published adjudication transition conflicts")
    if os.environ.get("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT") == "AFTER_TRANSITION":
        raise AdjudicationError("test-only interruption after transition publication")
    if _workflow(state / "workflow.json")["workflow_sha256"] != successor_value["workflow_sha256"]:
        os.replace(control / "workflow-publish.json", state / "workflow.json")
    if os.environ.get("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT") == "AFTER_WORKFLOW":
        raise AdjudicationError("test-only interruption after workflow publication")
    result = {
        "result": "TECHNICAL_ADJUDICATION_COMPLETED",
        "transition_id": pending["transition_id"],
        "candidate": candidate_state(candidate),
        "workflow_sha256": successor_value["workflow_sha256"],
    }
    shutil.rmtree(control)
    return result


def recover(
    state: Path,
    candidate: Path,
    candidate_state: Callable[[Path], dict],
    source_checkouts: dict[str, str] | None = None,
    source_revisions: dict[str, str] | None = None,
) -> None:
    pending_root = state / "technical-adjudication-pending"
    kind = state_control.entry_kind(pending_root)
    if kind is None:
        return
    if kind != "DIRECTORY":
        raise AdjudicationError("technical adjudication pending root is invalid")
    controls = [path for path in pending_root.iterdir() if path.name != ".writer.lock"]
    if not controls:
        return
    lock_path = state / "authoritative-integrator.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AdjudicationError("technical adjudication recovery blocked by active writer lock") from error
        for control in sorted(controls):
            if state_control.entry_kind(control) != "DIRECTORY":
                raise AdjudicationError("technical adjudication pending entry is invalid")
            if state_control.entry_kind(control / "pending.json") is None:
                incomplete = state / "technical-adjudication-incomplete"
                _validate_destination(incomplete, "incomplete adjudication root")
                incomplete.mkdir(exist_ok=True)
                retained = incomplete / control.name
                if state_control.entry_kind(retained) is not None:
                    raise AdjudicationError("incomplete adjudication archive conflicts")
                os.replace(control, retained)
                continue
            _publish_pending(
                control, candidate, state, candidate_state,
                source_checkouts, source_revisions,
            )


def verify_transition(
    state: Path,
    candidate: Path,
    profile: dict,
    profile_identity: dict,
    workflow: dict,
    receipts: dict[str, dict],
    current_inputs: str,
    technical_lineage: Callable[[Path], str],
    source_checkouts: dict[str, str] | None = None,
    source_revisions: dict[str, str] | None = None,
) -> dict:
    binding = workflow.get("technical_adjudication_transition")
    if not isinstance(binding, dict) or not binding.get("transition_id"):
        raise AdjudicationError("workflow lacks a technical adjudication binding")
    final = _transition_dir(state, binding["transition_id"])
    if state_control.entry_kind(final) != "DIRECTORY":
        raise AdjudicationError("technical adjudication transition is unavailable")
    return _transition(
        final, candidate, profile, profile_identity, workflow, receipts,
        current_inputs, technical_lineage, source_checkouts, source_revisions,
    )


def apply(
    *,
    adjudication_path: Path,
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
    source_checkouts: dict[str, str],
    source_revisions: dict[str, str],
) -> dict:
    adjudication, approval, cohort, material = _load_bundle(
        adjudication_path, approval_path, project_id
    )
    transition_id = f"technical-adjudication:{adjudication['content_hash'][:24]}"
    final = _transition_dir(state, transition_id)
    if state_control.entry_kind(final) == "DIRECTORY":
        transition = verify_transition(
            state, candidate, profile, profile_identity,
            _workflow(state / "workflow.json"), receipts, current_technical_inputs,
            technical_lineage, source_checkouts, source_revisions,
        )
        if transition.get("transition_id") != transition_id or transition.get("adjudication_content_hash") != adjudication["content_hash"]:
            raise AdjudicationError("existing adjudication transition differs from the approved cohort")
        return {"result": "REUSED", "transition_id": transition_id, "candidate": candidate_state(candidate)}
    base_state = candidate_state(candidate)
    base = adjudication["base"]
    if base.get("candidate_sha256") != base_state.get("sha256") or base.get("candidate_size") != base_state.get("size") or base.get("workflow_sha256") != prior_workflow.get("workflow_sha256") or base.get("workflow_file_sha256") != file_hash(Path(prior_workflow["_locator"])) or base.get("profile_sha256") != profile_identity["sha256"]:
        raise AdjudicationError("technical adjudication base identity differs")
    if base.get("technical_candidate_lineage_sha256") != technical_lineage(candidate) or base.get("technical_input_lineage_sha256") != current_technical_inputs:
        raise AdjudicationError("technical adjudication lineage base differs")
    if prior_workflow.get("technical_adjudication_transition"):
        verify_transition(
            state,
            candidate,
            profile,
            profile_identity,
            prior_workflow,
            receipts,
            current_technical_inputs,
            technical_lineage,
            source_checkouts,
            source_revisions,
        )
    provider_receipts, retained = _verify_provider(profile, receipts, material["provider"])
    if base.get("provider_inventory_sha256") != material["provider"]["inventory_sha256"] or base.get("provider_counters") != material["provider"]["counters"]:
        raise AdjudicationError("provider inventory differs from the adjudication base")
    external_prerequisites = _external_prerequisites(
        adjudication,
        approval_path,
        cohort,
        material,
        profile,
        receipts,
        prior_workflow,
    )
    prepared = Path(material["successor"]["resolved_locator"])
    delta = _validate_successor(
        candidate, prepared, cohort, project_id, source_checkouts, source_revisions
    )
    after_lineage = technical_lineage(prepared)
    stages_by_id = {item["stage_id"]: item for item in profile["automation"]["stages"]}
    invalidated = [
        {"stage_id": stage_id, "receipt_sha256": prior_workflow["stages"][stage_id]}
        for stage_id in sorted(prior_workflow["stages"])
        if stages_by_id[stage_id]["phase"] in INVALIDATED_DOWNSTREAM_PHASES
    ]
    if adjudication.get("technical_candidate_lineage_after") not in {None, after_lineage}:
        raise AdjudicationError("prepared successor technical lineage differs")
    pending_root = state / "technical-adjudication-pending"
    _validate_destination(pending_root, "adjudication pending")
    pending_root.mkdir(exist_ok=True)
    control = Path(tempfile.mkdtemp(prefix=f"{transition_id.replace(':', '-')}-", dir=pending_root))
    _test_interrupt("PREPARATION_DIRECTORY_CREATED")
    publish = control / "transition-publish"
    publish.mkdir()
    _test_interrupt("PREPARATION_PUBLICATION_DIRECTORY_CREATED")
    shutil.copy2(candidate, control / "candidate-predecessor.db")
    _test_interrupt("PREPARATION_PREDECESSOR_COPIED")
    shutil.copy2(prepared, control / "candidate-successor.db")
    shutil.copy2(prepared, control / "candidate-publish.db")
    _test_interrupt("PREPARATION_SUCCESSOR_COPIED")
    shutil.copy2(prior_workflow["_locator"], control / "workflow-predecessor.json")
    _test_interrupt("PREPARATION_WORKFLOW_COPIED")
    shutil.copy2(adjudication["_locator"], publish / "adjudication.json")
    shutil.copy2(approval_path, publish / "approval.json")
    shutil.copy2(cohort["_locator"], publish / "cohort.json")
    shutil.copy2(candidate, publish / "candidate-predecessor.db")
    shutil.copy2(prepared, publish / "candidate-successor.db")
    shutil.copy2(prior_workflow["_locator"], publish / "workflow-predecessor.json")
    _test_interrupt("PREPARATION_EVIDENCE_COPIED")
    transition = {
        "format_version": TRANSITION_FORMAT,
        "control_revision": CONTROL_REVISION,
        "transition_id": transition_id,
        "project_id": project_id,
        "profile_sha256": profile_identity["sha256"],
        "base_candidate": base_state,
        "successor_candidate": candidate_state(prepared),
        "base_workflow_sha256": prior_workflow["workflow_sha256"],
        "base_workflow_file": _file_identity(control / "workflow-predecessor.json", "base workflow bytes"),
        "base_workflow_file_sha256": base["workflow_file_sha256"],
        "adjudication_content_hash": adjudication["content_hash"],
        "adjudication_file_sha256": adjudication["_sha256"],
        "approval_content_hash": approval["content_hash"],
        "approval_file_sha256": approval["_sha256"],
        "cohort_content_hash": cohort["content_hash"],
        "cohort_file_sha256": cohort["_sha256"],
        "candidate_delta": delta,
        "decisive_source_files": delta["decisive_source_files"],
        "technical_candidate_lineage_before": base["technical_candidate_lineage_sha256"],
        "technical_candidate_lineage_after": after_lineage,
        "technical_input_lineage_sha256": current_technical_inputs,
        "provider_inventory_before": material["provider"],
        "provider_inventory_after": material["provider"],
        "retained_provider_receipts": provider_receipts,
        "retained_prerequisites": retained,
        "invalidated_downstream_receipts": invalidated,
        "published_material": _directory_inventory(publish, "transition publication material"),
    }
    transition["content_hash"] = object_hash(transition)
    atomic_json(publish / "transition.json", transition)
    transition_file_sha256 = file_hash(publish / "transition.json")
    shutil.copy2(publish / "transition.json", control / "transition.json")
    _test_interrupt("PREPARATION_TRANSITION_WRITTEN")
    successor_workflow = {
        key: value for key, value in prior_workflow.items() if not key.startswith("_") and key != "workflow_sha256"
    }
    successor_workflow.update(
        {
            "candidate": candidate_state(prepared),
            "technical_candidate_lineage_sha256": after_lineage,
            "technical_input_lineage_sha256": current_technical_inputs,
            "technical_lineage_version": TECHNICAL_LINEAGE_VERSION,
            "execution_mode": "TECHNICAL_ADJUDICATION",
            "provider_phase_dispatches_permitted": 0,
            "current_policy_evidence": False,
            "campaign_complete": False,
            "submission_ready": False,
            "base_workflow_sha256": prior_workflow["workflow_sha256"],
            "technical_adjudication_transition": {
                "transition_id": transition_id,
                "locator": str(final / "transition.json"),
                "sha256": transition["content_hash"],
                "file_sha256": transition_file_sha256,
            },
        }
    )
    successor_workflow["statuses"] = {
        key: ("STALE_REOPENED" if any(item["stage_id"] == key for item in invalidated) else value)
        for key, value in prior_workflow["statuses"].items()
    }
    successor_workflow["workflow_sha256"] = object_hash(successor_workflow)
    atomic_json(control / "workflow-successor.json", successor_workflow)
    shutil.copy2(control / "workflow-successor.json", control / "workflow-publish.json")
    _test_interrupt("PREPARATION_SUCCESSOR_WORKFLOW_WRITTEN")
    pending = {
        "format_version": PENDING_FORMAT,
        "control_revision": CONTROL_REVISION,
        "transition_id": transition_id,
        "transition_sha256": transition["content_hash"],
        "base_candidate": base_state,
        "successor_candidate": candidate_state(prepared),
        "base_workflow_sha256": prior_workflow["workflow_sha256"],
        "base_workflow_file": _file_identity(control / "workflow-predecessor.json", "base workflow bytes"),
        "successor_workflow_sha256": successor_workflow["workflow_sha256"],
        "candidate_publication": _file_identity(control / "candidate-publish.db", "candidate publication bytes"),
        "workflow_publication": _file_identity(control / "workflow-publish.json", "workflow publication bytes"),
        "transition_publication": _directory_inventory(publish, "transition publication"),
        "decisive_source_files": delta["decisive_source_files"],
        "external_prerequisites": external_prerequisites,
        "content_hash": "",
    }
    pending["content_hash"] = object_hash({key: value for key, value in pending.items() if key != "content_hash"})
    atomic_json(control / "pending.json", pending)
    if os.environ.get("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT") == "BEFORE_PUBLICATION":
        raise AdjudicationError("test-only interruption before publication")
    return _publish_pending(
        control, candidate, state, candidate_state, source_checkouts, source_revisions
    )


def apply_with_lock(**arguments) -> dict:
    state = Path(arguments["state"])
    lock = state / "authoritative-integrator.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open("a+") as descriptor:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AdjudicationError("technical adjudication blocked by active writer lock") from error
        return apply(**arguments)
