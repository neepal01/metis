# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Versioned portable-firmware SQLite adapter; deliberately outside Metis core."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from typing import Any

ALLOWED_OPERATIONS = {
    "prior_record",
    "root_fingerprint_variants",
    "tickets_conclusions_pocs",
    "project_findings_reproducers",
    "five_layer_dedup",
    "evidence_context_capsule",
    "call_paths",
    "build_graph_identity",
    "reproduction_reopen",
}


def object_hash(value: object) -> str:
    data = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(data).hexdigest()


def content_hashes(value: object) -> list[str]:
    found: set[str] = set()
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, str) and len(current) == 64:
            try:
                bytes.fromhex(current)
            except ValueError:
                continue
            found.add(current)
    return sorted(found)


def rows(
    connection: sqlite3.Connection, statement: str, parameters: tuple = ()
) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(statement, parameters)]


def tables(connection: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type IN('table','view')"
        )
    }


def columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info('{table}')")}


def resolve_v3_root(connection: sqlite3.Connection, identity: str | None) -> str | None:
    if not identity:
        return None
    if connection.execute("SELECT 1 FROM root WHERE root_id=?", (identity,)).fetchone():
        return identity
    row = connection.execute(
        "SELECT root_id FROM campaign_record_root WHERE record_id=? ORDER BY root_id LIMIT 1",
        (identity,),
    ).fetchone()
    return row[0] if row else None


def normalize_edge_authority(value: str) -> str:
    if value == "EXACT_SOURCE":
        return "SOURCE_CONFIRMED"
    if value in {
        "CANDIDATE_STATIC",
        "SOURCE_CONFIRMED",
        "RUNTIME_CONFIRMED",
        "STALE",
        "REJECTED",
    }:
        return value
    return "UNRESOLVED"


def v3_identity_errors(connection: sqlite3.Connection, expected: dict) -> list[str]:
    errors = []
    project = connection.execute(
        "SELECT project_id,campaign_generation FROM project LIMIT 1"
    ).fetchone()
    if not project or tuple(project) != (
        expected["project_id"],
        expected["campaign_generation"],
    ):
        errors.append("project/campaign generation mismatch")
    expected_snapshots = {
        "programme-policy": expected["policy_sha256"],
        "threat-model": expected["threat_model_sha256"],
        "historical-tickets-and-pocs": expected["historical_tickets_pocs_sha256"],
        "current-ticket-inventory": expected["current_tickets_sha256"],
    }
    for snapshot_id, expected_hash in expected_snapshots.items():
        row = connection.execute(
            "SELECT content_hash FROM snapshot WHERE snapshot_id=?", (snapshot_id,)
        ).fetchone()
        if not row or row[0] != expected_hash:
            errors.append(f"{snapshot_id} mismatch")
    components = {
        row[0]: row[1]
        for row in connection.execute("SELECT component_id,revision FROM component")
    }
    if components != expected["component_revisions"]:
        errors.append("component revision mismatch")
    graph_rows = {
        (row[0], row[1])
        for row in connection.execute(
            "SELECT build_id,content_hash FROM graph_artifact"
        )
    }
    for graph in expected["build_graph_registry"]:
        build = connection.execute(
            "SELECT source_revision,platform,configuration_hash,toolchain_hash FROM build_capsule WHERE build_id=?",
            (graph["build_id"],),
        ).fetchone()
        if not build or not (
            build[0] in set(graph["component_revisions"].values())
            and tuple(build)[1:]
            == (
                graph["platform"],
                graph["configuration_sha256"],
                graph["toolchain_sha256"],
            )
        ):
            errors.append(f"build mismatch: {graph['build_id']}")
        if (
            graph.get("graph_sha256")
            and (graph["build_id"], graph["graph_sha256"]) not in graph_rows
        ):
            errors.append(f"graph mismatch: {graph['build_id']}")
    return errors


def v3_query(
    connection: sqlite3.Connection, operation: str, identity: str | None, limit: int
) -> tuple[list[dict[str, Any]], list[str], str]:
    present = tables(connection)
    required = {"campaign_subject", "root", "campaign_record_root"}
    if not required <= present:
        return [], [], "required portable campaign tables are unavailable"
    evidence_hashes: list[str] = []
    if operation == "prior_record":
        result = rows(
            connection,
            "SELECT * FROM campaign_subject WHERE record_id=? LIMIT 1",
            (identity,),
        )
        if result:
            result[0]["roots"] = rows(
                connection,
                "SELECT root_id,relationship,confidence FROM campaign_record_root WHERE record_id=? ORDER BY root_id LIMIT ?",
                (identity, limit),
            )
            evidence_hashes.append(result[0].get("raw_hash", ""))
    elif operation == "root_fingerprint_variants":
        root = resolve_v3_root(connection, identity)
        result = (
            rows(connection, "SELECT * FROM root WHERE root_id=?", (root,))
            if root
            else []
        )
        if result:
            result[0]["fingerprints"] = rows(
                connection,
                "SELECT * FROM fingerprint WHERE root_id=? LIMIT ?",
                (root, limit),
            )
            result[0]["variants"] = rows(
                connection,
                "SELECT v.* FROM variant_analysis_run r JOIN variant_candidate v ON v.variant_run_id=r.variant_id WHERE r.root_id=? ORDER BY v.variant_id LIMIT ?",
                (root, limit),
            )
            evidence_hashes.append(result[0].get("source_hash", ""))
    elif operation == "tickets_conclusions_pocs":
        root = resolve_v3_root(connection, identity)
        record_ids = (
            [identity]
            if identity
            and connection.execute(
                "SELECT 1 FROM campaign_subject WHERE record_id=?", (identity,)
            ).fetchone()
            else []
        )
        if root:
            record_ids = [
                row[0]
                for row in connection.execute(
                    "SELECT record_id FROM campaign_record_root WHERE root_id=? ORDER BY record_id LIMIT ?",
                    (root, limit),
                )
            ]
        result = []
        for record_id in record_ids[:limit]:
            ticket = rows(
                connection,
                "SELECT t.* FROM campaign_subject s JOIN ticket t ON t.ticket_id=s.ticket_id WHERE s.record_id=?",
                (record_id,),
            )
            dispositions = rows(
                connection,
                "SELECT technical_class,programme_scope,scanner_claim_status,processing_route,reproduction_level,rationale,historical_close_reason,evidence_hash,terminal FROM ticket_disposition WHERE ticket_id=? ORDER BY disposition_id",
                (record_id,),
            )
            artifacts = rows(
                connection,
                "SELECT artifact_role,locator,content_hash,size FROM poc_artifact WHERE ticket_id=? ORDER BY artifact_role,locator LIMIT ?",
                (record_id, limit),
            )
            result.append(
                {
                    "record_id": record_id,
                    "ticket": ticket,
                    "conclusions": dispositions,
                    "pocs": artifacts,
                }
            )
            evidence_hashes.extend(item.get("content_hash", "") for item in artifacts)
    elif operation == "project_findings_reproducers":
        root = resolve_v3_root(connection, identity)
        if root:
            result = [
                {
                    "root_id": root,
                    "records": rows(
                        connection,
                        "SELECT s.record_id,s.title,s.raw_hash,s.technical_class,s.programme_scope,s.reproduction_level FROM campaign_record_root r JOIN campaign_subject s USING(record_id) WHERE r.root_id=? ORDER BY s.record_id LIMIT ?",
                        (root, limit),
                    ),
                    "reproducers": rows(
                        connection,
                        "SELECT p.ticket_id,p.artifact_role,p.locator,p.content_hash,p.size FROM campaign_record_root r JOIN poc_artifact p ON p.ticket_id=r.record_id WHERE r.root_id=? ORDER BY p.ticket_id,p.artifact_role,p.locator LIMIT ?",
                        (root, limit),
                    ),
                    "validation_artifacts": rows(
                        connection,
                        "SELECT x.validation_run_id,v.artifact_role,p.locator,p.content_hash,p.size FROM validation_run_root x JOIN validation_artifact v USING(validation_run_id) JOIN poc_artifact p USING(artifact_id) WHERE x.root_id=? ORDER BY x.validation_run_id,v.artifact_role,p.locator LIMIT ?",
                        (root, limit),
                    ),
                }
            ]
        else:
            result = rows(
                connection,
                "SELECT s.record_id,s.title,s.raw_hash,s.technical_class,s.programme_scope,s.reproduction_level FROM campaign_subject s ORDER BY s.record_id LIMIT ?",
                (limit,),
            )
        evidence_hashes.extend(item.get("raw_hash", "") for item in result)
    elif operation == "five_layer_dedup":
        root = resolve_v3_root(connection, identity)
        result = (
            rows(connection, "SELECT * FROM dedup_run WHERE root_id=?", (root,))
            if root
            else []
        )
        if result:
            result[0]["candidates"] = rows(
                connection,
                "SELECT * FROM dedup_candidate WHERE dedup_id=? ORDER BY layer,candidate_identity LIMIT ?",
                (result[0]["dedup_id"], limit),
            )
            evidence_hashes.append(result[0].get("content_hash", ""))
    elif operation == "evidence_context_capsule":
        root = resolve_v3_root(connection, identity)
        result = (
            rows(
                connection,
                "SELECT * FROM evidence_capsule WHERE root_id=? ORDER BY capsule_id LIMIT ?",
                (root, limit),
            )
            if root
            else []
        )
        required_kinds = {
            "DECISIVE_SOURCE_FILE",
            "BUILD_PLATFORM_CONFIG_TOOLCHAIN",
            "PROGRAMME_POLICY",
            "THREAT_MODEL",
            "KNOWLEDGE_ROOT",
            "HISTORICAL_TICKETS_POCS",
            "CURRENT_TICKETS",
            "GRAPH_ARTIFACT",
        }
        for capsule in result:
            capsule["dependencies"] = rows(
                connection,
                "SELECT kind,identity,content_hash,status,required FROM capsule_dependency WHERE capsule_id=? ORDER BY kind,identity",
                (capsule["capsule_id"],),
            )
            capsule["complete"] = required_kinds <= {
                item["kind"] for item in capsule["dependencies"]
            } and all(
                item["required"] == 1 and item["status"] == "VERIFIED"
                for item in capsule["dependencies"]
            )
            evidence_hashes.extend(
                item["content_hash"] for item in capsule["dependencies"]
            )
    elif operation == "call_paths":
        root = resolve_v3_root(connection, identity)
        result = (
            rows(
                connection,
                "SELECT * FROM call_path WHERE root_id=? ORDER BY call_path_id LIMIT ?",
                (root, limit),
            )
            if root
            else []
        )
        for path in result:
            path["direct_edges"] = rows(
                connection,
                "SELECT caller,callee,authority_state,source_location FROM call_edge WHERE call_path_id=? ORDER BY seq LIMIT ?",
                (path["call_path_id"], limit),
            )
            for edge in path["direct_edges"]:
                edge["authority"] = normalize_edge_authority(
                    edge.pop("authority_state")
                )
        if root and "indirect_edge_evidence" in present:
            indirect = rows(
                connection,
                "SELECT indirect_id,caller,callee_candidate,evidence_hash,authority_state FROM indirect_edge_evidence ORDER BY indirect_id LIMIT ?",
                (limit,),
            )
            for edge in indirect:
                edge["authority"] = normalize_edge_authority(
                    edge.pop("authority_state")
                )
            result.append(
                {
                    "candidate_indirect_edges": indirect,
                    "authority_limit": "CANDIDATE_STATIC and UNRESOLVED edges are navigation only",
                }
            )
    elif operation == "build_graph_identity":
        root = resolve_v3_root(connection, identity)
        if root:
            result = rows(
                connection,
                "SELECT b.* FROM validation_run_root x JOIN validation_run v USING(validation_run_id) JOIN build_capsule b USING(build_id) WHERE x.root_id=? LIMIT ?",
                (root, limit),
            )
        else:
            result = rows(
                connection,
                "SELECT * FROM build_capsule ORDER BY build_id LIMIT ?",
                (limit,),
            )
        for build in result:
            build["decisive_sources"] = rows(
                connection,
                "SELECT path,file_hash FROM build_source_file WHERE build_id=? ORDER BY path LIMIT ?",
                (build["build_id"], limit),
            )
            build["graphs"] = rows(
                connection,
                "SELECT * FROM graph_artifact WHERE build_id=? ORDER BY graph_id LIMIT ?",
                (build["build_id"], limit),
            )
            for graph in build["graphs"]:
                graph["query_authority"] = normalize_edge_authority(
                    graph["authority_state"]
                    if graph["exact_build_run"] == 1 and graph["status"] == "COMPLETE"
                    else "UNRESOLVED"
                )
            evidence_hashes.extend(
                item.get("content_hash", "") for item in build["graphs"]
            )
    elif operation == "reproduction_reopen":
        root = resolve_v3_root(connection, identity)
        if root:
            result = rows(
                connection,
                "SELECT v.* FROM validation_run_root x JOIN validation_run v USING(validation_run_id) WHERE x.root_id=? LIMIT ?",
                (root, limit),
            )
            for validation in result:
                validation["observations"] = rows(
                    connection,
                    "SELECT observation_role,status,result,validation_artifact_id,artifact_hash,evidence_hash FROM execution_observation WHERE validation_run_id=? ORDER BY observation_role",
                    (validation["validation_run_id"],),
                )
                validation["reopen_conditions"] = rows(
                    connection,
                    "SELECT s.record_id,s.decision_status,a.status AS assignment_status,a.reason FROM campaign_record_root r JOIN campaign_subject s USING(record_id) LEFT JOIN analysis_assignment a ON a.record_id=s.record_id WHERE r.root_id=? ORDER BY s.record_id LIMIT ?",
                    (root, limit),
                )
        elif identity:
            result = rows(
                connection,
                "SELECT s.record_id,s.decision_status,s.technical_class,a.reason AS reopen_condition FROM campaign_subject s LEFT JOIN analysis_assignment a ON a.record_id=s.record_id WHERE s.record_id=? LIMIT 1",
                (identity,),
            )
        else:
            result = []
    else:
        result = []
    return (
        result,
        [value for value in evidence_hashes if len(value) == 64],
        "portable schema lookup completed",
    )


def legacy_tfa_query(
    connection: sqlite3.Connection, operation: str, identity: str | None, limit: int
) -> tuple[list[dict[str, Any]], list[str], str]:
    present = tables(connection)
    if (
        operation == "prior_record"
        and identity
        and "campaign_subject" in present
        and "subject_id" in columns(connection, "campaign_subject")
    ):
        return (
            rows(
                connection,
                "SELECT * FROM campaign_subject WHERE subject_type='RECORD' AND subject_id=? LIMIT 1",
                (identity,),
            ),
            [],
            "legacy TF-A record lookup completed",
        )
    if (
        operation == "build_graph_identity"
        and {"build_capsule", "graph_artifact"} <= present
    ):
        builds = rows(connection, "SELECT * FROM build_capsule LIMIT ?", (limit,))
        graphs = rows(connection, "SELECT * FROM graph_artifact LIMIT ?", (limit,))
        for graph in graphs:
            graph["query_authority"] = "UNRESOLVED"
        return (
            [{"builds": builds, "graphs": graphs}],
            [item.get("sha256", "") for item in graphs if item.get("sha256")],
            "legacy TF-A graph registry is readable through its adapter path",
        )
    return [], [], "legacy schema needs a project-specific operation adapter"


def main() -> int:
    try:
        request = json.loads(sys.stdin.read())
        if set(request) - {
            "format_version",
            "operation",
            "identity",
            "query",
            "limit",
            "database_uri",
            "expected",
        }:
            raise ValueError("unknown query fields")
        operation = request["operation"]
        if operation not in ALLOWED_OPERATIONS:
            raise ValueError("unknown operation")
        connection = sqlite3.connect(request["database_uri"], uri=True, timeout=1)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        before_changes = connection.total_changes
        present = tables(connection)
        if "record_id" in columns(connection, "campaign_subject"):
            identity_errors = v3_identity_errors(connection, request["expected"])
            incomplete = False
            if identity_errors:
                result, evidence_hashes, reason = [], [], "; ".join(identity_errors)
            else:
                result, evidence_hashes, reason = v3_query(
                    connection,
                    operation,
                    request.get("identity"),
                    int(request["limit"]),
                )
                incomplete = bool(
                    operation == "evidence_context_capsule"
                    and any(not item["complete"] for item in result)
                )
        elif {"campaign_import", "build_capsule", "graph_artifact"} <= present:
            identity_errors = []
            incomplete = False
            result, evidence_hashes, reason = legacy_tfa_query(
                connection, operation, request.get("identity"), int(request["limit"])
            )
        else:
            identity_errors = []
            incomplete = True
            result, evidence_hashes = [], []
            reason = (
                "campaign schema identity and required dependencies are unavailable"
            )
        if connection.total_changes != before_changes:
            raise RuntimeError("adapter write attempt")
        connection.close()
        evidence_hashes = sorted(set(evidence_hashes) | set(content_hashes(result)))
        response = {
            "status": (
                "STALE"
                if identity_errors
                else ("INCOMPLETE" if incomplete else ("HIT" if result else "MISS"))
            ),
            "reason": reason,
            "result": result,
            "evidence_hashes": evidence_hashes,
            "uncertainty": (
                []
                if result
                else [
                    "No exact mapped campaign evidence exists for this identity and operation."
                ]
            ),
            "limitations": [
                "Query output is navigation evidence; exact source remains terminal authority."
            ],
            "fallback": "Reread decisive exact source/configuration and preserve unresolved facts as DEFERRED.",
            "write_attempts": 0,
        }
        response["result_content_sha256"] = object_hash(response)
        sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")))
        return 0
    except (KeyError, OSError, sqlite3.Error, TypeError, ValueError) as exc:
        sys.stderr.write(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
