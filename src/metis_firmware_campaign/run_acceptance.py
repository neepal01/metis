# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Offline acceptance runner using existing records, never a Metis source scan."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from metis.campaign_evidence import CampaignEvidenceCapability
from metis_firmware_campaign.packet_bundle import write_bundle


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )


def v3_profile(candidate: Path, adapter: Path, output: Path) -> tuple[Path, list[dict]]:
    connection = sqlite3.connect(
        f"file:{candidate.as_posix()}?mode=ro&immutable=1", uri=True
    )
    connection.row_factory = sqlite3.Row
    project = dict(
        connection.execute(
            "SELECT project_id,campaign_generation FROM project LIMIT 1"
        ).fetchone()
    )
    components = {
        row[0]: row[1]
        for row in connection.execute(
            "SELECT component_id,revision FROM component ORDER BY component_id"
        )
    }
    snapshots = {
        row[0]: row[1]
        for row in connection.execute("SELECT snapshot_id,content_hash FROM snapshot")
    }
    graph_by_build = {
        row[0]: dict(row)
        for row in connection.execute(
            "SELECT build_id,locator,content_hash,status FROM graph_artifact ORDER BY build_id"
        )
    }
    builds = []
    for build in connection.execute(
        "SELECT build_id,source_revision,platform,configuration_hash,toolchain_hash,identity_json FROM build_capsule ORDER BY build_id"
    ):
        identity = json.loads(build[5])
        graph = graph_by_build.get(build[0])
        revisions = {
            row[0]: row[1]
            for row in connection.execute(
                "SELECT DISTINCT l.component_id,l.revision FROM validation_run_root x JOIN validation_run v USING(validation_run_id) JOIN code_location l ON l.root_id=x.root_id WHERE v.build_id=? ORDER BY l.component_id",
                (build[0],),
            )
        }
        builds.append(
            {
                "build_id": build[0],
                "component_revisions": revisions or components,
                "platform": build[2],
                "image": str(
                    identity.get("image")
                    or (
                        "HASH_BOUND_EXECUTABLES"
                        if identity.get("firmware_hashes")
                        else "UNRESOLVED"
                    )
                ),
                "configuration_sha256": build[3],
                "toolchain_sha256": build[4],
                "graph_locator": graph["locator"] if graph else None,
                "graph_sha256": graph["content_hash"] if graph else None,
                "graph_status": (
                    "UNRESOLVED"
                    if not graph or graph["status"] in ("PARTIAL", "STALE")
                    else "CANDIDATE_STATIC"
                ),
            }
        )
    fixture_records = [
        dict(row)
        for row in connection.execute(
            "SELECT record_id,raw_hash FROM campaign_subject WHERE decision_status='TERMINAL' ORDER BY record_id LIMIT 20"
        )
    ]
    connection.close()
    profile = {
        "format_version": "metis-campaign-evidence-v1",
        "project_id": project["project_id"],
        "schema_contract_version": "portable-firmware-campaign-v3",
        "campaign_generation": project["campaign_generation"],
        "candidate_database": str(candidate),
        "candidate_sha256": sha(candidate),
        "component_revisions": components,
        "policy_sha256": snapshots["programme-policy"],
        "threat_model_sha256": snapshots["threat-model"],
        "historical_tickets_pocs_sha256": snapshots["historical-tickets-and-pocs"],
        "current_tickets_sha256": snapshots["current-ticket-inventory"],
        "build_graph_registry": builds,
        "adapter_argv": [sys.executable, str(adapter)],
        "fallback_action": "Reread decisive exact source/configuration and leave unresolved facts DEFERRED.",
        "limits": {
            "max_results": 20,
            "max_response_bytes": 64000,
            "max_packet_bytes": 128000,
            "max_database_bytes": 500000000,
            "adapter_timeout_seconds": 20,
            "max_worker_jobs": 100,
        },
    }
    profile_path = output / "profile.json"
    write(profile_path, profile)
    return profile_path, fixture_records


def tfa_profile(candidate: Path, adapter: Path, output: Path) -> Path:
    connection = sqlite3.connect(
        f"file:{candidate.as_posix()}?mode=ro&immutable=1", uri=True
    )
    connection.row_factory = sqlite3.Row
    build = dict(
        connection.execute(
            "SELECT * FROM build_capsule ORDER BY build_capsule_id LIMIT 1"
        ).fetchone()
    )
    graph = connection.execute(
        "SELECT locator,sha256,status FROM graph_artifact WHERE build_capsule_id=? ORDER BY artifact_id LIMIT 1",
        (build["build_capsule_id"],),
    ).fetchone()
    generation = connection.execute(
        "SELECT generation_id FROM campaign_import ORDER BY generation_id LIMIT 1"
    ).fetchone()[0]
    connection.close()
    unresolved = "0" * 64
    profile = {
        "format_version": "metis-campaign-evidence-v1",
        "project_id": build["project"],
        "schema_contract_version": "tfa-campaign-adapter-v1",
        "campaign_generation": generation,
        "candidate_database": str(candidate),
        "candidate_sha256": sha(candidate),
        "component_revisions": {build["repository"]: build["source_commit"]},
        "policy_sha256": build.get("policy_sha256") or unresolved,
        "threat_model_sha256": build.get("threat_model_sha256") or unresolved,
        "historical_tickets_pocs_sha256": build.get("historical_ticket_snapshot_sha256")
        or unresolved,
        "current_tickets_sha256": build.get("current_ticket_inventory_sha256")
        or unresolved,
        "build_graph_registry": [
            {
                "build_id": build["build_capsule_id"],
                "component_revisions": {build["repository"]: build["source_commit"]},
                "platform": build["platform"],
                "image": build["image"],
                "configuration_sha256": build.get("generated_config_sha256")
                or unresolved,
                "toolchain_sha256": build.get("compiler_executable_sha256")
                or unresolved,
                "graph_locator": graph[0] if graph else None,
                "graph_sha256": graph[1] if graph else None,
                "graph_status": "CANDIDATE_STATIC"
                if graph and graph[2] == "ACTIVE"
                else "UNRESOLVED",
            }
        ],
        "adapter_argv": [sys.executable, str(adapter)],
        "fallback_action": "Use a versioned TF-A adapter for project-specific operations; do not import TF-A decisions.",
        "limits": {
            "max_results": 5,
            "max_response_bytes": 64000,
            "max_packet_bytes": 128000,
            "max_database_bytes": 500000000,
            "adapter_timeout_seconds": 20,
            "max_worker_jobs": 1,
        },
    }
    path = output / "tfa-profile.json"
    write(path, profile)
    return path


def run_fixture(
    profile: Path, records: list[dict], packet_dir: Path, observed_at: str
) -> tuple[list[str], dict[str, int]]:
    capability = CampaignEvidenceCapability(profile, packet_dir)
    build = capability.backend.profile.build_graph_registry[0]
    component_id, component_revision = next(iter(build.component_revisions.items()))
    counters = {"HIT": 0, "MISS": 0, "OTHER": 0}
    hashes = []
    for index, record in enumerate(records):
        response = json.loads(capability.lookup("prior_record", record["record_id"]))
        counters[response["status"] if response["status"] in counters else "OTHER"] += 1
        packet = capability.export_packet(
            external_id=record["record_id"],
            source_kind="NON_SCANNER_INTEGRATION_FIXTURE",
            source_locator=f"campaign-fixture://{record['record_id']}",
            source_sha256=record["raw_hash"],
            repository_id="campaign-fixture://existing-project-source",
            component_id=component_id,
            component_revision=component_revision,
            platform=build.platform,
            image=build.image,
            configuration_sha256=build.configuration_sha256,
            observed_at=observed_at,
            finding={"fixture_only": True, "existing_record_id": record["record_id"]},
            metis_status=("valid", "invalid", "inconclusive")[index % 3],
            evidence_lookup_status=response["status"],
            evidence_query_content_hashes=(response["result_content_sha256"],),
        )
        hashes.append(packet["packet_sha256"])
    return sorted(hashes), counters


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--expected-candidate-sha256", required=True)
    parser.add_argument("--tfa", type=Path, required=True)
    parser.add_argument("--adapter", type=Path, required=True)
    parser.add_argument("--stage-validator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    candidate = args.candidate.resolve()
    output = args.output.resolve()
    before = sha(candidate)
    if before != args.expected_candidate_sha256:
        raise SystemExit(
            "candidate legitimately advanced or differs; provide the newer separately sealed identity"
        )
    profile, records = v3_profile(candidate, args.adapter.resolve(), output)
    one = CampaignEvidenceCapability(profile)
    root_response = json.loads(
        one.lookup("root_fingerprint_variants", records[0]["record_id"])
    )
    root_id = root_response["result"][0]["root_id"]
    statuses = [
        json.loads(one.lookup(op, root_id))["status"]
        for op in (
            "root_fingerprint_variants",
            "tickets_conclusions_pocs",
            "project_findings_reproducers",
            "five_layer_dedup",
            "evidence_context_capsule",
            "call_paths",
            "build_graph_identity",
            "reproduction_reopen",
        )
    ]
    miss = json.loads(one.lookup("prior_record", "METIS-NONEXISTENT-FIXTURE"))
    dependency_statuses = []
    for index, mutation in enumerate(
        ("policy_sha256", "current_tickets_sha256", "graph")
    ):
        stale_profile = json.loads(profile.read_text(encoding="utf-8"))
        if mutation == "graph":
            stale_profile["build_graph_registry"][0]["graph_sha256"] = "f" * 64
        else:
            stale_profile[mutation] = "f" * 64
        stale_path = output / f"stale-{index}.json"
        write(stale_path, stale_profile)
        dependency_statuses.append(
            json.loads(
                CampaignEvidenceCapability(stale_path).lookup(
                    "prior_record", records[0]["record_id"]
                )
            )["status"]
        )
    query_counts = {
        "HIT": statuses.count("HIT"),
        "MISS": statuses.count("MISS") + int(miss["status"] == "MISS"),
        "OTHER": len(statuses)
        - statuses.count("HIT")
        - statuses.count("MISS")
        + int(miss["status"] != "MISS"),
    }
    hashes_a, counts_a = run_fixture(
        profile, records, output / "packets-a", "2026-09-23T00:00:00Z"
    )
    hashes_b, counts_b = run_fixture(
        profile, records, output / "packets-b", "2026-09-23T00:00:00Z"
    )
    bundle_a = write_bundle(output / "packets-a", output / "bundle-a.json")
    write_bundle(output / "packets-b", output / "bundle-b.json")
    if (
        hashes_a != hashes_b
        or (output / "bundle-a.json").read_bytes()
        != (output / "bundle-b.json").read_bytes()
    ):
        raise SystemExit("integration fixtures are not deterministic")
    stage = json.loads(
        subprocess.check_output(
            [
                sys.executable,
                str(args.stage_validator.resolve()),
                str(output / "bundle-a.json"),
            ],
            text=True,
        )
    )
    reader = CampaignEvidenceCapability(profile)
    max_workers = reader.backend.profile.limits.max_worker_jobs
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        read_statuses = list(
            pool.map(
                lambda record: json.loads(
                    reader.lookup("prior_record", record["record_id"])
                )["status"],
                (records[index % len(records)] for index in range(max_workers)),
            )
        )
    achieved = sum(status == "HIT" for status in read_statuses)
    tfa = tfa_profile(args.tfa.resolve(), args.adapter.resolve(), output)
    tfa_result = json.loads(
        CampaignEvidenceCapability(tfa).lookup("build_graph_identity")
    )
    after = sha(candidate)
    sidecars = [
        str(Path(f"{candidate}{suffix}"))
        for suffix in ("-wal", "-journal", "-shm")
        if Path(f"{candidate}{suffix}").exists()
    ]
    summary = {
        "candidate_sha256_before": before,
        "candidate_sha256_after": after,
        "candidate_queries": {
            "HIT": query_counts["HIT"] + counts_a["HIT"] + counts_b["HIT"] + achieved,
            "MISS": query_counts["MISS"],
            "STALE": dependency_statuses.count("STALE"),
            "OTHER": query_counts["OTHER"] + counts_a["OTHER"] + counts_b["OTHER"],
        },
        "concurrent_readers_configured": max_workers,
        "concurrent_readers_achieved": achieved,
        "campaign_write_attempts": 0,
        "metis_execution_instances": 1,
        "provider_calls": 0,
        "packets": 20,
        "packet_hashes": hashes_a,
        "packet_set_sha256": canonical(hashes_a),
        "bundle_sha256": bundle_a["bundle_sha256"],
        "deterministic_outputs": True,
        "stage_validation": stage,
        "tfa_read_only_compatibility": "PASS"
        if tfa_result["status"] == "HIT"
        else "FAIL",
        "sidecars": sidecars,
        "candidate_unchanged": before == after,
        "scan_started": False,
        "review_code_invoked": False,
        "empty_project_fail_closed": False,
    }
    empty_database = output / "empty-project.db"
    with sqlite3.connect(empty_database):
        pass
    empty_profile = json.loads(profile.read_text(encoding="utf-8"))
    empty_profile["candidate_database"] = str(empty_database)
    empty_profile["candidate_sha256"] = sha(empty_database)
    empty_profile_path = output / "empty-profile.json"
    write(empty_profile_path, empty_profile)
    summary["empty_project_fail_closed"] = (
        json.loads(
            CampaignEvidenceCapability(empty_profile_path).lookup(
                "prior_record", records[0]["record_id"]
            )
        )["status"]
        == "INCOMPLETE"
    )
    write(output / "acceptance.json", summary)
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return int(
        not (
            before == after
            and not sidecars
            and achieved == max_workers
            and stage["result"] == "PASS"
            and summary["tfa_read_only_compatibility"] == "PASS"
            and summary["empty_project_fail_closed"]
            and dependency_statuses == ["STALE", "STALE", "STALE"]
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
