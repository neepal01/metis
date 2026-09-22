# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from metis.campaign_evidence import CampaignBuildGraph
from metis.campaign_evidence import CampaignEvidenceCapability
from metis.campaign_evidence import CampaignEvidenceError
from metis.campaign_evidence import CampaignGraphEdge
from metis.engine.capabilities.catalog import get_capability_manifest
from metis.engine.tools.campaign_evidence import campaign_evidence_model_tools


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _object_hash(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def _adapter_code(mode: str) -> str:
    return "\n".join(
        [
            "import hashlib,json,sys",
            f"mode={mode!r}; q=json.loads(sys.stdin.read())",
            "if mode=='corrupt': print('{'); raise SystemExit(0)",
            "result=[{'identity':q.get('identity'),'authority':'CANDIDATE_STATIC'}] if q.get('identity')=='hit' else []",
            "status='STALE' if q.get('identity')=='stale' else ('INCOMPLETE' if q.get('identity')=='incomplete' else ('HIT' if result else 'MISS'))",
            "if mode=='oversized': result=[{'value':'x'*20000}]",
            "r={'status':status,'reason':status.lower(),'result':result,'evidence_hashes':['a'*64] if result else [],'uncertainty':[],'limitations':[],'fallback':'read exact source','write_attempts':0}",
            "r['result_content_sha256']=hashlib.sha256(json.dumps(r,sort_keys=True,separators=(',',':')).encode()).hexdigest()",
            "print(json.dumps(r,sort_keys=True,separators=(',',':')))",
        ]
    )


def _fixture(tmp_path: Path, *, mode: str = "normal", max_response_bytes: int = 64000):
    tmp_path.mkdir(parents=True, exist_ok=True)
    database = tmp_path / "candidate.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE fixture(id TEXT)")
        connection.execute("INSERT INTO fixture VALUES('immutable')")
    profile = tmp_path / "profile.json"
    raw = {
        "format_version": "metis-campaign-evidence-v1",
        "project_id": "synthetic-firmware",
        "schema_contract_version": "portable-v1",
        "campaign_generation": "generation-1",
        "candidate_database": str(database),
        "candidate_sha256": _hash(database),
        "component_revisions": {"firmware": "1" * 40},
        "policy_sha256": "1" * 64,
        "threat_model_sha256": "2" * 64,
        "historical_tickets_pocs_sha256": "3" * 64,
        "current_tickets_sha256": "4" * 64,
        "build_graph_registry": [
            {
                "build_id": "build-1",
                "component_revisions": {"firmware": "1" * 40},
                "platform": "synthetic-board-v1",
                "image": "firmware.bin",
                "configuration_sha256": "5" * 64,
                "toolchain_sha256": "6" * 64,
                "graph_locator": None,
                "graph_sha256": None,
                "graph_status": "UNRESOLVED",
            }
        ],
        "adapter_argv": [sys.executable, "-c", _adapter_code(mode)],
        "fallback_action": "read exact source",
        "limits": {
            "max_results": 20,
            "max_response_bytes": max_response_bytes,
            "max_packet_bytes": 4096,
            "max_database_bytes": 1000000,
            "adapter_timeout_seconds": 10,
            "max_worker_jobs": 100,
        },
    }
    profile.write_text(json.dumps(raw), encoding="utf-8")
    return database, profile, tmp_path / "packets"


def test_exact_hit_miss_and_non_authorizing_envelope(tmp_path: Path) -> None:
    database, profile, packet_dir = _fixture(tmp_path)
    capability = CampaignEvidenceCapability(profile, packet_dir)
    hit = json.loads(capability.lookup("prior_record", "hit"))
    miss = json.loads(capability.lookup("prior_record", "missing"))
    assert hit["status"] == "HIT" and miss["status"] == "MISS"
    assert hit["candidate_database_sha256"] == _hash(database)
    assert all(value is False for value in hit["authority"].values())
    assert hit["terminal_source_reread_required"] is True
    unsigned = {
        key: value for key, value in hit.items() if key != "result_content_sha256"
    }
    assert hit["result_content_sha256"] == _object_hash(unsigned)


def test_identity_mismatch_and_database_symlink_fail_closed(tmp_path: Path) -> None:
    database, profile, packet_dir = _fixture(tmp_path)
    raw = json.loads(profile.read_text())
    raw["candidate_sha256"] = "f" * 64
    profile.write_text(json.dumps(raw))
    with pytest.raises(CampaignEvidenceError, match="identity mismatch"):
        CampaignEvidenceCapability(profile, packet_dir)
    raw["candidate_database"] = str(tmp_path / "linked.db")
    (tmp_path / "linked.db").symlink_to(database)
    raw["candidate_sha256"] = _hash(database)
    profile.write_text(json.dumps(raw))
    with pytest.raises(CampaignEvidenceError, match="regular file"):
        CampaignEvidenceCapability(profile, packet_dir)


@pytest.mark.parametrize("suffix", ["-wal", "-journal", "-shm"])
def test_unexpected_sidecar_fails_closed(tmp_path: Path, suffix: str) -> None:
    database, profile, packet_dir = _fixture(tmp_path)
    Path(f"{database}{suffix}").write_bytes(b"sidecar")
    with pytest.raises(CampaignEvidenceError, match="sidecar"):
        CampaignEvidenceCapability(profile, packet_dir)


def test_corrupt_and_oversized_adapter_output_fails_closed(tmp_path: Path) -> None:
    _, profile, packet_dir = _fixture(tmp_path / "corrupt", mode="corrupt")
    with pytest.raises(CampaignEvidenceError, match="corrupt"):
        CampaignEvidenceCapability(profile, packet_dir).lookup("prior_record", "hit")
    _, profile, packet_dir = _fixture(
        tmp_path / "large", mode="oversized", max_response_bytes=4096
    )
    with pytest.raises(CampaignEvidenceError, match="limit"):
        CampaignEvidenceCapability(profile, packet_dir).lookup("prior_record", "hit")


def test_stale_and_incomplete_dependencies_are_exposed(tmp_path: Path) -> None:
    _, profile, packet_dir = _fixture(tmp_path)
    capability = CampaignEvidenceCapability(profile, packet_dir)
    stale = json.loads(capability.lookup("build_graph_identity", "stale"))
    incomplete = json.loads(capability.lookup("evidence_context_capsule", "incomplete"))
    assert stale["status"] == "STALE" and incomplete["status"] == "INCOMPLETE"


def test_candidate_indirect_edge_cannot_establish_reachability() -> None:
    with pytest.raises(ValueError, match="cannot prove"):
        CampaignGraphEdge(
            caller="entry",
            callee="indirect_target",
            authority="CANDIDATE_STATIC",
            evidence_hash="a" * 64,
            required_for_proof=True,
        )


def test_miss_and_invalid_packets_cannot_promote_or_authorize_fp(
    tmp_path: Path,
) -> None:
    _, profile, packet_dir = _fixture(tmp_path)
    capability = CampaignEvidenceCapability(profile, packet_dir)
    evidence = json.loads(capability.lookup("prior_record", "missing"))
    missing = capability.export_packet(
        external_id="missing",
        source_kind="SYNTHETIC_NON_SCANNER_FIXTURE",
        source_locator="fixture://missing",
        source_sha256="7" * 64,
        repository_id="synthetic://firmware",
        component_id="firmware",
        component_revision="1" * 40,
        platform="synthetic-board-v1",
        image="firmware.bin",
        configuration_sha256="5" * 64,
        observed_at="2026-01-01T00:00:00Z",
        finding={"message": "fixture"},
        metis_status="invalid",
        evidence_lookup_status="MISS",
        evidence_query_content_hashes=(evidence["result_content_sha256"],),
    )
    assert missing["campaign_route"] == "NEW_ANALYSIS"
    assert missing["technical_class"] == "DEFERRED"
    assert missing["fp_no_bug_authorized"] is False
    assert missing["creates_root"] is False


def test_deterministic_packet_resume_and_replay_rejection(tmp_path: Path) -> None:
    _, profile, packet_dir = _fixture(tmp_path)
    capability = CampaignEvidenceCapability(profile, packet_dir)
    evidence = json.loads(capability.lookup("prior_record", "hit"))
    kwargs = {
        "external_id": "fixture-1",
        "source_kind": "SYNTHETIC_NON_SCANNER_FIXTURE",
        "source_locator": "fixture://1",
        "source_sha256": "8" * 64,
        "repository_id": "synthetic://firmware",
        "component_id": "firmware",
        "component_revision": "1" * 40,
        "platform": "synthetic-board-v1",
        "image": "firmware.bin",
        "configuration_sha256": "5" * 64,
        "observed_at": "2026-01-01T00:00:00Z",
        "finding": {"message": "fixture"},
        "metis_status": "valid",
        "evidence_lookup_status": "HIT",
        "evidence_query_content_hashes": (evidence["result_content_sha256"],),
    }
    packet = capability.export_packet(**kwargs)
    assert capability.export_packet(**kwargs, resume=True) == packet
    with pytest.raises(CampaignEvidenceError, match="duplicate"):
        capability.export_packet(**kwargs)
    assert len(list(packet_dir.glob("*.json"))) == 1


def test_concurrent_readers_leave_candidate_unchanged(tmp_path: Path) -> None:
    database, profile, packet_dir = _fixture(tmp_path)
    before = _hash(database)
    capability = CampaignEvidenceCapability(profile, packet_dir)
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(
            pool.map(lambda _: capability.lookup("prior_record", "hit"), range(40))
        )
    assert len(results) == 40
    assert all(json.loads(item)["status"] == "HIT" for item in results)
    assert _hash(database) == before
    assert not any(
        Path(f"{database}{suffix}").exists() for suffix in ("-wal", "-journal", "-shm")
    )


def test_graph_registry_requires_content_addressed_pair() -> None:
    with pytest.raises(ValueError, match="appear together"):
        CampaignBuildGraph(
            build_id="build",
            component_revisions={"firmware": "1" * 40},
            platform="board-v1",
            image="firmware.bin",
            configuration_sha256="2" * 64,
            toolchain_sha256="3" * 64,
            graph_locator="graph.json",
            graph_status="CANDIDATE_STATIC",
        )


def test_packet_rejects_unregistered_source_platform_configuration(
    tmp_path: Path,
) -> None:
    _, profile, packet_dir = _fixture(tmp_path)
    capability = CampaignEvidenceCapability(profile, packet_dir)
    evidence = json.loads(capability.lookup("prior_record", "hit"))
    with pytest.raises(CampaignEvidenceError, match="build registry"):
        capability.export_packet(
            external_id="unbound",
            source_kind="SYNTHETIC_NON_SCANNER_FIXTURE",
            source_locator="fixture://unbound",
            source_sha256="7" * 64,
            repository_id="synthetic://firmware",
            component_id="firmware",
            component_revision="1" * 40,
            platform="unregistered-board",
            image="firmware.bin",
            configuration_sha256="5" * 64,
            observed_at="2026-01-01T00:00:00Z",
            finding={"message": "fixture"},
            metis_status="valid",
            evidence_lookup_status="HIT",
            evidence_query_content_hashes=(evidence["result_content_sha256"],),
        )


def test_default_runtime_does_not_create_campaign_output(tmp_path: Path) -> None:
    _, profile, packet_dir = _fixture(tmp_path)
    assert profile.is_file() and not packet_dir.exists()


def test_non_default_manifest_exposes_only_bounded_lookup_to_models() -> None:
    manifest = get_capability_manifest("campaign_evidence")
    assert manifest is not None and manifest.active
    assert [
        operation.name
        for operation in manifest.operations
        if "model_tool" in operation.surfaces
    ] == ["campaign_evidence"]
    lookup = next(
        operation
        for operation in manifest.operations
        if operation.operation == "lookup"
    )
    assert set(lookup.input_schema["properties"]["operation"]["enum"]) == {
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
    export = next(
        operation
        for operation in manifest.operations
        if operation.id.endswith("export_packet")
    )
    assert "model_tool" not in export.surfaces and export.surfaces == ("orchestration",)


def test_manifest_model_tool_runs_bounded_non_authorizing_query(tmp_path: Path) -> None:
    _, profile, packet_dir = _fixture(tmp_path)
    capability = CampaignEvidenceCapability(profile, packet_dir)
    manifest = get_capability_manifest("campaign_evidence")
    assert manifest is not None
    tools = campaign_evidence_model_tools(capability, manifest, max_contract_chars=6000)
    result = json.loads(
        tools[0].invoke({"operation": "prior_record", "identity": "hit"})
    )
    assert [tool.name for tool in tools] == ["campaign_evidence"]
    assert result["status"] == "HIT"
    assert all(value is False for value in result["authority"].values())
