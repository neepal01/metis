# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from metis_firmware_campaign.packet_bundle import load_packets
from metis_firmware_campaign.packet_bundle import object_hash
from metis_firmware_campaign.packet_bundle import write_bundle


def _packet(external_id: str, source_hash: str = "a" * 64) -> dict:
    identity = [
        "SYNTHETIC_NON_SCANNER_FIXTURE",
        external_id,
        f"fixture://{external_id}",
        source_hash,
        "synthetic://firmware",
        "firmware",
        "1" * 40,
        "synthetic-board-v1",
        "firmware.bin",
        "c" * 64,
    ]
    body = {
        "format_version": "metis-firmware-finding-v1",
        "record_id": f"metis:{object_hash(identity)[:32]}",
        "external_id": external_id,
        "source_kind": "SYNTHETIC_NON_SCANNER_FIXTURE",
        "source_locator": f"fixture://{external_id}",
        "source_sha256": source_hash,
        "repository_id": "synthetic://firmware",
        "component_id": "firmware",
        "component_revision": "1" * 40,
        "platform": "synthetic-board-v1",
        "image": "firmware.bin",
        "configuration_sha256": "c" * 64,
        "observed_at": "2026-01-01T00:00:00Z",
        "project_id": "portable-project",
        "schema_contract_version": "portable-v1",
        "campaign_generation": "generation-1",
        "candidate_sha256": "b" * 64,
        "profile_sha256": "c" * 64,
        "dependency_hashes": {
            "policy": "d" * 64,
            "threat_model": "e" * 64,
            "historical_tickets_pocs": "f" * 64,
            "current_tickets": "0" * 64,
        },
        "build_graph_registry_sha256": "1" * 64,
        "finding": {"message": "fixture"},
        "metis_status": "valid",
        "evidence_lookup_status": "HIT",
        "evidence_query_content_hashes": ["2" * 64],
        "graph_edges": [],
        "campaign_route": "SEALED_CONTEXT",
        "technical_class": "DEFERRED",
        "exact_source_validation_complete": False,
        "creates_root": False,
        "fp_no_bug_authorized": False,
        "candidate_authorizes_governed_state": False,
    }
    body["packet_sha256"] = object_hash(body)
    return body


def _write_packet(directory: Path, body: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{body['record_id']}.{body['packet_sha256']}.json"
    path.write_text(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")


def test_packet_integration_is_sorted_one_to_one_and_deterministic(
    tmp_path: Path,
) -> None:
    source_a = tmp_path / "a"
    source_b = tmp_path / "b"
    for external_id in reversed([f"fixture-{index:02d}" for index in range(20)]):
        body = _packet(external_id)
        _write_packet(source_a, body)
        _write_packet(source_b, body)
    first = write_bundle(source_a, tmp_path / "first.json")
    second = write_bundle(source_b, tmp_path / "second.json")
    assert first == second
    assert first["campaign_write_attempts"] == 0
    assert len(first["records"]) == 20
    assert [item["record_id"] for item in first["records"]] == sorted(
        item["record_id"] for item in first["records"]
    )


def test_duplicate_replayed_packet_and_empty_project_fail_closed(
    tmp_path: Path,
) -> None:
    source = tmp_path / "packets"
    body = _packet("duplicate")
    _write_packet(source, body)
    replay = _packet("duplicate", "b" * 64)
    _write_packet(source, replay)
    with pytest.raises(ValueError, match="duplicate/replayed"):
        load_packets(source)
    (tmp_path / "empty").mkdir()
    with pytest.raises(ValueError, match="empty"):
        write_bundle(tmp_path / "empty", tmp_path / "empty.json")


def test_single_writer_atomic_generation(tmp_path: Path) -> None:
    source = tmp_path / "packets"
    _write_packet(source, _packet("single"))

    def invoke() -> str:
        try:
            write_bundle(source, tmp_path / "bundle.json")
            return "PASS"
        except ValueError:
            return "BLOCKED"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(lambda _: invoke(), range(2)))
    assert outcomes == ["BLOCKED", "PASS"]
    assert not (tmp_path / "bundle.json.lock").exists()
    assert json.loads((tmp_path / "bundle.json").read_text())["integrator_count"] == 1


def test_changed_and_corrupt_packets_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "packets"
    body = _packet("changed")
    _write_packet(source, body)
    path = next(source.glob("*.json"))
    path.write_text("{}")
    with pytest.raises(ValueError, match="identity mismatch"):
        load_packets(source)
