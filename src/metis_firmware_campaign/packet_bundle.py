# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Single-writer packet validation and staging for the firmware pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from metis.campaign_evidence import CampaignFindingPacket


def object_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


def load_packets(source: Path) -> list[dict]:
    if source.is_symlink() or not source.is_dir():
        raise ValueError("packet population must be a regular directory")
    unexpected = [
        path.name
        for path in source.iterdir()
        if path.is_symlink() or not path.is_file() or not path.name.endswith(".json")
    ]
    if unexpected:
        raise ValueError(f"unexpected packet-directory files: {unexpected}")
    packets = []
    for path in sorted(source.glob("*.json")):
        unsigned = json.loads(path.read_text(encoding="utf-8"))
        claimed = unsigned.pop("packet_sha256", None)
        actual = object_hash(unsigned)
        if claimed != actual or not path.name.endswith(f".{actual}.json"):
            raise ValueError(f"packet identity mismatch: {path.name}")
        packet = json.loads(
            CampaignFindingPacket.model_validate(unsigned).model_dump_json()
        )
        packet["packet_sha256"] = claimed
        packets.append(packet)
    external_ids = [packet["external_id"] for packet in packets]
    record_ids = [packet["record_id"] for packet in packets]
    if len(external_ids) != len(set(external_ids)) or len(record_ids) != len(
        set(record_ids)
    ):
        raise ValueError("duplicate/replayed packet")
    if not packets:
        raise ValueError("empty packet population")
    return packets


def write_bundle(source: Path, output: Path) -> dict:
    packets = load_packets(source)
    population = [packet["packet_sha256"] for packet in packets]
    output.parent.mkdir(parents=True, exist_ok=True)
    lock = output.with_suffix(output.suffix + ".lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ValueError("another campaign integrator is active") from exc
    try:
        os.close(descriptor)
        if output.exists():
            raise ValueError("candidate-generation request already exists")
        packets.sort(key=lambda packet: packet["record_id"])
        records = [
            {
                "record_id": packet["record_id"],
                "external_id": packet["external_id"],
                "source_locator": packet["source_locator"],
                "content_hash": packet["source_sha256"],
                "repository_id": packet["repository_id"],
                "component_id": packet["component_id"],
                "component_revision": packet["component_revision"],
                "platform": packet["platform"],
                "image": packet["image"],
                "configuration_sha256": packet["configuration_sha256"],
                "state": "STAGED",
                "project_relevance": "UNVALIDATED",
                "reason": "Immutable Metis output awaits firmware-pipeline exact-source validation.",
                "metis_status": packet["metis_status"],
                "metis_packet_sha256": packet["packet_sha256"],
                "campaign_route": packet["campaign_route"],
                "technical_class": "DEFERRED",
                "creates_root": False,
                "candidate_authorizes_production_or_governed_state": False,
            }
            for packet in packets
        ]
        bundle = {
            "format_version": "firmware-campaign-metis-staging-v1",
            "project_id": packets[0]["project_id"],
            "candidate_sha256": packets[0]["candidate_sha256"],
            "campaign_generation": packets[0]["campaign_generation"],
            "records": records,
            "records_sha256": object_hash(records),
            "packet_set_sha256": object_hash(population),
            "integrator_count": 1,
            "campaign_write_attempts": 0,
            "candidate_generation_required": True,
        }
        if any(
            packet[key] != packets[0][key]
            for packet in packets
            for key in (
                "project_id",
                "schema_contract_version",
                "candidate_sha256",
                "campaign_generation",
                "profile_sha256",
                "dependency_hashes",
                "build_graph_registry_sha256",
            )
        ):
            raise ValueError("packet project/candidate/generation mismatch")
        bundle["bundle_sha256"] = object_hash(bundle)
        fd, temp_name = tempfile.mkstemp(
            dir=output.parent, prefix=f".{output.name}.", suffix=".tmp"
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(
                bundle,
                stream,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, output)
        if [packet["packet_sha256"] for packet in load_packets(source)] != population:
            output.unlink(missing_ok=True)
            raise ValueError("packet population changed during atomic integration")
        return bundle
    finally:
        lock.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packet_dir", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        bundle = write_bundle(args.packet_dir, args.output)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        sys.stderr.write(str(exc))
        return 2
    print(json.dumps(bundle, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
