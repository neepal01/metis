# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json

from metis_firmware_campaign.analysis_packet import validate


H = "a" * 64


def _packet() -> dict:
    record = {
        "record_id": "scanner:1",
        "technical_class": "NO_BUG",
        "programme_scope": "UNRESOLVED",
        "scanner_claim_status": "UNSUPPORTED",
        "decision_status": "TERMINAL",
        "source_reread": True,
        "decisive_sources": [],
        "exact_counterevidence": "The represented operation is absent.",
        "exact_counterevidence_category": "CLAIMED_OPERATION_SINK_OR_EFFECT_ABSENT",
        "creates_root": False,
        "fp_no_bug_audit": {
            "primary_review_hash": "b" * 64,
            "blind_review_hash": "c" * 64,
            "primary_decision": "NO_BUG",
            "blind_decision": "NO_BUG",
            "arbitration_status": "AGREED",
            "arbitration_evidence_hash": "d" * 64,
        },
    }
    value = {
        "contract_version": "6.2",
        "campaign_write_attempts": 0,
        "authoritative_integrator": True,
        "records": [record],
    }
    value["packet_sha256"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return value


def test_v62_integrator_fails_without_blind_pair():
    packet = _packet()
    packet["records"][0].pop("fp_no_bug_audit")
    body = dict(packet)
    body.pop("packet_sha256")
    packet["packet_sha256"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    errors = validate(packet, {})
    assert "NO_BUG lacks primary/blind audit pair: scanner:1" in errors


def test_v62_integrator_rejects_uncategorized_counterevidence():
    packet = _packet()
    packet["records"][0]["exact_counterevidence_category"] = "OTHER"
    body = dict(packet)
    body.pop("packet_sha256")
    packet["packet_sha256"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    errors = validate(packet, {})
    assert "NO_BUG lacks exact counterevidence category: scanner:1" in errors
