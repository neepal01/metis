# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest

from metis_firmware_campaign.autonomous_campaign import object_hash
from metis_firmware_campaign.triage_benchmark import compare


def seal(value: dict) -> dict:
    value["content_sha256"] = object_hash(value)
    return value


def test_triage_only_benchmark_reports_noninferiority_and_limitations() -> None:
    manifest = seal(
        {
            "format_version": "metis-triage-before-after-benchmark-v1",
            "mode": "TRIAGE_ONLY",
            "provider_execution_authorized": False,
            "run_contract": {
                "provider": "offline-fixture",
                "model": "fixed-model",
                "token_budget": 1000,
                "graph_identity_sha256": "f" * 64,
                "triage_configuration_sha256": "9" * 64,
            },
            "cases": [
                {
                    "case_id": "tp",
                    "bucket": "VALID_VULNERABILITY",
                    "expected_status": "valid",
                    "source_revision": "a" * 40,
                    "source_identity_sha256": "b" * 64,
                    "sarif_record_sha256": "c" * 64,
                },
                {
                    "case_id": "fp",
                    "bucket": "NO_BUG",
                    "expected_status": "invalid",
                    "source_revision": "a" * 40,
                    "source_identity_sha256": "d" * 64,
                    "sarif_record_sha256": "e" * 64,
                },
            ],
        }
    )
    baseline = seal(
        {
            "format_version": "metis-triage-before-after-results-v1",
            "mode": "TRIAGE_ONLY",
            "provider_execution_authorized": False,
            "implementation_revision": "baseline",
            "manifest_sha256": manifest["content_sha256"],
            "run_contract_sha256": object_hash(manifest["run_contract"]),
            "observations": [
                {"case_id": "tp", "status": "inconclusive", "citations_verified": True},
                {"case_id": "fp", "status": "invalid", "citations_verified": True},
            ],
        }
    )
    candidate = seal(
        {
            "format_version": "metis-triage-before-after-results-v1",
            "mode": "TRIAGE_ONLY",
            "provider_execution_authorized": False,
            "implementation_revision": "candidate",
            "manifest_sha256": manifest["content_sha256"],
            "run_contract_sha256": object_hash(manifest["run_contract"]),
            "observations": [
                {"case_id": "tp", "status": "valid", "citations_verified": True},
                {"case_id": "fp", "status": "invalid", "citations_verified": True},
            ],
        }
    )

    result = compare(manifest, baseline, candidate)

    assert result["quality_noninferior"] is True
    assert result["candidate"]["exact"] == 2
    assert "Does not measure discovery recall." in result["limitations"]

    candidate["run_contract_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="different controlled run settings"):
        compare(manifest, baseline, candidate)
