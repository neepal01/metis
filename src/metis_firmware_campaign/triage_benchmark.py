# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Offline comparison for separately authorized baseline/head triage runs.

This module never invokes a model provider. It compares triage-only result files;
it cannot establish discovery recall or whole-pipeline superiority.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from metis_firmware_campaign.autonomous_campaign import object_hash

MANIFEST_FORMAT = "metis-triage-before-after-benchmark-v1"
RESULT_FORMAT = "metis-triage-before-after-results-v1"
VERDICTS = {"valid", "invalid", "inconclusive"}
RUN_CONTRACT_FIELDS = {
    "provider",
    "model",
    "token_budget",
    "graph_identity_sha256",
    "triage_configuration_sha256",
}


def _load(path: Path, expected_format: str) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get("format_version") != expected_format:
        raise ValueError(f"unexpected benchmark format: {path}")
    claimed = value.pop("content_sha256", None)
    if claimed != object_hash(value):
        raise ValueError(f"benchmark content identity mismatch: {path}")
    value["content_sha256"] = claimed
    return value


def _cases(manifest: dict) -> dict[str, dict]:
    if manifest.get("mode") != "TRIAGE_ONLY":
        raise ValueError("benchmark mode must be TRIAGE_ONLY")
    if manifest.get("provider_execution_authorized") is not False:
        raise ValueError("the offline harness cannot authorize provider execution")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("benchmark requires a non-empty case set")
    indexed = {}
    for case in cases:
        case_id = case.get("case_id") if isinstance(case, dict) else None
        if not case_id or case_id in indexed:
            raise ValueError("benchmark case IDs must be non-empty and unique")
        if case.get("expected_status") not in VERDICTS:
            raise ValueError(f"benchmark case has an invalid status: {case_id}")
        required = {
            "bucket",
            "expected_status",
            "source_revision",
            "source_identity_sha256",
            "sarif_record_sha256",
        }
        if required - set(case):
            raise ValueError(f"benchmark case is incomplete: {case_id}")
        indexed[case_id] = case
    return indexed


def _run_contract(manifest: dict) -> str:
    contract = manifest.get("run_contract")
    if not isinstance(contract, dict) or RUN_CONTRACT_FIELDS - set(contract):
        raise ValueError("benchmark run contract is incomplete")
    if (
        not contract.get("provider")
        or not contract.get("model")
        or isinstance(contract.get("token_budget"), bool)
        or not isinstance(contract.get("token_budget"), int)
        or contract["token_budget"] <= 0
    ):
        raise ValueError("benchmark run contract has invalid provider settings")
    for name in ("graph_identity_sha256", "triage_configuration_sha256"):
        value = contract.get(name)
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError(f"benchmark run contract has invalid {name}")
    return object_hash(contract)


def _observations(result: dict, manifest: dict) -> dict[str, dict]:
    if result.get("mode") != "TRIAGE_ONLY":
        raise ValueError("result mode must be TRIAGE_ONLY")
    if result.get("provider_execution_authorized") is not False:
        raise ValueError("result must not claim provider authorization")
    if result.get("manifest_sha256") != manifest["content_sha256"]:
        raise ValueError("benchmark result is bound to a different case manifest")
    if result.get("run_contract_sha256") != _run_contract(manifest):
        raise ValueError("benchmark result used different controlled run settings")
    if not result.get("implementation_revision"):
        raise ValueError("benchmark result lacks an implementation revision")
    case_ids = set(_cases(manifest))
    records = result.get("observations")
    if not isinstance(records, list):
        raise ValueError("benchmark result lacks observations")
    indexed = {}
    for record in records:
        case_id = record.get("case_id") if isinstance(record, dict) else None
        if not case_id or case_id in indexed or record.get("status") not in VERDICTS:
            raise ValueError("benchmark result has invalid observations")
        if not isinstance(record.get("citations_verified"), bool):
            raise ValueError("benchmark observation lacks citation verification")
        indexed[case_id] = record
    if set(indexed) != case_ids:
        raise ValueError("benchmark result population differs from the manifest")
    return indexed


def _metrics(cases: dict[str, dict], observations: dict[str, dict]) -> dict:
    totals = {
        "exact": 0,
        "false_valid": 0,
        "false_invalid": 0,
        "inconclusive_on_decisive": 0,
        "citation_failures": 0,
        "provider_calls": 0,
        "tool_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
    }
    for case_id, expected in cases.items():
        observed = observations[case_id]
        expected_status = expected["expected_status"]
        status = observed["status"]
        totals["exact"] += status == expected_status
        totals["false_valid"] += expected_status != "valid" and status == "valid"
        totals["false_invalid"] += expected_status == "valid" and status == "invalid"
        totals["inconclusive_on_decisive"] += (
            expected_status in {"valid", "invalid"} and status == "inconclusive"
        )
        totals["citation_failures"] += not observed["citations_verified"]
        for name in ("provider_calls", "tool_calls", "input_tokens", "output_tokens"):
            value = observed.get(name, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"benchmark observation has invalid {name}")
            totals[name] += value
    totals["total"] = len(cases)
    return totals


def compare(manifest: dict, baseline: dict, candidate: dict) -> dict:
    cases = _cases(manifest)
    baseline_metrics = _metrics(
        cases, _observations(baseline, manifest)
    )
    candidate_metrics = _metrics(
        cases, _observations(candidate, manifest)
    )
    quality_noninferior = all(
        (
            candidate_metrics["false_valid"] <= baseline_metrics["false_valid"],
            candidate_metrics["false_invalid"] <= baseline_metrics["false_invalid"],
            candidate_metrics["citation_failures"]
            <= baseline_metrics["citation_failures"],
            candidate_metrics["inconclusive_on_decisive"]
            <= baseline_metrics["inconclusive_on_decisive"],
            candidate_metrics["exact"] >= baseline_metrics["exact"],
        )
    )
    output = {
        "format_version": "metis-triage-before-after-comparison-v1",
        "mode": "TRIAGE_ONLY",
        "limitations": [
            "Does not measure discovery recall.",
            "Does not establish whole-pipeline superiority.",
            "Does not authorize provider execution or campaign decisions.",
        ],
        "manifest_sha256": manifest["content_sha256"],
        "run_contract_sha256": _run_contract(manifest),
        "baseline_revision": baseline.get("implementation_revision"),
        "candidate_revision": candidate.get("implementation_revision"),
        "baseline": baseline_metrics,
        "candidate": candidate_metrics,
        "quality_noninferior": quality_noninferior,
    }
    output["content_sha256"] = object_hash(output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--baseline-results", type=Path, required=True)
    parser.add_argument("--candidate-results", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            compare(
                _load(args.manifest, MANIFEST_FORMAT),
                _load(args.baseline_results, RESULT_FORMAT),
                _load(args.candidate_results, RESULT_FORMAT),
            ),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
