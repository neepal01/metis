# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Validate one non-authorizing exact-source worker/integrator packet."""

import argparse
import hashlib
import json
from pathlib import Path

CLASSES = {
    "NO_BUG",
    "HARDENING",
    "VALID_VULNERABILITY",
    "DEFERRED",
    "NO_RETAINED_PROPOSITION",
}
RELATIONS = {
    "EXACT_DUPLICATE",
    "RELATED_VARIANT",
    "RCA_DISTINCT_NEW_ROOT_CANDIDATE",
    "RCA_DISTINCT_NEW_ROOT",
}
PROOF = {
    "attacker_source",
    "input_delivery",
    "missing_control",
    "controlled_object",
    "security_sink",
    "concrete_effect",
    "boundary_configuration",
}
LAYERS = {
    "PROJECT_FINDINGS",
    "PROJECT_REPRODUCERS",
    "PROMOTED_ROOTS",
    "HISTORICAL_TICKETS_POCS",
    "CURRENT_TICKETS",
}
OBSERVATIONS = {"POSITIVE", "NEGATIVE_PATCHED", "CLEAN_RERUN"}
SCOPES = {"IN_SCOPE", "OOS", "NOT_APPLICABLE", "UNRESOLVED"}
SCANNER = {"SUPPORTED", "OVERSTATED", "UNSUPPORTED", "UNRESOLVED"}
EXACT_COMPARISONS = {
    "attacker_source",
    "entry_flow",
    "missing_control",
    "sink",
    "effect",
    "source",
    "configuration",
    "boundary",
    "dependencies",
}
COUNTEREVIDENCE_CATEGORIES = {
    "CHECK_DOMINATES_SINK", "PRODUCER_CANNOT_GENERATE",
    "GOVERNED_BUILD_EXCLUDES_PATH", "ARCHITECTURE_OR_INTEGER_WIDTH_DISPROVES",
    "OBJECT_LIFETIME_REMAINS_VALID", "SCANNER_WRONG_OBJECT_OR_API",
    "CLAIMED_OPERATION_SINK_OR_EFFECT_ABSENT",
}


def canon(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def sha_obj(value):
    return hashlib.sha256(canon(value)).hexdigest()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def content_hashes(value):
    hashes = set()
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
            hashes.add(current)
    return hashes


def validate(packet, source_bindings):
    errors = []
    records = packet.get("records", [])
    integrator = packet.get("authoritative_integrator") is True
    v62 = packet.get("contract_version") in {"6.2", "6.2.0", "6.3", "6.3.0", "6.4", "6.4.0", "6.5", "6.5.0", "6.6", "6.6.0", "6.6.1", "6.7", "6.7.0"}
    if not records or not isinstance(records, list):
        errors.append("records must be non-empty")
    if packet.get("campaign_write_attempts") != 0:
        errors.append("campaign/production write attempts must be zero")
    ids = []
    for record in records if isinstance(records, list) else []:
        rid = record.get("record_id")
        ids.append(rid)
        technical = record.get("technical_class")
        if technical not in CLASSES:
            errors.append(f"invalid technical class: {rid}")
        if record.get("programme_scope") not in SCOPES:
            errors.append(f"invalid programme scope: {rid}")
        if record.get("scanner_claim_status") not in SCANNER:
            errors.append(f"invalid scanner status: {rid}")
        terminal = record.get("decision_status") == "TERMINAL"
        if record.get("source_reread") is not True:
            errors.append(f"exact source was not reread: {rid}")
        sources = record.get("decisive_sources", [])
        if terminal and not sources:
            errors.append(f"terminal record lacks decisive source: {rid}")
        for source in sources:
            checkout = source_bindings.get(source.get("component_id"))
            checkout_root = Path(checkout or "/nonexistent").resolve()
            path = (checkout_root / str(source.get("path", ""))).resolve()
            try:
                path.relative_to(checkout_root)
            except ValueError:
                errors.append(f"decisive source escapes checkout: {rid}")
                continue
            if (
                not checkout
                or not path.is_file()
                or path.is_symlink()
                or sha(path) != source.get("file_sha256")
            ):
                errors.append(f"decisive source mismatch: {rid}")
        if terminal and technical == "VALID_VULNERABILITY":
            proof = record.get("proof_tuple", {})
            if set(proof) != PROOF or any(
                not isinstance(value, str) or not value.strip()
                for value in proof.values()
            ):
                errors.append(f"valid record lacks complete proof tuple: {rid}")
        if (
            terminal
            and technical == "NO_BUG"
            and not record.get("exact_counterevidence")
        ):
            errors.append(f"NO_BUG lacks exact counterevidence: {rid}")
        if terminal and technical == "NO_BUG" and v62 and record.get(
            "exact_counterevidence_category"
        ) not in COUNTEREVIDENCE_CATEGORIES:
            errors.append(f"NO_BUG lacks exact counterevidence category: {rid}")
        if integrator and terminal and technical == "NO_BUG" and v62:
            audit = record.get("fp_no_bug_audit", {})
            required = {"primary_review_hash", "blind_review_hash",
                        "primary_decision", "blind_decision",
                        "arbitration_status", "arbitration_evidence_hash"}
            if set(audit) != required or audit.get("primary_review_hash") == audit.get(
                "blind_review_hash"
            ) or any(len(str(audit.get(key, ""))) != 64 for key in
                     ("primary_review_hash", "blind_review_hash",
                      "arbitration_evidence_hash")):
                errors.append(f"NO_BUG lacks primary/blind audit pair: {rid}")
        if terminal and technical == "HARDENING" and not record.get("residual_defect"):
            errors.append(f"HARDENING lacks residual defect: {rid}")
        if technical == "DEFERRED" and not record.get("reopen_condition"):
            errors.append(f"DEFERRED lacks reopen condition: {rid}")
        relation = record.get("root_relationship")
        if technical == "VALID_VULNERABILITY":
            if not relation or relation.get("kind") not in RELATIONS:
                errors.append(f"valid record lacks root disposition: {rid}")
                continue
            kind = relation.get("kind")
            root_id = relation.get("root_id")
            dedup = record.get("five_layer_dedup", {})
            layers = dedup.get("layers", {})
            if (
                dedup.get("status") != "COMPLETE"
                or set(layers) != LAYERS
                or any(not content_hashes(value) for value in layers.values())
            ):
                errors.append(f"valid record lacks five-layer dedup: {rid}")
            if kind == "EXACT_DUPLICATE":
                comparisons = relation.get("comparisons", {})
                if (
                    not root_id
                    or relation.get("RCA_DISTINCT") is not False
                    or set(comparisons) != EXACT_COMPARISONS
                    or any(value != "MATCH" for value in comparisons.values())
                ):
                    errors.append(f"exact duplicate is not exact/RCA-same: {rid}")
            elif kind == "RELATED_VARIANT" and not root_id:
                errors.append(f"related variant lacks related root: {rid}")
            elif kind == "RCA_DISTINCT_NEW_ROOT_CANDIDATE":
                if root_id or relation.get("RCA_DISTINCT") is not True:
                    errors.append(f"new-root candidate lacks RCA_DISTINCT: {rid}")
                if not integrator and record.get("creates_root") is not False:
                    errors.append(f"worker created a root: {rid}")
            elif kind == "RCA_DISTINCT_NEW_ROOT" and (
                not integrator
                or not root_id
                or relation.get("RCA_DISTINCT") is not True
                or record.get("creates_root") is not True
            ):
                errors.append(f"invalid integrator root promotion: {rid}")
        if record.get("reproduction", {}).get("status") == "COMPLETE":
            reproduction = record["reproduction"]
            if set(reproduction.get("observations", {})) != OBSERVATIONS:
                errors.append(f"completed reproduction lacks controls: {rid}")
            if reproduction.get("level") == "PLATFORM_FAITHFUL_REPRODUCED" and (
                reproduction.get("blocker") is not None
                or not reproduction.get("required_target_detail")
            ):
                errors.append(f"faithful reproduction identity/blocker invalid: {rid}")
        if not integrator and record.get("creates_root") is not False:
            errors.append(f"non-integrator authorizes root creation: {rid}")
    if len(ids) != len(set(ids)):
        errors.append("record IDs duplicated")
    body = dict(packet)
    claimed = body.pop("packet_sha256", None)
    if claimed != sha_obj(body):
        errors.append("packet identity mismatch")
    return errors


def main():
    p = argparse.ArgumentParser()
    p.add_argument("packet")
    p.add_argument("--source", action="append", default=[])
    a = p.parse_args()
    bindings = {x.split("=", 1)[0]: x.split("=", 1)[1] for x in a.source}
    packet = json.loads(Path(a.packet).read_text())
    errors = validate(packet, bindings)
    print(
        json.dumps(
            {
                "result": "FAIL" if errors else "PASS",
                "records": len(packet.get("records", [])),
                "errors": errors,
            },
            sort_keys=True,
        )
    )
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
