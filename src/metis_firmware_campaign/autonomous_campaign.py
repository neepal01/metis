# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Restart-safe, profile-driven firmware campaign coordinator.

The coordinator owns stage ordering, identities, locks, receipts and human
blockers.  Project adapters own collection/build/execution details.  It never
stores credentials and only an AUTHORITATIVE_INTEGRATION adapter may replace
the one candidate database.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from metis_firmware_campaign.analysis_packet import validate as validate_analysis_packet

FORMAT = "firmware-autonomous-campaign-v1"
V6_OUTPUTS = {
    "collect-source": {"source-manifest.json", "active-source-membership.json", "indirect-call-inventory.json"},
    "collect-historical-tickets": {"historical-ticket-manifest.json", "ticket-source-relations.json", "connector-receipts.json"},
    "collect-current-tickets": {"current-ticket-manifest.json", "ticket-source-relations.json", "connector-receipts.json"},
    "collect-threat-policy": {"threat-policy-manifest.json", "connector-receipts.json"},
    "build-candidate": {"candidate-build.json", "contract-discovery.json", "exact-build-bindings.json", "knowledge-fts.json"},
    "metis-full": {"incremental-finalization.json", "rendered-prompt-receipts.json", "coverage-schedules.json", "context-cache-receipts.json"},
    "validate-packets": {"stage.json", "terminal-decision-capsules.json", "review-bindings.json"},
    "integrate": {"integration.packet.json", "root-fingerprints.json", "fts-index-receipt.json"},
    "reproduce": {"reproduction-frontier.json", "backend-capabilities.json", "rerun-manifests.json", "reproducer-reuse.json", "candidate-patch-state.json"},
}
V62_OUTPUTS = dict(V6_OUTPUTS)
V62_OUTPUTS["validate-packets"] = V6_OUTPUTS["validate-packets"] | {
    "fp-no-bug-audits.json",
    "classification-reopen-proposals.json",
    "terminal-change-anomaly-gate.json",
}
V63_OUTPUTS = dict(V62_OUTPUTS)
V63_OUTPUTS["collect-source"] |= {"documentation-manifest.json", "component-registry.json"}
V63_OUTPUTS["collect-threat-policy"] |= {"security-properties.json", "programme-rules.json", "advisory-fix-regression.json", "programme-threat-comparison.json"}
V63_OUTPUTS["build-candidate"] |= {"independent-rebuild.json"}
V63_OUTPUTS["integrate"] |= {"root-property-mappings.json", "variant-searches.json", "scope-invalidation.json"}
V63_OUTPUTS["reproduce"] |= {"control-triplets.json"}
V63_OUTPUTS["package-seal"] = {"candidate-a.db", "candidate-b.db", "candidate-a.dump", "candidate-b.dump", "report-a.md", "report-b.md", "delivery-a.json", "delivery-b.json", "packages-a/manifest.json", "packages-b/manifest.json", "validation-gates.json", "current-frontier.json", "final-receipts.json"}
V64_OUTPUTS = dict(V63_OUTPUTS)
V64_OUTPUTS["package-export"] = {"INDEX.json", "INDEX.md", "VALIDATION-RECEIPT.json"}
V65_OUTPUTS = dict(V64_OUTPUTS)
V65_OUTPUTS["severity-calibration"] = {"SEVERITY-INDEX.json", "SEVERITY-VALIDATION.json"}
V66_OUTPUTS = dict(V65_OUTPUTS)
V66_OUTPUTS["collect-threat-policy"] |= {"policy-reconciliation-input.json"}
V66_OUTPUTS["policy-reconciliation"] = {"POLICY-INDEX.json", "POC-EVIDENCE-INDEX.json", "NOVELTY-INDEX.json", "POLICY-VALIDATION.json"}
V661_OUTPUTS = dict(V66_OUTPUTS)
V661_OUTPUTS["population-report"] = {"POPULATION-SCOPED-REPORT.json", "POPULATION-SCOPED-REPORT.md"}
V67_OUTPUTS = dict(V661_OUTPUTS)
V67_OUTPUTS["existing-report-followup"] = {"EXISTING-REPORT-FOLLOWUP-INDEX.json", "EXISTING-REPORT-FOLLOWUP-INDEX.md", "FOLLOWUP-VALIDATION.json"}
PHASES = {
    "SOURCE_COLLECTION",
    "HISTORICAL_TICKET_COLLECTION",
    "CURRENT_TICKET_COLLECTION",
    "THREAT_POLICY_COLLECTION",
    "CANDIDATE_BUILD",
    "METIS_HEALTH",
    "METIS_CALIBRATION_1",
    "METIS_CALIBRATION_20",
    "METIS_CALIBRATION_100",
    "METIS_FULL_SCAN",
    "PACKET_VALIDATION",
    "AUTHORITATIVE_INTEGRATION",
    "REPRODUCTION",
    "PACKAGE_AND_SEAL",
}
PHASES_V64 = PHASES | {"PACKAGE_EXPORT"}
PHASES_V65 = PHASES_V64 | {"SEVERITY_CALIBRATION"}
PHASES_V66 = PHASES_V65 | {"POLICY_RECONCILIATION"}
PHASES_V661 = PHASES_V66 | {"POPULATION_SCOPED_REPORTING"}
PHASES_V67 = PHASES_V661 | {"EXISTING_REPORT_FOLLOWUP"}
HUMAN_CLASSES = {
    "EXTERNAL_CREDENTIAL_LICENCE_HARDWARE_DEPENDENCY",
    "OWNER_DISCLOSURE_DECISION",
    "GENUINE_UNRESOLVED_EVIDENCE",
}
TERMINAL = {"COMPLETE", "REUSED", "BLOCKED"}


class ContractError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def object_hash(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ContractError(f"{label} must be a regular non-symlink file: {path}")
    return path


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def absolute(base: Path, value: str) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else base / path).resolve()


def material_file(base: Path, value: str, label: str) -> dict:
    path = regular(absolute(base, value), label)
    inputs = {
        "locator": str(path),
        "sha256": file_hash(path),
        "size": path.stat().st_size,
    }


def parse_bindings(values: list[str], profile: dict) -> dict:
    bindings = {}
    components = {x["component_id"]: x for x in profile["project"]["components"]}
    for value in values:
        try:
            component_id, locator, revision = (
                value.split("=", 1)[0],
                value.split("=", 1)[1].rsplit("@", 1)[0],
                value.rsplit("@", 1)[1],
            )
        except (ValueError, IndexError):
            raise ContractError("source binding must be COMPONENT=URL_OR_PATH@REVISION")
        if component_id not in components:
            raise ContractError(
                f"source binding names unknown component: {component_id}"
            )
        if (
            components[component_id]["repository"] != locator
            or components[component_id]["revision"] != revision
        ):
            raise ContractError(
                f"source binding conflicts with profile: {component_id}"
            )
        bindings[component_id] = {"repository": locator, "revision": revision}
    return bindings


def source_paths(values: list[str], profile: dict) -> dict:
    known = {x["component_id"] for x in profile["project"]["components"]}
    output = {}
    for value in values:
        component_id, separator, locator = value.partition("=")
        if not separator or component_id not in known:
            raise ContractError(
                "source path must be COMPONENT=PATH for a profile component"
            )
        output[component_id] = str(Path(locator).resolve())
        path = Path(output[component_id])
        if path.is_symlink() or not path.is_dir():
            raise ContractError(
                f"source checkout must be a regular directory: {component_id}"
            )
    return output


def checkout_state(path: Path) -> dict:
    if (path / ".git").exists():
        command = ["git", "-C", str(path), "ls-files", "--stage", "-z"]
        listing = subprocess.check_output(command).split(b"\0")
        entries = []
        for raw in listing:
            if not raw:
                continue
            metadata, encoded_name = raw.split(b"\t", 1)
            mode = metadata.split(b" ", 1)[0].decode()
            entries.append((encoded_name.decode(), mode))
        entries.sort()
        revision = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
        ).strip()
        if subprocess.run(
            ["git", "-C", str(path), "diff", "--quiet", revision, "--"],
            capture_output=True,
            check=False,
        ).returncode:
            raise ContractError(f"source checkout has tracked modifications: {path}")
        tracked = {name for name, _mode in entries}
        if any(
            item.is_symlink()
            and ".git" not in item.relative_to(path).parts
            and str(item.relative_to(path)) not in tracked
            for item in path.rglob("*")
        ):
            raise ContractError(f"source checkout contains an untracked symlink: {path}")
    else:
        entries = sorted(
            (str(x.relative_to(path)), "100644")
            for x in path.rglob("*")
            if x.is_file() and not x.is_symlink()
        )
        revision = None
    manifest = []
    symlinks = []
    source_root = path.resolve()
    for name, mode in entries:
        item = path / name
        if mode != "120000":
            manifest.append(
                {"path": name, "sha256": file_hash(regular(item, "source tree entry"))}
            )
            continue
        if item.is_symlink():
            target = os.readlink(item)
        else:
            # Git materializes symlinks as their target text when core.symlinks=false.
            target = regular(item, "tracked symlink representation").read_text()
        if Path(target).is_absolute():
            raise ContractError(f"tracked symlink target must be relative: {name}")
        try:
            resolved = (item.parent / target).resolve(strict=True)
        except (FileNotFoundError, RuntimeError) as error:
            raise ContractError(f"tracked symlink is dangling or recursive: {name}") from error
        try:
            resolved.relative_to(source_root)
        except ValueError as error:
            raise ContractError(f"tracked symlink escapes source checkout: {name}") from error
        manifest.append({"path": name, "sha256": hashlib.sha256(target.encode()).hexdigest()})
        symlinks.append(
            {"path": name, "target": target, "target_sha256": file_hash(regular(resolved, "tracked symlink target"))}
        )
    return {
        "revision": revision,
        "files": len(manifest),
        "tree_sha256": object_hash(manifest),
        "tracked_symlink_count": len(symlinks),
        "tracked_symlink_manifest_sha256": object_hash(symlinks),
    }


def candidate_state(candidate: Path) -> dict:
    if not candidate.exists():
        return {"exists": False}
    regular(candidate, "candidate database")
    sidecars = [
        str(Path(str(candidate) + suffix))
        for suffix in ("-wal", "-shm", "-journal")
        if Path(str(candidate) + suffix).exists()
    ]
    if sidecars:
        raise ContractError(f"unexpected candidate sidecars: {sidecars}")
    return {
        "exists": True,
        "sha256": file_hash(candidate),
        "size": candidate.stat().st_size,
    }


def verify_profile(
    path: Path, candidate: Path, sources: dict, source_checkouts: dict
) -> tuple[dict, dict]:
    path = regular(path.resolve(), "project profile")
    profile = json.loads(path.read_text())
    if profile.get("schema_version") not in ("4", "5", "6", "6.2", "6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7"):
        raise ContractError("project profile schema_version must be 4, 5, 6, 6.2, 6.3, 6.4, 6.5, 6.6, 6.6.1, or 6.7")
    if not profile.get("project", {}).get("project_id") or not profile["project"].get(
        "components"
    ):
        raise ContractError("project profile lacks project/components")
    governance = profile.get("governance", {})
    if (
        governance.get("candidate_database_only") is not True
        or governance.get("production_write_target_configured") is not False
        or governance.get("production_write_attempts") != 0
    ):
        raise ContractError(
            "profile does not prove the candidate-only zero-write boundary"
        )
    production = governance.get("production_database")
    if production and absolute(path.parent, production) == candidate:
        raise ContractError(
            "candidate and production database resolve to the same path"
        )
    component_ids = {item["component_id"] for item in profile["project"]["components"]}
    if sources and set(sources) != component_ids:
        raise ContractError(
            "run requires one exact URL/revision binding for every profile component"
        )
    unknown_checkouts = set(source_checkouts) - component_ids
    if unknown_checkouts:
        raise ContractError(
            f"source paths name unknown components: {sorted(unknown_checkouts)}"
        )
    automation = profile.get("automation")
    if not automation or automation.get("format_version") != FORMAT:
        raise ContractError("profile lacks the generic automation contract")
    stages = automation.get("stages", [])
    if (
        not isinstance(automation.get("provider_worker_configuration_limit"), int)
        or not 1 <= automation["provider_worker_configuration_limit"] <= 100
    ):
        raise ContractError("provider worker configuration limit must be 1..100")
    if (
        not isinstance(automation.get("campaign_reader_limit"), int)
        or not 1 <= automation["campaign_reader_limit"] <= 11
    ):
        raise ContractError("campaign reader limit must be 1..11")
    ids = [item.get("stage_id") for item in stages]
    phases = [item.get("phase") for item in stages]
    expected_phases = PHASES_V67 if profile.get("schema_version") == "6.7" else (PHASES_V661 if profile.get("schema_version") == "6.6.1" else (PHASES_V66 if profile.get("schema_version") == "6.6" else (PHASES_V65 if profile.get("schema_version") == "6.5" else (PHASES_V64 if profile.get("schema_version") == "6.4" else PHASES))))
    if set(phases) != expected_phases or len(ids) != len(set(ids)) or None in ids:
        raise ContractError(
            "automation must define each generic phase exactly once with unique stage IDs"
        )
    for item in stages:
        builtin_export = item.get("phase") == "PACKAGE_EXPORT" and item.get("builtin") == "INTERNAL_TECHNICAL_PACKAGE_EXPORT" and not item.get("adapter")
        builtin_severity = item.get("phase") == "SEVERITY_CALIBRATION" and item.get("builtin") == "TECHNICAL_SEVERITY_CALIBRATION" and not item.get("adapter")
        builtin_policy = item.get("phase") == "POLICY_RECONCILIATION" and item.get("builtin") == "POLICY_PRECEDENCE_RECONCILIATION" and not item.get("adapter")
        builtin_reporting = item.get("phase") == "POPULATION_SCOPED_REPORTING" and item.get("builtin") == "POPULATION_SCOPED_SUMMARY" and not item.get("adapter")
        builtin_followup = item.get("phase") == "EXISTING_REPORT_FOLLOWUP" and item.get("builtin") == "EXISTING_REPORT_FOLLOWUP_ASSESSMENT" and not item.get("adapter")
        if item.get("phase") not in expected_phases or (not builtin_export and not builtin_severity and not builtin_policy and not builtin_reporting and not builtin_followup and (not isinstance(item.get("adapter"), list) or not item["adapter"])):
            raise ContractError(f"invalid adapter for stage {item.get('stage_id')}")
        if item.get("phase") == "PACKAGE_EXPORT" and not builtin_export:
            raise ContractError("PACKAGE_EXPORT must use the generic built-in exporter")
        if item.get("phase") == "SEVERITY_CALIBRATION" and not builtin_severity:
            raise ContractError("SEVERITY_CALIBRATION must use the generic built-in calibrator")
        if item.get("phase") == "POLICY_RECONCILIATION" and not builtin_policy:
            raise ContractError("POLICY_RECONCILIATION must use the generic built-in reconciler")
        if item.get("phase") == "POPULATION_SCOPED_REPORTING" and not builtin_reporting:
            raise ContractError("POPULATION_SCOPED_REPORTING must use the generic built-in reporter")
        if item.get("phase") == "EXISTING_REPORT_FOLLOWUP" and not builtin_followup:
            raise ContractError("EXISTING_REPORT_FOLLOWUP must use the generic built-in assessor")
        if not isinstance(item.get("depends_on", []), list) or set(
            item.get("depends_on", [])
        ) - set(ids):
            raise ContractError(f"unknown dependency for stage {item['stage_id']}")
        human = item.get("human_dependency")
        if human and human.get("class") not in HUMAN_CLASSES:
            raise ContractError(
                f"invalid human dependency class for {item['stage_id']}"
            )
        if item["phase"] == "PACKET_VALIDATION" and not item.get("worker_adapter"):
            raise ContractError("PACKET_VALIDATION requires a worker adapter")
        if not item.get("required_outputs") or not isinstance(
            item["required_outputs"], list
        ):
            raise ContractError(
                f"stage requires explicit output closure: {item['stage_id']}"
            )
    contract_release = None
    if profile.get("schema_version") in ("6", "6.2", "6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7"):
        contract_release = profile.get("contract_release")
        expected_release = ({
            "version": "6.7.0", "manifest": "AUTO_DISCOVER", "core_database_contract": "AUTO_DISCOVER",
            "capability_schema": "AUTO_DISCOVER", "accuracy_contract": "AUTO_DISCOVER",
            "accuracy_schema_extension": "AUTO_DISCOVER", "knowledge_contract": "AUTO_DISCOVER",
            "knowledge_schema_extension": "AUTO_DISCOVER", "severity_contract": "AUTO_DISCOVER",
            "policy_contract": "AUTO_DISCOVER", "policy_schema_extension": "AUTO_DISCOVER",
            "reporting_contract": "AUTO_DISCOVER", "followup_contract": "AUTO_DISCOVER", "automatic": True,
        } if profile.get("schema_version") == "6.7" else {
            "version": "6.6.1", "manifest": "AUTO_DISCOVER", "core_database_contract": "AUTO_DISCOVER",
            "capability_schema": "AUTO_DISCOVER", "accuracy_contract": "AUTO_DISCOVER",
            "accuracy_schema_extension": "AUTO_DISCOVER", "knowledge_contract": "AUTO_DISCOVER",
            "knowledge_schema_extension": "AUTO_DISCOVER", "severity_contract": "AUTO_DISCOVER",
            "policy_contract": "AUTO_DISCOVER", "policy_schema_extension": "AUTO_DISCOVER",
            "reporting_contract": "AUTO_DISCOVER", "automatic": True,
        } if profile.get("schema_version") == "6.6.1" else {
            "version": "6.6.0", "manifest": "AUTO_DISCOVER", "core_database_contract": "AUTO_DISCOVER",
            "capability_schema": "AUTO_DISCOVER", "accuracy_contract": "AUTO_DISCOVER",
            "accuracy_schema_extension": "AUTO_DISCOVER", "knowledge_contract": "AUTO_DISCOVER",
            "knowledge_schema_extension": "AUTO_DISCOVER", "severity_contract": "AUTO_DISCOVER",
            "policy_contract": "AUTO_DISCOVER", "policy_schema_extension": "AUTO_DISCOVER", "automatic": True,
        } if profile.get("schema_version") == "6.6" else {
            "version": "6.5.0", "manifest": "AUTO_DISCOVER", "core_database_contract": "AUTO_DISCOVER",
            "capability_schema": "AUTO_DISCOVER", "accuracy_contract": "AUTO_DISCOVER",
            "accuracy_schema_extension": "AUTO_DISCOVER", "knowledge_contract": "AUTO_DISCOVER",
            "knowledge_schema_extension": "AUTO_DISCOVER", "severity_contract": "AUTO_DISCOVER", "automatic": True,
        } if profile.get("schema_version") == "6.5" else {
            "version": "6.4.0", "manifest": "AUTO_DISCOVER",
            "core_database_contract": "AUTO_DISCOVER",
            "capability_schema": "AUTO_DISCOVER",
            "accuracy_contract": "AUTO_DISCOVER",
            "accuracy_schema_extension": "AUTO_DISCOVER",
            "knowledge_contract": "AUTO_DISCOVER",
            "knowledge_schema_extension": "AUTO_DISCOVER", "automatic": True,
        } if profile.get("schema_version") == "6.4" else {
            "version": "6.3.0", "manifest": "AUTO_DISCOVER",
            "core_database_contract": "AUTO_DISCOVER",
            "capability_schema": "AUTO_DISCOVER",
            "accuracy_contract": "AUTO_DISCOVER",
            "accuracy_schema_extension": "AUTO_DISCOVER",
            "knowledge_contract": "AUTO_DISCOVER",
            "knowledge_schema_extension": "AUTO_DISCOVER", "automatic": True,
        } if profile.get("schema_version") == "6.3" else {
            "version": "6.2.0", "manifest": "AUTO_DISCOVER",
            "core_database_contract": "AUTO_DISCOVER",
            "capability_schema": "AUTO_DISCOVER",
            "accuracy_contract": "AUTO_DISCOVER",
            "accuracy_schema_extension": "AUTO_DISCOVER", "automatic": True,
        } if profile.get("schema_version") == "6.2" else {
            "version": "6.0.0", "manifest": "AUTO_DISCOVER",
            "core_database_contract": "AUTO_DISCOVER",
            "capability_schema": "AUTO_DISCOVER", "automatic": True,
        })
        if contract_release != expected_release:
            raise ContractError("schema-v6 profile does not request automatic release discovery")
        discovery = Path(__file__).resolve().parents[2].parent / "portable-firmware-campaign/.agents/skills/firmware-campaign-bootstrap/scripts/discover_contract.py"
        found = json.loads(subprocess.check_output([sys.executable, str(discovery)], text=True))
        allowed_versions = {"6.7.0"} if profile.get("schema_version") == "6.7" else ({"6.6.1", "6.7.0"} if profile.get("schema_version") == "6.6.1" else ({"6.6.0", "6.6.1", "6.7.0"} if profile.get("schema_version") == "6.6" else ({"6.5.0", "6.6.0", "6.6.1", "6.7.0"} if profile.get("schema_version") == "6.5" else ({"6.4.0", "6.5.0", "6.6.0", "6.6.1", "6.7.0"} if profile.get("schema_version") == "6.4" else ({"6.3.0", "6.4.0", "6.5.0", "6.6.0", "6.6.1", "6.7.0"} if profile.get("schema_version") == "6.3" else ({"6.2.0", "6.3.0", "6.4.0", "6.5.0", "6.6.0", "6.6.1", "6.7.0"} if profile.get("schema_version") == "6.2" else {"6.0.0", "6.2.0", "6.3.0", "6.4.0", "6.5.0", "6.6.0", "6.6.1", "6.7.0"}))))))
        if found.get("contract_version") not in allowed_versions:
            raise ContractError("installed capability release does not satisfy profile")
        contract_release = {**contract_release, "installed_release_hashes": [x["release_hash"] for x in found["skills"]]}
        connectors = automation.get("connectors", [])
        if {item.get("kind") for item in connectors} != {"TICKET", "JIRA", "INTIGRITI", "CONFLUENCE"} or any(item.get("read_only") is not True for item in connectors):
            raise ContractError("schema-v6 connector contract incomplete")
        outputs = V67_OUTPUTS if profile.get("schema_version") == "6.7" else (V661_OUTPUTS if profile.get("schema_version") == "6.6.1" else (V66_OUTPUTS if profile.get("schema_version") == "6.6" else (V65_OUTPUTS if profile.get("schema_version") == "6.5" else (V64_OUTPUTS if profile.get("schema_version") == "6.4" else (V63_OUTPUTS if profile.get("schema_version") == "6.3" else (V62_OUTPUTS if profile.get("schema_version") == "6.2" else V6_OUTPUTS))))))
        for stage_id, expected in outputs.items():
            actual = next(
                (set(item["required_outputs"]) for item in stages if item["stage_id"] == stage_id),
                None,
            )
            if actual != expected:
                raise ContractError(f"schema-v6 output closure mismatch: {stage_id}")
    if profile.get("schema_version") in ("5", "6", "6.2", "6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7"):
        components = {x["component_id"]: x for x in profile["project"]["components"]}
        required_checkouts = ({x["component_id"] for x in profile["project"]["components"] if x.get("source_checkout_required", True)} if profile.get("schema_version") in ("6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7") else set(components))
        if set(source_checkouts) != required_checkouts:
            raise ContractError(
                "schema-v5 runs require one checkout for every component"
            )
        for component_id, locator in source_checkouts.items():
            observed = checkout_state(Path(locator))
            if (
                observed["revision"]
                and observed["revision"] != components[component_id]["revision"]
            ):
                raise ContractError(f"source revision changed: {component_id}")
            if observed["tree_sha256"] != components[component_id]["tree_sha256"]:
                raise ContractError(f"source tree content changed: {component_id}")
    identity = {"locator": str(path), "sha256": file_hash(path)}
    if contract_release:
        identity["contract_release"] = contract_release
    return profile, identity


def redact(value: str, credential_names: list[str]) -> str:
    for name in credential_names:
        secret = os.environ.get(name)
        if secret:
            value = value.replace(secret, "<redacted>")
    return value


def receipt(path: Path) -> dict | None:
    if not path.exists():
        return None
    data = json.loads(regular(path, "stage receipt").read_text())
    claimed = data.pop("receipt_sha256", None)
    if claimed != object_hash(data):
        raise ContractError(f"stage receipt identity mismatch: {path}")
    data["receipt_sha256"] = claimed
    return data


def stage_inputs(
    stage: dict,
    profile: dict,
    profile_identity: dict,
    state: Path,
    candidate: Path,
    sources: dict,
    checkouts: dict,
    selectors: dict,
    dependency_receipts: dict,
) -> dict:
    base = Path(profile_identity["locator"]).parent
    files = [
        material_file(base, value, f"stage input {value}")
        for value in stage.get("input_files", [])
    ]
    adapter = stage.get("adapter", [])
    adapter_files = []
    for value in adapter:
        if "{" in value:
            continue
        path = absolute(base, value)
        if path.is_file() and not path.is_symlink():
            adapter_files.append({"locator": str(path), "sha256": file_hash(path)})
    adapter_identity = object_hash({"argv": adapter, "files": adapter_files})
    inputs = {
        "format_version": FORMAT,
        "project_id": profile["project"]["project_id"],
        "profile_sha256": profile_identity["sha256"],
        "stage_id": stage["stage_id"],
        "phase": stage["phase"],
        "adapter_sha256": adapter_identity,
        "source_bindings": sources,
        "source_checkouts": checkouts,
        "selectors": selectors,
        "input_files": files,
        "dependencies": {
            key: dependency_receipts[key]["receipt_sha256"]
            for key in sorted(dependency_receipts)
        },
        "profile_schema_version": profile["schema_version"],
        "contract_release": profile_identity.get("contract_release"),
    }
    # The candidate is an output of authoritative integration.  Making its
    # mutable state an input to every stage invalidates already-completed
    # provider work on the first resume.  Pre-6.3 profiles retain their frozen
    # identity semantics; 6.3 relies on explicit dependency receipts instead.
    if profile.get("schema_version") not in {"6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7"} or stage["phase"] in {"PACKAGE_EXPORT", "POPULATION_SCOPED_REPORTING", "EXISTING_REPORT_FOLLOWUP"}:
        inputs["candidate_before"] = candidate_state(candidate)
    return inputs


def check_human(stage: dict, base: Path) -> tuple[str | None, dict | None]:
    missing_credentials = sorted(
        name for name in stage.get("credential_env", []) if not os.environ.get(name)
    )
    if missing_credentials:
        return "EXTERNAL_CREDENTIAL_LICENCE_HARDWARE_DEPENDENCY", {
            "missing_credential_env": missing_credentials
        }
    human = stage.get("human_dependency")
    if not human:
        return None, None
    evidence = human.get("evidence")
    if evidence:
        path = absolute(base, evidence)
        if (
            path.is_file()
            and not path.is_symlink()
            and (not human.get("sha256") or file_hash(path) == human["sha256"])
        ):
            return None, None
    return human["class"], {
        key: value for key, value in human.items() if key not in {"sha256"}
    }


def run_command(
    command: list[str], context: dict, work: Path, credentials: list[str]
) -> None:
    context = {**context, "output_directory": str(work)}
    context_path = work / "context.json"
    atomic_json(context_path, context)
    variables = {
        "context": str(context_path),
        "output_dir": str(work),
        "candidate": context["candidate_path"],
        "reader_limit": str(context["reader_limit"]),
    }
    argv = [item.format(**variables) for item in command]
    env = os.environ.copy()
    env["FIRMWARE_CAMPAIGN_CONTEXT"] = str(context_path)
    env["CAMPAIGN_DATABASE_URI"] = (
        f"file:{context['candidate_path']}?mode=ro&immutable=1"
    )
    env["CAMPAIGN_READER_LIMIT"] = str(context["reader_limit"])
    env["METIS_FIRMWARE_PROVIDER_CHECKPOINT_ROOT"] = context[
        "provider_checkpoint_root"
    ]
    result = subprocess.run(
        argv,
        cwd=context["project_directory"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    (work / "stdout.log").write_text(redact(result.stdout, credentials))
    (work / "stderr.log").write_text(redact(result.stderr, credentials))
    if result.returncode:
        raise ContractError(f"adapter failed ({result.returncode}): {command[0]}")


def package_exporter_path() -> Path:
    local = Path(__file__).resolve().parents[1].parent / "firmware-campaign-bootstrap/scripts/export_internal_review_packages.py"
    workspace = Path(__file__).resolve().parents[2].parent / "portable-firmware-campaign/.agents/skills/firmware-campaign-bootstrap/scripts/export_internal_review_packages.py"
    for path in (local, workspace):
        if path.is_file() and not path.is_symlink():
            return path
    raise ContractError("capability-6.4 generic package exporter is unavailable")


def run_package_export(context: dict, work: Path) -> None:
    candidate_hash = context.get("candidate_before", {}).get("sha256")
    if not candidate_hash:
        raise ContractError("PACKAGE_EXPORT requires an immutable candidate identity")
    command = [sys.executable, str(package_exporter_path()),
               "--profile", context["profile_locator"],
               "--candidate", context["candidate_path"],
               "--project-directory", context["project_directory"],
               "--output", str(work), "--expected-candidate-sha256", candidate_hash]
    for component, path in sorted(context["source_checkouts"].items()):
        command += ["--source-path", f"{component}={path}"]
    for values in context.get("dependency_outputs", {}).values():
        if any(item["locator"].endswith("SEVERITY-INDEX.json") for item in values):
            command += ["--severity-path", str(Path(values[0]["locator"]).parent)]
        if any(item["locator"].endswith("POLICY-INDEX.json") for item in values):
            command += ["--policy-path", str(Path(values[0]["locator"]).parent)]
        if any(item["locator"].endswith("EXISTING-REPORT-FOLLOWUP-INDEX.json") for item in values):
            command += ["--followup-path", str(Path(values[0]["locator"]).parent)]
    result = subprocess.run(command, cwd=context["project_directory"], text=True,
                            capture_output=True, check=False)
    (work / "stdout.log").write_text(result.stdout)
    (work / "stderr.log").write_text(result.stderr)
    if result.returncode:
        raise ContractError(f"generic package export failed: {result.stderr.strip()}")


def run_severity_calibration(context: dict, work: Path) -> None:
    script = package_exporter_path().with_name("calibrate_severity.py")
    result = subprocess.run([sys.executable, str(script), "--profile", context["profile_locator"],
                             "--candidate", context["candidate_path"], "--output", str(work)],
                            cwd=context["project_directory"], text=True, capture_output=True, check=False)
    (work / "stdout.log").write_text(result.stdout);(work / "stderr.log").write_text(result.stderr)
    if result.returncode:raise ContractError(f"generic severity calibration failed: {result.stderr.strip()}")


def run_policy_reconciliation(context: dict, work: Path) -> None:
    script = package_exporter_path().with_name("reconcile_policy_scope.py")
    evidence = [Path(item["locator"]) for values in context["dependency_outputs"].values() for item in values if item["locator"].endswith("policy-reconciliation-input.json")]
    if len(evidence) != 1:
        raise ContractError("POLICY_RECONCILIATION requires exactly one collected policy input")
    result = subprocess.run([sys.executable, str(script), "--candidate", context["candidate_path"], "--evidence", str(evidence[0]), "--project-directory", context["project_directory"], "--output", str(work)], cwd=context["project_directory"], text=True, capture_output=True, check=False)
    (work / "stdout.log").write_text(result.stdout);(work / "stderr.log").write_text(result.stderr)
    if result.returncode:raise ContractError(f"generic policy reconciliation failed: {result.stderr.strip()}")


def run_population_scoped_reporting(context: dict, work: Path) -> None:
    script = package_exporter_path().with_name("population_scoped_reporting.py")
    candidate_hash = context.get("candidate_before", {}).get("sha256")
    if not candidate_hash:
        raise ContractError("POPULATION_SCOPED_REPORTING requires an immutable candidate identity")
    result = subprocess.run([sys.executable, str(script), context["candidate_path"],
                             "--expected-candidate-sha256", candidate_hash,
                             "--output-json", str(work / "POPULATION-SCOPED-REPORT.json"),
                             "--output-markdown", str(work / "POPULATION-SCOPED-REPORT.md")],
                            cwd=context["project_directory"], text=True, capture_output=True, check=False)
    (work / "stdout.log").write_text(result.stdout);(work / "stderr.log").write_text(result.stderr)
    if result.returncode:raise ContractError(f"generic population-scoped reporting failed: {result.stderr.strip()}")


def run_existing_report_followup(context: dict, work: Path) -> None:
    script = package_exporter_path().with_name("assess_existing_report_followup.py")
    candidate_hash = context.get("candidate_before", {}).get("sha256")
    if not candidate_hash:
        raise ContractError("EXISTING_REPORT_FOLLOWUP requires an immutable candidate identity")
    command = [sys.executable, str(script), "--candidate", context["candidate_path"],
               "--profile", context["profile_locator"], "--project-directory", context["project_directory"],
               "--output", str(work), "--expected-candidate-sha256", candidate_hash]
    routing = [item["locator"] for item in context.get("input_files", []) if item["locator"].endswith("INTERNAL-PSIRT-ROUTING-INDEX.json")]
    if len(routing) > 1:
        raise ContractError("EXISTING_REPORT_FOLLOWUP has ambiguous routing evidence")
    if routing:
        command += ["--routing-evidence", routing[0]]
    result = subprocess.run(command, cwd=context["project_directory"], text=True, capture_output=True, check=False)
    (work / "stdout.log").write_text(result.stdout);(work / "stderr.log").write_text(result.stderr)
    if result.returncode:raise ContractError(f"generic existing-report follow-up failed: {result.stderr.strip()}")


def worker_run(
    worker: int,
    command: list[str],
    context: dict,
    stage_work: Path,
    credentials: list[str],
) -> dict:
    work = stage_work / "workers" / f"worker-{worker:02d}"
    work.mkdir(parents=True)
    run_command(command, {**context, "worker_id": worker}, work, credentials)
    packets = []
    for path in sorted(work.glob("*.packet.json")):
        packet = json.loads(path.read_text())
        errors = (
            ["schema-v6 packet omitted capability contract"]
            if context.get("profile_schema_version") in ("6", "6.2", "6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7")
            and packet.get("contract_version") not in ({"6"} if context.get("profile_schema_version") == "6" else ({"6.2", "6.2.0"} if context.get("profile_schema_version") == "6.2" else ({"6.3", "6.3.0"} if context.get("profile_schema_version") == "6.3" else ({"6.4", "6.4.0"} if context.get("profile_schema_version") == "6.4" else ({"6.5", "6.5.0"} if context.get("profile_schema_version") == "6.5" else ({"6.6", "6.6.0", "6.6.1"} if context.get("profile_schema_version") in {"6.6","6.6.1"} else {"6.7", "6.7.0"}))))))
            else []
        ) + validate_analysis_packet(packet, context["source_checkouts"])
        if errors or packet.get("authoritative_integrator") is True:
            raise ContractError(f"worker {worker} analysis packet failed: {errors}")
        packets.append(
            {"locator": str(path.relative_to(stage_work)), "sha256": file_hash(path)}
        )
    if not packets:
        raise ContractError(
            f"worker {worker} produced no content-hashed analysis packet"
        )
    return {
        "worker": worker,
        "packets": packets,
        "outputs_sha256": object_hash(packets),
    }


def execute_stage(
    stage: dict,
    profile: dict,
    profile_identity: dict,
    state: Path,
    candidate: Path,
    sources: dict,
    checkouts: dict,
    selectors: dict,
    dependency_receipts: dict,
) -> dict:
    inputs = stage_inputs(
        stage,
        profile,
        profile_identity,
        state,
        candidate,
        sources,
        checkouts,
        selectors,
        dependency_receipts,
    )
    identity = object_hash(inputs)
    stage_root = state / "stages" / stage["stage_id"]
    final = stage_root / identity
    current = receipt(final / "receipt.json")
    if current:
        for item in current.get("outputs", []):
            path = regular(final / item["locator"], "reused stage output")
            if file_hash(path) != item["sha256"]:
                raise ContractError(
                    f"completed stage output changed: {stage['stage_id']}"
                )
        return current
    if any(
        dep["status"] not in {"COMPLETE", "REUSED"}
        for dep in dependency_receipts.values()
    ) and not stage.get("continue_on_blocked_dependencies", False):
        block = {
            "stage_id": stage["stage_id"],
            "stage_identity": identity,
            "status": "BLOCKED",
            "class": "GENUINE_UNRESOLVED_EVIDENCE",
            "reason": "A content-bound prerequisite is blocked.",
            "input_sha256": object_hash(inputs),
            "human_request_emitted": False,
        }
        block["receipt_sha256"] = object_hash(block)
        final.mkdir(parents=True)
        atomic_json(final / "receipt.json", block)
        return block
    human_class, detail = check_human(stage, Path(profile_identity["locator"]).parent)
    if human_class:
        blocker_id = object_hash({"class": human_class, "detail": detail})
        shared = state / "blockers" / f"{blocker_id}.json"
        first = not shared.exists()
        blocker = {
            "blocker_id": blocker_id,
            "class": human_class,
            "reason": stage.get("blocker", "Required external input is unavailable."),
            "detail": detail,
            "human_request_emitted": bool(
                first and human_class != "GENUINE_UNRESOLVED_EVIDENCE"
            ),
        }
        if first:
            atomic_json(shared, blocker)
        block = {
            "stage_id": stage["stage_id"],
            "stage_identity": identity,
            "status": "BLOCKED",
            **blocker,
            "input_sha256": object_hash(inputs),
        }
        block["receipt_sha256"] = object_hash(block)
        final.mkdir(parents=True)
        atomic_json(final / "receipt.json", block)
        return block
    stage_root.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(
        tempfile.mkdtemp(dir=stage_root.parent, prefix=f".{stage['stage_id']}.")
    )
    lock_descriptor = None
    try:
        writer = stage["phase"] in {"CANDIDATE_BUILD", "AUTHORITATIVE_INTEGRATION", "SEVERITY_CALIBRATION", "POLICY_RECONCILIATION"}
        if writer:
            lock_path = state / "authoritative-integrator.lock"
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            lock_descriptor = lock_path.open("a+")
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = candidate_state(candidate)
        dependency_outputs = {}
        for dep, value in dependency_receipts.items():
            root = state / "stages" / dep / value["stage_identity"]
            dependency_outputs[dep] = [
                {**item, "locator": str(root / item["locator"])}
                for item in value.get("outputs", [])
            ]
        context = {
            **inputs,
            "candidate_path": str(candidate),
            "profile_locator": profile_identity["locator"],
            "project_directory": str(Path(profile_identity["locator"]).parent),
            "reader_limit": min(
                int(profile["automation"].get("campaign_reader_limit", 11)), 11
            ),
            "provider_worker_configuration_limit": profile["automation"][
                "provider_worker_configuration_limit"
            ],
            "output_directory": str(temp),
            "dependency_outputs": dependency_outputs,
            "authoritative_integrator": stage["phase"] in {"AUTHORITATIVE_INTEGRATION", "SEVERITY_CALIBRATION", "POLICY_RECONCILIATION"},
            # This directory survives a failed stage workspace. Metis review
            # checkpoints commit each provider result into it synchronously.
            "provider_checkpoint_root": str(
                state / "provider-results" / stage["stage_id"] / identity
            ),
        }
        Path(context["provider_checkpoint_root"]).mkdir(parents=True, exist_ok=True)
        credentials = stage.get("credential_env", [])
        if stage["phase"] == "PACKET_VALIDATION":
            reader_count = context["reader_limit"]
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=reader_count
            ) as pool:
                workers = [
                    pool.submit(
                        worker_run,
                        worker,
                        stage["worker_adapter"],
                        context,
                        temp,
                        credentials,
                    )
                    for worker in range(reader_count)
                ]
                worker_receipts = [future.result() for future in workers]
            atomic_json(
                temp / "worker-packets.json",
                {
                    "reader_count": reader_count,
                    "authoritative_integrators": 1,
                    "workers": worker_receipts,
                },
            )
        if stage["phase"] == "PACKAGE_EXPORT":
            run_package_export(context, temp)
        elif stage["phase"] == "SEVERITY_CALIBRATION":
            run_severity_calibration(context, temp)
        elif stage["phase"] == "POLICY_RECONCILIATION":
            run_policy_reconciliation(context, temp)
        elif stage["phase"] == "POPULATION_SCOPED_REPORTING":
            run_population_scoped_reporting(context, temp)
        elif stage["phase"] == "EXISTING_REPORT_FOLLOWUP":
            run_existing_report_followup(context, temp)
        else:
            run_command(stage["adapter"], context, temp, credentials)
        after = candidate_state(candidate)
        if not writer and after != before:
            raise ContractError(
                f"non-authoritative stage changed candidate: {stage['stage_id']}"
            )
        if (
            stage["phase"] == "AUTHORITATIVE_INTEGRATION"
            and after.get("exists")
            and before == after
            and not stage.get("idempotent_noop_allowed", False)
        ):
            # Integrating a no-op batch is legal only when explicitly identified as replay.
            raise ContractError(
                "authoritative integrator produced no new candidate identity"
            )
        if stage["phase"] == "CANDIDATE_BUILD" and not after.get("exists"):
            raise ContractError(
                "candidate builder did not generate the project candidate"
            )
        outputs = []
        ignored = {"context.json", "stdout.log", "stderr.log"}
        for path in sorted(temp.rglob("*")):
            if path.is_file() and path.name not in ignored:
                outputs.append(
                    {
                        "locator": str(path.relative_to(temp)),
                        "sha256": file_hash(path),
                        "size": path.stat().st_size,
                    }
                )
        if not outputs:
            raise ContractError(
                f"stage produced no immutable output: {stage['stage_id']}"
            )
        if stage["phase"] == "AUTHORITATIVE_INTEGRATION":
            integrator_packets = sorted(temp.glob("*.packet.json"))
            if not integrator_packets:
                raise ContractError(
                    "authoritative integrator produced no integration packet"
                )
            source_records = {}
            for dep, items in dependency_outputs.items():
                for item in items:
                    if not item["locator"].endswith(".packet.json"):
                        continue
                    packet = json.loads(
                        regular(Path(item["locator"]), "worker packet").read_text()
                    )
                    for record in packet["records"]:
                        if record["record_id"] in source_records:
                            raise ContractError(
                                "worker packet assignment duplicated a record"
                            )
                        source_records[record["record_id"]] = record
            integrated = {}
            for path in integrator_packets:
                packet = json.loads(path.read_text())
                errors = (
                    ["schema-v6 packet omitted capability contract"]
                    if profile.get("schema_version") in ("6", "6.2", "6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7")
                    and packet.get("contract_version") not in ({"6"} if profile.get("schema_version") == "6" else ({"6.2", "6.2.0"} if profile.get("schema_version") == "6.2" else ({"6.3", "6.3.0"} if profile.get("schema_version") == "6.3" else ({"6.4", "6.4.0"} if profile.get("schema_version") == "6.4" else ({"6.5", "6.5.0"} if profile.get("schema_version") == "6.5" else ({"6.6", "6.6.0", "6.6.1"} if profile.get("schema_version") in {"6.6","6.6.1"} else {"6.7", "6.7.0"}))))))
                    else []
                ) + validate_analysis_packet(packet, checkouts)
                if errors or packet.get("authoritative_integrator") is not True:
                    raise ContractError(f"integrator packet failed: {errors}")
                for record in packet["records"]:
                    if record["record_id"] in integrated:
                        raise ContractError("integrator duplicated a record")
                    integrated[record["record_id"]] = record
            if set(integrated) != set(source_records):
                raise ContractError(
                    "integrator packet cardinality differs from worker packets"
                )
            axes = ("decision_status", "technical_class")
            if any(
                any(integrated[rid].get(k) != source_records[rid].get(k) for k in axes)
                for rid in integrated
            ):
                raise ContractError(
                    "integrator mechanically recoded a worker technical result"
                )
            for rid, record in integrated.items():
                if (
                    record.get("creates_root") is True
                    and source_records[rid].get("root_relationship", {}).get("kind")
                    != "RCA_DISTINCT_NEW_ROOT_CANDIDATE"
                ):
                    raise ContractError(
                        "integrator root creation lacks a worker RCA-distinct candidate"
                    )
        available = {item["locator"]: item for item in outputs}
        if set(stage["required_outputs"]) - set(available):
            raise ContractError(f"stage omitted required outputs: {stage['stage_id']}")
        for pair in stage.get("deterministic_pairs", []):
            if (
                len(pair) != 2
                or pair[0] not in available
                or pair[1] not in available
                or available[pair[0]]["sha256"] != available[pair[1]]["sha256"]
            ):
                raise ContractError(
                    f"stage deterministic output pair differs: {stage['stage_id']}:{pair}"
                )
        body = {
            "stage_id": stage["stage_id"],
            "phase": stage["phase"],
            "stage_identity": identity,
            "status": "COMPLETE",
            "input_sha256": object_hash(inputs),
            "outputs": outputs,
            "candidate_before": before,
            "candidate_after": after,
            "campaign_write_attempts": 0
            if stage["phase"] != "AUTHORITATIVE_INTEGRATION"
            else stage.get("campaign_write_attempts", 0),
        }
        body["receipt_sha256"] = object_hash(body)
        atomic_json(temp / "receipt.json", body)
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(temp, final)
        return body
    except BaseException:
        failed = state / "failed-stages" / stage["stage_id"] / identity
        if not failed.exists():
            failed.parent.mkdir(parents=True, exist_ok=True)
            os.replace(temp, failed)
        raise
    finally:
        if lock_descriptor:
            lock_descriptor.close()
        if temp.exists():
            shutil.rmtree(temp)


def run(args: argparse.Namespace) -> dict:
    candidate = Path(args.candidate).resolve()
    selector_files = [
        material_file(Path.cwd(), x, "selector")
        for x in args.ticket_selector + args.confluence_selector
    ]
    preliminary = json.loads(
        regular(args.project_profile.resolve(), "project profile").read_text()
    )
    bindings = parse_bindings(args.source, preliminary)
    checkouts = source_paths(args.source_path, preliminary)
    profile, profile_identity = verify_profile(
        args.project_profile, candidate, bindings, checkouts
    )
    configured = sorted(
        {
            name
            for stage in profile["automation"]["stages"]
            for name in stage.get("credential_env", [])
        }
    )
    extra = set(args.credential_env) - set(configured)
    if extra:
        raise ContractError(
            f"credential names not declared by profile: {sorted(extra)}"
        )
    state = Path(args.state).resolve()
    state.mkdir(parents=True, exist_ok=True)
    previous_blockers = (
        {path.stem for path in (state / "blockers").glob("*.json")}
        if (state / "blockers").exists()
        else set()
    )
    selectors = {
        "tickets": selector_files[: len(args.ticket_selector)],
        "confluence": selector_files[len(args.ticket_selector) :],
    }
    pending = {x["stage_id"]: x for x in profile["automation"]["stages"]}
    completed = {}
    while pending:
        ready = sorted(
            key
            for key, value in pending.items()
            if set(value.get("depends_on", [])) <= set(completed)
        )
        if not ready:
            raise ContractError("automation stage graph has a cycle")
        for key in ready:
            stage = pending.pop(key)
            dependencies = {dep: completed[dep] for dep in stage.get("depends_on", [])}
            completed[key] = execute_stage(
                stage,
                profile,
                profile_identity,
                state,
                candidate,
                bindings,
                checkouts,
                selectors,
                dependencies,
            )
    unique = {}
    for value in completed.values():
        if value.get("blocker_id") and (
            value["blocker_id"] not in unique or value.get("human_request_emitted")
        ):
            unique[value["blocker_id"]] = value
    final = {
        "format_version": FORMAT,
        "project_id": profile["project"]["project_id"],
        "profile_sha256": profile_identity["sha256"],
        "candidate": candidate_state(candidate),
        "stages": {key: value["receipt_sha256"] for key, value in completed.items()},
        "statuses": {key: value["status"] for key, value in completed.items()},
        "human_blockers": [
            value
            for value in unique.values()
            if value["class"] != "GENUINE_UNRESOLVED_EVIDENCE"
        ],
        "evidence_blockers": [
            value
            for value in unique.values()
            if value["class"] == "GENUINE_UNRESOLVED_EVIDENCE"
        ],
        "campaign_write_attempts": 0,
    }
    final["workflow_sha256"] = object_hash(final)
    atomic_json(state / "workflow.json", final)
    return {
        **final,
        "new_human_requests": [
            value
            for value in final["human_blockers"]
            if value["blocker_id"] not in previous_blockers
        ],
    }


def replay(args: argparse.Namespace) -> dict:
    profile_path = regular(args.project_profile.resolve(), "project profile")
    profile = json.loads(profile_path.read_text())
    project = profile_path.parent
    candidate = Path(args.candidate).resolve()
    state = candidate_state(candidate)
    if state.get("sha256") != args.expected_candidate_sha256:
        raise ContractError("sealed replay candidate identity mismatch")
    frontier_path = regular(Path(args.frontier).resolve(), "frontier")
    frontier = json.loads(frontier_path.read_text())
    assignments = {}
    population_assignments = None
    for packet in frontier["packets"]:
        locator = regular(project / packet["locator"], "frontier packet")
        if file_hash(locator) != packet["sha256"]:
            raise ContractError(f"frontier packet changed: {packet['packet_id']}")
        owned = set()
        for item in packet.get("assignments", []):
            if item["record_id"] in assignments:
                raise ContractError("frontier assigns a record more than once")
            assignments[item["record_id"]] = packet["packet_id"]
            owned.add(item["record_id"])
        if packet["packet_id"] == args.population_packet_id:
            population_assignments = owned
    decision = json.loads(
        regular(Path(args.decision_packet).resolve(), "decision packet").read_text()
    )
    records = decision["records"]
    if population_assignments != {x["record_id"] for x in records}:
        raise ContractError(
            "intermediate decision population and frontier assignments differ"
        )
    checkouts = source_paths(args.source_path, profile)
    components = {x["component_id"]: x for x in profile["project"]["components"]}
    database = sqlite3.connect(f"file:{candidate}?mode=ro&immutable=1", uri=True)
    database.row_factory = sqlite3.Row
    if database.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ContractError("candidate integrity check failed")
    actual = {
        x["record_id"]: dict(x)
        for x in database.execute(
            "SELECT record_id,decision_status,technical_class,programme_scope,scanner_claim_status,processing_route FROM campaign_subject"
        )
    }
    reread = {}
    for item in records:
        source = item.get("source") or {}
        component = source.get("component_id")
        if item["record_id"] not in actual:
            raise ContractError(f"candidate lacks replay record: {item['record_id']}")
        expected = {
            key: item[key]
            for key in (
                "decision_status",
                "technical_class",
                "programme_scope",
                "scanner_claim_status",
            )
        }
        if {key: actual[item["record_id"]][key] for key in expected} != expected:
            raise ContractError(f"structured decision changed: {item['record_id']}")
        if component:
            if (
                components[component]["revision"] != source["revision"]
                or component not in checkouts
            ):
                raise ContractError(
                    f"source identity unavailable for replay: {item['record_id']}"
                )
            path = regular(
                Path(checkouts[component]) / source["path"], "decisive source"
            )
            if file_hash(path) != source["file_hash"]:
                raise ContractError(f"decisive source changed: {item['record_id']}")
            reread[str(path)] = source["file_hash"]
        raw = regular(project / item["raw_packet_locator"], "raw scanner packet")
        if file_hash(raw) != item["raw_packet_sha256"]:
            raise ContractError(f"raw packet changed: {item['record_id']}")
    classification_projection = sorted(
        (
            row["record_id"],
            row["decision_status"],
            row["technical_class"],
            row["programme_scope"],
            row["scanner_claim_status"],
            row["processing_route"],
        )
        for row in actual.values()
        if row["record_id"] in population_assignments
    )
    root_projection = [
        tuple(x)
        for x in database.execute(
            "SELECT record_id,root_id,relationship,confidence FROM campaign_record_root WHERE record_id IN ({}) ORDER BY record_id,root_id".format(
                ",".join("?" * len(population_assignments))
            ),
            sorted(population_assignments),
        )
    ]
    reproduction_projection = [
        tuple(x)
        for x in database.execute(
            "SELECT vr.root_id,v.reproduction_level,v.required_target,v.required_target_detail,v.reproduction_workflow_status,v.blocker FROM validation_run v JOIN validation_run_root vr USING(validation_run_id) ORDER BY vr.root_id"
        )
    ]
    valid_roots = {
        x[0]
        for x in database.execute(
            "SELECT DISTINCT cr.root_id FROM campaign_record_root cr JOIN campaign_subject s USING(record_id) WHERE s.technical_class='VALID_VULNERABILITY'"
        )
    }
    database.close()
    packages = json.loads(
        regular(Path(args.package_manifest).resolve(), "package manifest").read_text()
    )
    reports = packages.get("reports", [])
    package_dir = Path(args.package_manifest).resolve().parent
    if any(
        file_hash(
            regular(
                package_dir / item.get("locator", item.get("report", "")),
                "package report",
            )
        )
        != item.get("sha256", item.get("report_sha256"))
        for item in reports
    ):
        raise ContractError("package report identity mismatch")
    if (
        packages.get("candidate_sha256") != state["sha256"]
        or {x["root_id"] for x in reports} != valid_roots
    ):
        raise ContractError("package root/candidate closure mismatch")
    result = {
        "format_version": FORMAT,
        "mode": "SEALED_INTERMEDIATE_CHECKPOINT_REPLAY",
        "project_id": profile["project"]["project_id"],
        "candidate_sha256": state["sha256"],
        "frontier_sha256": file_hash(frontier_path),
        "decision_packet_sha256": file_hash(Path(args.decision_packet)),
        "workflow_script_sha256": file_hash(Path(__file__)),
        "analysis_validator_sha256": file_hash(
            Path(__file__).with_name("validate_analysis_packet.py")
        ),
        "classification_projection_sha256": object_hash(classification_projection),
        "root_relationship_projection_sha256": object_hash(root_projection),
        "reproduction_projection_sha256": object_hash(reproduction_projection),
        "package_identity": packages["package_identity"],
        "package_manifest_sha256": file_hash(Path(args.package_manifest)),
        "records": len(records),
        "roots_linked": len(root_projection),
        "valid_roots": len(valid_roots),
        "decisive_source_files_reread": len(reread),
        "campaign_write_attempts": 0,
        "technical_outcomes_unchanged": True,
        "root_relationships_unchanged": True,
        "reproduction_states_unchanged": True,
        "package_identities_unchanged": True,
    }
    result["replay_sha256"] = object_hash(result)
    atomic_json(Path(args.output).resolve(), result)
    return result


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    p = commands.add_parser("run")
    p.add_argument("--project-profile", type=Path, required=True)
    p.add_argument("--candidate", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--source", action="append", default=[])
    p.add_argument("--source-path", action="append", default=[])
    p.add_argument("--ticket-selector", action="append", default=[])
    p.add_argument("--confluence-selector", action="append", default=[])
    p.add_argument("--credential-env", action="append", default=[])
    p = commands.add_parser("replay")
    p.add_argument("--project-profile", type=Path, required=True)
    p.add_argument("--candidate", required=True)
    p.add_argument("--expected-candidate-sha256", required=True)
    p.add_argument("--frontier", required=True)
    p.add_argument("--population-packet-id", required=True)
    p.add_argument("--decision-packet", required=True)
    p.add_argument("--package-manifest", required=True)
    p.add_argument("--source-path", action="append", default=[])
    p.add_argument("--output", required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        result = run(args) if args.command == "run" else replay(args)
    except (
        ContractError,
        OSError,
        json.JSONDecodeError,
        sqlite3.Error,
        KeyError,
        ValueError,
        BlockingIOError,
    ) as exc:
        print(json.dumps({"result": "FAIL", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"result": "PASS", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
