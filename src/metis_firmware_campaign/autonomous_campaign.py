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
from datetime import datetime
import fcntl
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

from metis_firmware_campaign.analysis_packet import validate as validate_analysis_packet
from metis_firmware_campaign import technical_state_correction
from metis_firmware_campaign import technical_adjudication

FORMAT = "firmware-autonomous-campaign-v1"
V6_OUTPUTS = {
    "collect-source": {
        "source-manifest.json",
        "active-source-membership.json",
        "indirect-call-inventory.json",
    },
    "collect-historical-tickets": {
        "historical-ticket-manifest.json",
        "ticket-source-relations.json",
        "connector-receipts.json",
    },
    "collect-current-tickets": {
        "current-ticket-manifest.json",
        "ticket-source-relations.json",
        "connector-receipts.json",
    },
    "collect-threat-policy": {"threat-policy-manifest.json", "connector-receipts.json"},
    "build-candidate": {
        "candidate-build.json",
        "contract-discovery.json",
        "exact-build-bindings.json",
        "knowledge-fts.json",
    },
    "metis-full": {
        "incremental-finalization.json",
        "rendered-prompt-receipts.json",
        "coverage-schedules.json",
        "context-cache-receipts.json",
    },
    "validate-packets": {
        "stage.json",
        "terminal-decision-capsules.json",
        "review-bindings.json",
    },
    "integrate": {
        "integration.packet.json",
        "root-fingerprints.json",
        "fts-index-receipt.json",
    },
    "reproduce": {
        "reproduction-frontier.json",
        "backend-capabilities.json",
        "rerun-manifests.json",
        "reproducer-reuse.json",
        "candidate-patch-state.json",
    },
}


def copy_output_contract(outputs: dict[str, set[str]]) -> dict[str, set[str]]:
    """Return independent sets so one schema version cannot mutate another."""
    return {stage_id: set(names) for stage_id, names in outputs.items()}


V62_OUTPUTS = copy_output_contract(V6_OUTPUTS)
V62_OUTPUTS["validate-packets"] = V6_OUTPUTS["validate-packets"] | {
    "fp-no-bug-audits.json",
    "classification-reopen-proposals.json",
    "terminal-change-anomaly-gate.json",
}
V63_OUTPUTS = copy_output_contract(V62_OUTPUTS)
V63_OUTPUTS["collect-source"] |= {
    "documentation-manifest.json",
    "component-registry.json",
}
V63_OUTPUTS["collect-threat-policy"] |= {
    "security-properties.json",
    "programme-rules.json",
    "advisory-fix-regression.json",
    "programme-threat-comparison.json",
}
V63_OUTPUTS["build-candidate"] |= {"independent-rebuild.json"}
V63_OUTPUTS["integrate"] |= {
    "root-property-mappings.json",
    "variant-searches.json",
    "scope-invalidation.json",
}
V63_OUTPUTS["reproduce"] |= {"control-triplets.json"}
V63_OUTPUTS["package-seal"] = {
    "candidate-a.db",
    "candidate-b.db",
    "candidate-a.dump",
    "candidate-b.dump",
    "report-a.md",
    "report-b.md",
    "delivery-a.json",
    "delivery-b.json",
    "packages-a/manifest.json",
    "packages-b/manifest.json",
    "validation-gates.json",
    "current-frontier.json",
    "final-receipts.json",
}
V64_OUTPUTS = copy_output_contract(V63_OUTPUTS)
V64_OUTPUTS["package-export"] = {"INDEX.json", "INDEX.md", "VALIDATION-RECEIPT.json"}
V65_OUTPUTS = copy_output_contract(V64_OUTPUTS)
V65_OUTPUTS["severity-calibration"] = {
    "SEVERITY-INDEX.json",
    "SEVERITY-VALIDATION.json",
}
V66_OUTPUTS = copy_output_contract(V65_OUTPUTS)
V66_OUTPUTS["collect-threat-policy"] |= {"policy-reconciliation-input.json"}
V66_OUTPUTS["policy-reconciliation"] = {
    "POLICY-INDEX.json",
    "POC-EVIDENCE-INDEX.json",
    "NOVELTY-INDEX.json",
    "POLICY-VALIDATION.json",
}
V661_OUTPUTS = copy_output_contract(V66_OUTPUTS)
V661_OUTPUTS["population-report"] = {
    "POPULATION-SCOPED-REPORT.json",
    "POPULATION-SCOPED-REPORT.md",
}
V67_OUTPUTS = copy_output_contract(V661_OUTPUTS)
V67_OUTPUTS["existing-report-followup"] = {
    "EXISTING-REPORT-FOLLOWUP-INDEX.json",
    "EXISTING-REPORT-FOLLOWUP-INDEX.md",
    "FOLLOWUP-VALIDATION.json",
}
V68_OUTPUTS = copy_output_contract(V67_OUTPUTS)
V68_OUTPUTS["policy-reconciliation"] |= {
    "POLICY-TRANSITION-LEDGER.json",
    "TECHNICAL-REOPEN-QUEUE.json",
    "independent-verifier.json",
}
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
CURRENT_EVIDENCE_PHASES = {"CURRENT_TICKET_COLLECTION", "THREAT_POLICY_COLLECTION"}
METIS_PROVIDER_PHASES = {
    "METIS_HEALTH",
    "METIS_CALIBRATION_1",
    "METIS_CALIBRATION_20",
    "METIS_CALIBRATION_100",
    "METIS_FULL_SCAN",
}
PROVIDER_EXECUTION_MODE_FORMAT = "metis-provider-execution-mode-v1"
PROVIDER_EXECUTION_MODES = {"LIVE", "FROZEN_REPLAY"}
POLICY_ONLY_PHASES = {
    "CURRENT_TICKET_COLLECTION",
    "THREAT_POLICY_COLLECTION",
    "POLICY_RECONCILIATION",
    "EXISTING_REPORT_FOLLOWUP",
    "PACKAGE_EXPORT",
    "POPULATION_SCOPED_REPORTING",
    "PACKAGE_AND_SEAL",
}
POLICY_REFRESH_FORMAT = "firmware-policy-refresh-bundle-v1"
RUNTIME_IDENTITY_FORMAT = "metis-firmware-runtime-identity-v1"
RUNTIME_IDENTITY_FILE = "runtime-identity-v1.json"
TECHNICAL_LINEAGE_VERSION = "sqlite-typed-v2"
PENDING_COMMIT_FORMAT = "firmware-candidate-pending-commit-v1"
VERSIONED_OUTPUT_CONTRACT_SHA256 = (
    "cd3aef05d749945d4704a8dcb94cf8a6fcbb2fb07705526d662306161c398cc2"
)
RUNTIME_SOURCE_ROOTS = ("src/metis", "src/metis_firmware_campaign")
RUNTIME_FILES = ("pyproject.toml", "uv.lock")
RUNTIME_IGNORED_PARTS = frozenset({"__pycache__", ".DS_Store"})
RUNTIME_ENV_ALLOWLIST = {
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TMP",
    "TEMP",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NO_PROXY",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "UV_CACHE_DIR",
    "UV_PYTHON",
}


def versioned_outputs(schema_version: str) -> dict[str, set[str]]:
    return {
        "6": V6_OUTPUTS,
        "6.2": V62_OUTPUTS,
        "6.3": V63_OUTPUTS,
        "6.4": V64_OUTPUTS,
        "6.5": V65_OUTPUTS,
        "6.6": V66_OUTPUTS,
        "6.6.1": V661_OUTPUTS,
        "6.7": V67_OUTPUTS,
        "6.8": V68_OUTPUTS,
    }[schema_version]


def versioned_output_contract_sha256() -> str:
    normalized = {
        version: {
            stage_id: sorted(names)
            for stage_id, names in sorted(versioned_outputs(version).items())
        }
        for version in ("6", "6.2", "6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7", "6.8")
    }
    return object_hash(normalized)


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
    return {
        "locator": str(path),
        "sha256": file_hash(path),
        "size": path.stat().st_size,
    }


def _runtime_members(root: Path, source_roots: tuple[str, ...]) -> list[dict]:
    members = []
    for value in source_roots:
        source_root = absolute(root, value)
        try:
            source_root.relative_to(root)
        except ValueError as error:
            raise ContractError(
                "runtime source root escapes runtime checkout"
            ) from error
        if source_root.is_symlink() or not source_root.is_dir():
            raise ContractError(f"runtime source root is unavailable: {value}")
        for path in sorted(source_root.rglob("*")):
            relative = path.relative_to(root)
            if any(part in RUNTIME_IGNORED_PARTS for part in relative.parts):
                continue
            if path.suffix in {".pyc", ".pyo"}:
                continue
            if path.is_symlink():
                raise ContractError(f"runtime source member is a symlink: {relative}")
            if path.is_dir():
                continue
            if not path.is_file():
                raise ContractError(f"runtime source member is not regular: {relative}")
            members.append(
                {
                    "path": relative.as_posix(),
                    "sha256": file_hash(path),
                    "size": path.stat().st_size,
                }
            )
    if not members:
        raise ContractError("runtime identity contains no source members")
    return members


def _direct_dependency_versions(pyproject: Path) -> dict[str, str]:
    project = tomllib.loads(pyproject.read_text()).get("project", {})
    names = []
    for requirement in project.get("dependencies", []):
        match = re.match(r"[A-Za-z0-9_.-]+", requirement)
        if match:
            names.append(match.group(0))
    versions = {}
    for name in sorted(set(names), key=lambda value: value.lower()):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as error:
            raise ContractError(
                f"runtime dependency is not installed: {name}"
            ) from error
    return versions


def _locked_installed_dependency_versions(uv_lock: Path) -> list[dict[str, str]]:
    locked = {
        re.sub(r"[-_.]+", "-", item["name"]).lower()
        for item in tomllib.loads(uv_lock.read_text()).get("package", [])
    }
    installed = {}
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get("Name")
        if not name:
            continue
        canonical_name = re.sub(r"[-_.]+", "-", name).lower()
        if canonical_name in locked:
            installed[canonical_name] = distribution.version
    return [{"name": name, "version": installed[name]} for name in sorted(installed)]


def runtime_identity(
    root: Path, source_roots: tuple[str, ...], runtime_files: tuple[str, ...]
) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise ContractError(f"runtime root is unavailable: {root}")
    root = root.resolve()
    members = _runtime_members(root, source_roots)
    files = [
        material_file(root, value, f"runtime file {value}") for value in runtime_files
    ]
    pyproject = regular(root / "pyproject.toml", "runtime pyproject")
    uv_lock = regular(root / "uv.lock", "runtime lockfile")
    executable = regular(Path(sys.executable).resolve(), "runtime Python executable")
    locked_dependencies = _locked_installed_dependency_versions(uv_lock)
    body = {
        "format_version": RUNTIME_IDENTITY_FORMAT,
        "runtime_root": ".",
        "source_roots": list(source_roots),
        "runtime_files": list(runtime_files),
        "source_file_count": len(members),
        "source_tree_sha256": object_hash(members),
        "runtime_files_sha256": object_hash(
            [
                {
                    "path": Path(item["locator"]).relative_to(root).as_posix(),
                    "sha256": item["sha256"],
                    "size": item["size"],
                }
                for item in files
            ]
        ),
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "executable_sha256": file_hash(executable),
        },
        "direct_dependency_versions": _direct_dependency_versions(pyproject),
        "locked_installed_dependency_count": len(locked_dependencies),
        "locked_installed_dependencies_sha256": object_hash(locked_dependencies),
    }
    body["runtime_identity_sha256"] = object_hash(body)
    return body


def verify_runtime_identity_manifest(path: Path) -> dict:
    manifest = json.loads(regular(path, "runtime identity manifest").read_text())
    allowed = {
        "format_version",
        "runtime_root",
        "source_roots",
        "runtime_files",
        "source_file_count",
        "source_tree_sha256",
        "runtime_files_sha256",
        "python",
        "direct_dependency_versions",
        "locked_installed_dependency_count",
        "locked_installed_dependencies_sha256",
        "runtime_identity_sha256",
    }
    if not isinstance(manifest, dict) or set(manifest) != allowed:
        raise ContractError("runtime identity manifest has an invalid shape")
    if manifest.get("format_version") != RUNTIME_IDENTITY_FORMAT:
        raise ContractError("runtime identity manifest has an unsupported format")
    source_roots = tuple(manifest.get("source_roots") or ())
    runtime_files = tuple(manifest.get("runtime_files") or ())
    if source_roots != RUNTIME_SOURCE_ROOTS or runtime_files != RUNTIME_FILES:
        raise ContractError(
            "runtime identity manifest omits required implementation inputs"
        )
    root = absolute(path.parent, manifest["runtime_root"])
    expected = runtime_identity(root, source_roots, runtime_files)
    if expected != manifest:
        raise ContractError("runtime identity manifest is stale")
    return expected


def runtime_dependency(base: Path, value: str, label: str) -> dict:
    path = regular(absolute(base, value), label)
    if path.name != RUNTIME_IDENTITY_FILE:
        return {
            "locator": str(path),
            "sha256": file_hash(path),
            "size": path.stat().st_size,
        }
    verified = verify_runtime_identity_manifest(path)
    return {
        "locator": str(path),
        "sha256": file_hash(path),
        "size": path.stat().st_size,
        "runtime_identity_sha256": verified["runtime_identity_sha256"],
        "python_executable_sha256": verified["python"]["executable_sha256"],
    }


def provider_execution_mode(profile: dict, profile_identity: dict) -> str | None:
    stages = profile.get("automation", {}).get("stages", [])
    if not any(stage.get("phase") in METIS_PROVIDER_PHASES for stage in stages):
        return None
    configured = profile.get("automation", {}).get("provider_execution_mode")
    sidecar = Path(f"{profile_identity['locator']}.provider-execution.json")
    sidecar_mode = None
    if sidecar.exists():
        record = json.loads(regular(sidecar, "provider execution sidecar").read_text())
        allowed = {
            "format_version",
            "profile_sha256",
            "provider_execution_mode",
            "content_sha256",
        }
        claimed = record.pop("content_sha256", None)
        if set(record) != allowed - {"content_sha256"} or claimed != object_hash(
            record
        ):
            raise ContractError("provider execution sidecar identity mismatch")
        if record.get("format_version") != PROVIDER_EXECUTION_MODE_FORMAT:
            raise ContractError("unsupported provider execution sidecar")
        if record.get("profile_sha256") != profile_identity["sha256"]:
            raise ContractError("provider execution sidecar is stale")
        sidecar_mode = record.get("provider_execution_mode")
    if configured and sidecar_mode and configured != sidecar_mode:
        raise ContractError("provider execution modes conflict")
    mode = configured or sidecar_mode
    if mode not in PROVIDER_EXECUTION_MODES:
        raise ContractError(
            "provider execution requires explicit LIVE or FROZEN_REPLAY mode"
        )
    if mode == "FROZEN_REPLAY" and any(
        stage.get("credential_env") or stage.get("runtime_dependency_files")
        for stage in stages
        if stage.get("phase") in METIS_PROVIDER_PHASES
    ):
        raise ContractError("frozen replay declares live provider inputs")
    return mode


def default_runtime_manifest() -> Path:
    return Path(__file__).resolve().parents[2] / RUNTIME_IDENTITY_FILE


def command_executable(base: Path, command: list[str], env: dict[str, str]) -> Path:
    if not command:
        raise ContractError("provider-backed stage has no adapter executable")
    value = command[0]
    value_path = Path(value)
    if value_path.is_absolute():
        found = value_path
    elif os.path.dirname(value):
        found = base / value_path
    else:
        search = []
        for entry in env.get("PATH", os.defpath).split(os.pathsep):
            directory = Path(entry or ".")
            search.append(
                str(directory if directory.is_absolute() else base / directory)
            )
        found = shutil.which(value, path=os.pathsep.join(search))
    if not found:
        raise ContractError(
            f"provider-backed adapter executable is unavailable: {value}"
        )
    declared = Path(found).absolute()
    regular(declared.resolve(), "provider-backed adapter executable")
    return declared


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
        listing = subprocess.check_output(command, env=runtime_environment([])).split(
            b"\0"
        )
        entries = []
        for raw in listing:
            if not raw:
                continue
            metadata, encoded_name = raw.split(b"\t", 1)
            mode = metadata.split(b" ", 1)[0].decode()
            entries.append((encoded_name.decode(), mode))
        entries.sort()
        revision = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
            env=runtime_environment([]),
        ).strip()
        if subprocess.run(
            ["git", "-C", str(path), "diff", "--quiet", revision, "--"],
            capture_output=True,
            check=False,
            env=runtime_environment([]),
        ).returncode:
            raise ContractError(f"source checkout has tracked modifications: {path}")
        tracked = {name for name, _mode in entries}
        if any(
            item.is_symlink()
            and ".git" not in item.relative_to(path).parts
            and str(item.relative_to(path)) not in tracked
            for item in path.rglob("*")
        ):
            raise ContractError(
                f"source checkout contains an untracked symlink: {path}"
            )
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
            raise ContractError(
                f"tracked symlink is dangling or recursive: {name}"
            ) from error
        try:
            resolved.relative_to(source_root)
        except ValueError as error:
            raise ContractError(
                f"tracked symlink escapes source checkout: {name}"
            ) from error
        manifest.append(
            {"path": name, "sha256": hashlib.sha256(target.encode()).hexdigest()}
        )
        symlinks.append(
            {
                "path": name,
                "target": target,
                "target_sha256": file_hash(regular(resolved, "tracked symlink target")),
            }
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


def technical_candidate_lineage(candidate: Path) -> str:
    """Hash technical decisions while excluding policy-only mutable dimensions."""
    if not candidate.is_file():
        return object_hash({"candidate": "ABSENT"})
    # Policy-only reconciliation is permitted to change only this explicit set.
    # Hashing every other user table prevents a newly introduced technical table
    # from silently escaping the lineage boundary.
    policy_tables = {
        "policy_decision_transition",
        "policy_reconciliation",
        "policy_refresh_population",
        "policy_rule_evaluation",
        "policy_rule_evidence_condition",
        "policy_rule_decision_binding",
        "policy_technical_reopen_queue",
        "programme_scope_separation",
        "ticket_reproduction_assessment",
    }
    projection = {}
    try:
        database = sqlite3.connect(
            f"file:{candidate.resolve()}?mode=ro&immutable=1", uri=True
        )
        database.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
    except sqlite3.DatabaseError:
        return object_hash({"opaque_candidate_sha256": file_hash(candidate)})
    with database:
        present = sorted(
            row[0]
            for row in database.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            if not row[0].startswith("sqlite_") and row[0] not in policy_tables
        )
        for table in present:
            columns = [
                row[1] for row in database.execute(f'PRAGMA table_info("{table}")')
            ]
            if table == "campaign_subject":
                columns = [name for name in columns if name != "programme_scope"]
            selection = ",".join(f'"{name}"' for name in columns)
            order = ",".join(str(index + 1) for index in range(len(columns)))
            raw_rows = database.execute(
                f'SELECT {selection} FROM "{table}" ORDER BY {order}'
            ).fetchall()
            projection[table] = {
                "columns": columns,
                "rows": [
                    [sqlite_lineage_value(value) for value in row] for row in raw_rows
                ],
            }
    return object_hash(
        {"format_version": TECHNICAL_LINEAGE_VERSION, "tables": projection}
    )


def sqlite_lineage_value(value: object) -> dict:
    """Canonical, lossless representation for every SQLite storage class."""
    if value is None:
        return {"type": "NULL"}
    if isinstance(value, bytes):
        return {"type": "BLOB", "hex": value.hex()}
    if isinstance(value, str):
        return {"type": "TEXT", "value": value}
    if isinstance(value, int):
        return {"type": "INTEGER", "value": value}
    if isinstance(value, float):
        return {"type": "REAL", "hex": value.hex()}
    raise ContractError(f"unsupported SQLite lineage value: {type(value).__name__}")


def verify_profile(
    path: Path, candidate: Path, sources: dict, source_checkouts: dict
) -> tuple[dict, dict]:
    path = regular(path.resolve(), "project profile")
    profile = json.loads(path.read_text())
    if profile.get("schema_version") not in (
        "4",
        "5",
        "6",
        "6.2",
        "6.3",
        "6.4",
        "6.5",
        "6.6",
        "6.6.1",
        "6.7",
        "6.8",
    ):
        raise ContractError(
            "project profile schema_version must be 4, 5, 6, 6.2, 6.3, 6.4, 6.5, 6.6, 6.6.1, 6.7, or 6.8"
        )
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
    if profile.get("schema_version") == "6.8":
        required_controls = {
            "append_only_policy_transitions",
            "authority_freshness_checked_at_reconciliation_and_verification",
            "completion_predicates_separate",
            "current_authority_requires_verified_refresh_lease",
            "current_policy_and_ticket_populations_separately_bound",
            "existing_report_and_scope_axes_separate",
            "historical_authority_requires_exact_root_attacker_effect_match",
            "novelty_requires_complete_current_ticket_population",
            "policy_only_execution_forbids_provider_phases_and_credentials",
            "selective_technical_reopen_queue",
            "supersession_requires_target_and_sufficient_authority",
        }
        controls = governance.get("policy_decision_controls_v6_8", {})
        if set(controls) != required_controls or not all(controls.values()):
            raise ContractError("schema-v6.8 policy decision controls are incomplete")
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
    expected_phases = (
        PHASES_V67
        if profile.get("schema_version") in {"6.7", "6.8"}
        else (
            PHASES_V661
            if profile.get("schema_version") == "6.6.1"
            else (
                PHASES_V66
                if profile.get("schema_version") == "6.6"
                else (
                    PHASES_V65
                    if profile.get("schema_version") == "6.5"
                    else (
                        PHASES_V64 if profile.get("schema_version") == "6.4" else PHASES
                    )
                )
            )
        )
    )
    if set(phases) != expected_phases or len(ids) != len(set(ids)) or None in ids:
        raise ContractError(
            "automation must define each generic phase exactly once with unique stage IDs"
        )
    for item in stages:
        builtin_export = (
            item.get("phase") == "PACKAGE_EXPORT"
            and item.get("builtin") == "INTERNAL_TECHNICAL_PACKAGE_EXPORT"
            and not item.get("adapter")
        )
        builtin_severity = (
            item.get("phase") == "SEVERITY_CALIBRATION"
            and item.get("builtin") == "TECHNICAL_SEVERITY_CALIBRATION"
            and not item.get("adapter")
        )
        builtin_policy = (
            item.get("phase") == "POLICY_RECONCILIATION"
            and item.get("builtin") == "POLICY_PRECEDENCE_RECONCILIATION"
            and not item.get("adapter")
        )
        builtin_reporting = (
            item.get("phase") == "POPULATION_SCOPED_REPORTING"
            and item.get("builtin") == "POPULATION_SCOPED_SUMMARY"
            and not item.get("adapter")
        )
        builtin_followup = (
            item.get("phase") == "EXISTING_REPORT_FOLLOWUP"
            and item.get("builtin") == "EXISTING_REPORT_FOLLOWUP_ASSESSMENT"
            and not item.get("adapter")
        )
        if item.get("phase") not in expected_phases or (
            not builtin_export
            and not builtin_severity
            and not builtin_policy
            and not builtin_reporting
            and not builtin_followup
            and (not isinstance(item.get("adapter"), list) or not item["adapter"])
        ):
            raise ContractError(f"invalid adapter for stage {item.get('stage_id')}")
        if item.get("phase") == "PACKAGE_EXPORT" and not builtin_export:
            raise ContractError("PACKAGE_EXPORT must use the generic built-in exporter")
        if item.get("phase") == "SEVERITY_CALIBRATION" and not builtin_severity:
            raise ContractError(
                "SEVERITY_CALIBRATION must use the generic built-in calibrator"
            )
        if item.get("phase") == "POLICY_RECONCILIATION" and not builtin_policy:
            raise ContractError(
                "POLICY_RECONCILIATION must use the generic built-in reconciler"
            )
        if item.get("phase") == "POPULATION_SCOPED_REPORTING" and not builtin_reporting:
            raise ContractError(
                "POPULATION_SCOPED_REPORTING must use the generic built-in reporter"
            )
        if item.get("phase") == "EXISTING_REPORT_FOLLOWUP" and not builtin_followup:
            raise ContractError(
                "EXISTING_REPORT_FOLLOWUP must use the generic built-in assessor"
            )
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
        if item["phase"] in CURRENT_EVIDENCE_PHASES:
            maximum_age = item.get("max_evidence_age_seconds", 86400)
            if (
                item.get("refresh_on_resume") not in {None, True, False}
                or not isinstance(maximum_age, int)
                or not 0 <= maximum_age <= 604800
            ):
                raise ContractError("current evidence refresh contract is invalid")
        if not item.get("required_outputs") or not isinstance(
            item["required_outputs"], list
        ):
            raise ContractError(
                f"stage requires explicit output closure: {item['stage_id']}"
            )
    contract_release = None
    if profile.get("schema_version") in (
        "6",
        "6.2",
        "6.3",
        "6.4",
        "6.5",
        "6.6",
        "6.6.1",
        "6.7",
        "6.8",
    ):
        contract_release = profile.get("contract_release")
        expected_release = (
            {
                "version": "6.8.0",
                "manifest": "AUTO_DISCOVER",
                "core_database_contract": "AUTO_DISCOVER",
                "capability_schema": "AUTO_DISCOVER",
                "accuracy_contract": "AUTO_DISCOVER",
                "accuracy_schema_extension": "AUTO_DISCOVER",
                "knowledge_contract": "AUTO_DISCOVER",
                "knowledge_schema_extension": "AUTO_DISCOVER",
                "severity_contract": "AUTO_DISCOVER",
                "policy_contract": "AUTO_DISCOVER",
                "policy_schema_extension": "AUTO_DISCOVER",
                "reporting_contract": "AUTO_DISCOVER",
                "followup_contract": "AUTO_DISCOVER",
                "policy_decision_controls_contract": "AUTO_DISCOVER",
                "policy_decision_controls_schema_extension": "AUTO_DISCOVER",
                "automatic": True,
            }
            if profile.get("schema_version") == "6.8"
            else {
                "version": "6.7.0",
                "manifest": "AUTO_DISCOVER",
                "core_database_contract": "AUTO_DISCOVER",
                "capability_schema": "AUTO_DISCOVER",
                "accuracy_contract": "AUTO_DISCOVER",
                "accuracy_schema_extension": "AUTO_DISCOVER",
                "knowledge_contract": "AUTO_DISCOVER",
                "knowledge_schema_extension": "AUTO_DISCOVER",
                "severity_contract": "AUTO_DISCOVER",
                "policy_contract": "AUTO_DISCOVER",
                "policy_schema_extension": "AUTO_DISCOVER",
                "reporting_contract": "AUTO_DISCOVER",
                "followup_contract": "AUTO_DISCOVER",
                "automatic": True,
            }
            if profile.get("schema_version") == "6.7"
            else {
                "version": "6.6.1",
                "manifest": "AUTO_DISCOVER",
                "core_database_contract": "AUTO_DISCOVER",
                "capability_schema": "AUTO_DISCOVER",
                "accuracy_contract": "AUTO_DISCOVER",
                "accuracy_schema_extension": "AUTO_DISCOVER",
                "knowledge_contract": "AUTO_DISCOVER",
                "knowledge_schema_extension": "AUTO_DISCOVER",
                "severity_contract": "AUTO_DISCOVER",
                "policy_contract": "AUTO_DISCOVER",
                "policy_schema_extension": "AUTO_DISCOVER",
                "reporting_contract": "AUTO_DISCOVER",
                "automatic": True,
            }
            if profile.get("schema_version") == "6.6.1"
            else {
                "version": "6.6.0",
                "manifest": "AUTO_DISCOVER",
                "core_database_contract": "AUTO_DISCOVER",
                "capability_schema": "AUTO_DISCOVER",
                "accuracy_contract": "AUTO_DISCOVER",
                "accuracy_schema_extension": "AUTO_DISCOVER",
                "knowledge_contract": "AUTO_DISCOVER",
                "knowledge_schema_extension": "AUTO_DISCOVER",
                "severity_contract": "AUTO_DISCOVER",
                "policy_contract": "AUTO_DISCOVER",
                "policy_schema_extension": "AUTO_DISCOVER",
                "automatic": True,
            }
            if profile.get("schema_version") == "6.6"
            else {
                "version": "6.5.0",
                "manifest": "AUTO_DISCOVER",
                "core_database_contract": "AUTO_DISCOVER",
                "capability_schema": "AUTO_DISCOVER",
                "accuracy_contract": "AUTO_DISCOVER",
                "accuracy_schema_extension": "AUTO_DISCOVER",
                "knowledge_contract": "AUTO_DISCOVER",
                "knowledge_schema_extension": "AUTO_DISCOVER",
                "severity_contract": "AUTO_DISCOVER",
                "automatic": True,
            }
            if profile.get("schema_version") == "6.5"
            else {
                "version": "6.4.0",
                "manifest": "AUTO_DISCOVER",
                "core_database_contract": "AUTO_DISCOVER",
                "capability_schema": "AUTO_DISCOVER",
                "accuracy_contract": "AUTO_DISCOVER",
                "accuracy_schema_extension": "AUTO_DISCOVER",
                "knowledge_contract": "AUTO_DISCOVER",
                "knowledge_schema_extension": "AUTO_DISCOVER",
                "automatic": True,
            }
            if profile.get("schema_version") == "6.4"
            else {
                "version": "6.3.0",
                "manifest": "AUTO_DISCOVER",
                "core_database_contract": "AUTO_DISCOVER",
                "capability_schema": "AUTO_DISCOVER",
                "accuracy_contract": "AUTO_DISCOVER",
                "accuracy_schema_extension": "AUTO_DISCOVER",
                "knowledge_contract": "AUTO_DISCOVER",
                "knowledge_schema_extension": "AUTO_DISCOVER",
                "automatic": True,
            }
            if profile.get("schema_version") == "6.3"
            else {
                "version": "6.2.0",
                "manifest": "AUTO_DISCOVER",
                "core_database_contract": "AUTO_DISCOVER",
                "capability_schema": "AUTO_DISCOVER",
                "accuracy_contract": "AUTO_DISCOVER",
                "accuracy_schema_extension": "AUTO_DISCOVER",
                "automatic": True,
            }
            if profile.get("schema_version") == "6.2"
            else {
                "version": "6.0.0",
                "manifest": "AUTO_DISCOVER",
                "core_database_contract": "AUTO_DISCOVER",
                "capability_schema": "AUTO_DISCOVER",
                "automatic": True,
            }
        )
        if contract_release != expected_release:
            raise ContractError(
                "schema-v6 profile does not request automatic release discovery"
            )
        discovery = (
            Path(__file__).resolve().parents[2].parent
            / "portable-firmware-campaign/.agents/skills/firmware-campaign-bootstrap/scripts/discover_contract.py"
        )
        found = json.loads(
            subprocess.check_output(
                [sys.executable, str(discovery)], text=True, env=runtime_environment([])
            )
        )
        allowed_versions = (
            {"6.8.0"}
            if profile.get("schema_version") == "6.8"
            else (
                {"6.7.0", "6.8.0"}
                if profile.get("schema_version") == "6.7"
                else (
                    {"6.6.1", "6.7.0", "6.8.0"}
                    if profile.get("schema_version") == "6.6.1"
                    else (
                        {"6.6.0", "6.6.1", "6.7.0", "6.8.0"}
                        if profile.get("schema_version") == "6.6"
                        else (
                            {"6.5.0", "6.6.0", "6.6.1", "6.7.0", "6.8.0"}
                            if profile.get("schema_version") == "6.5"
                            else (
                                {"6.4.0", "6.5.0", "6.6.0", "6.6.1", "6.7.0", "6.8.0"}
                                if profile.get("schema_version") == "6.4"
                                else (
                                    {
                                        "6.3.0",
                                        "6.4.0",
                                        "6.5.0",
                                        "6.6.0",
                                        "6.6.1",
                                        "6.7.0",
                                        "6.8.0",
                                    }
                                    if profile.get("schema_version") == "6.3"
                                    else (
                                        {
                                            "6.2.0",
                                            "6.3.0",
                                            "6.4.0",
                                            "6.5.0",
                                            "6.6.0",
                                            "6.6.1",
                                            "6.7.0",
                                            "6.8.0",
                                        }
                                        if profile.get("schema_version") == "6.2"
                                        else {
                                            "6.0.0",
                                            "6.2.0",
                                            "6.3.0",
                                            "6.4.0",
                                            "6.5.0",
                                            "6.6.0",
                                            "6.6.1",
                                            "6.7.0",
                                            "6.8.0",
                                        }
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
        allowed_versions.add("6.9.0")
        allowed_versions.add("6.10.0")
        allowed_versions.add("6.11.0")
        if found.get("contract_version") not in allowed_versions:
            raise ContractError("installed capability release does not satisfy profile")
        contract_release = {
            **contract_release,
            "installed_release_hashes": [x["release_hash"] for x in found["skills"]],
        }
        connectors = automation.get("connectors", [])
        if {item.get("kind") for item in connectors} != {
            "TICKET",
            "JIRA",
            "INTIGRITI",
            "CONFLUENCE",
        } or any(item.get("read_only") is not True for item in connectors):
            raise ContractError("schema-v6 connector contract incomplete")
        outputs = versioned_outputs(profile["schema_version"])
        for stage_id, expected in outputs.items():
            actual = next(
                (
                    set(item["required_outputs"])
                    for item in stages
                    if item["stage_id"] == stage_id
                ),
                None,
            )
            if actual != expected:
                raise ContractError(f"schema-v6 output closure mismatch: {stage_id}")
    if profile.get("schema_version") in (
        "5",
        "6",
        "6.2",
        "6.3",
        "6.4",
        "6.5",
        "6.6",
        "6.6.1",
        "6.7",
        "6.8",
    ):
        components = {x["component_id"]: x for x in profile["project"]["components"]}
        required_checkouts = (
            {
                x["component_id"]
                for x in profile["project"]["components"]
                if x.get("source_checkout_required", True)
            }
            if profile.get("schema_version")
            in ("6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7", "6.8")
            else set(components)
        )
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
    provider_execution_mode(profile, identity)
    return profile, identity


def redact(value: str, credential_names: list[str]) -> str:
    for name in credential_names:
        secret = os.environ.get(name)
        if secret:
            value = value.replace(secret, "<redacted>")
    return value


def runtime_environment(credential_names: list[str]) -> dict[str, str]:
    """Return a minimal environment plus only this stage's declared secrets."""
    env = {
        name: os.environ[name] for name in RUNTIME_ENV_ALLOWLIST if name in os.environ
    }
    for name in credential_names:
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


def command_identity(base: Path, command: list[str]) -> dict:
    files = []
    for value in command:
        if "{" in value:
            continue
        path = absolute(base, value)
        if path.is_file() and not path.is_symlink():
            files.append({"locator": str(path), "sha256": file_hash(path)})
    return {"argv": command, "files": files}


def receipt(path: Path) -> dict | None:
    if not path.exists():
        return None
    data = json.loads(regular(path, "stage receipt").read_text())
    claimed = data.pop("receipt_sha256", None)
    if claimed != object_hash(data):
        raise ContractError(f"stage receipt identity mismatch: {path}")
    data["receipt_sha256"] = claimed
    return data


LEGACY_STAGE_INPUT_FIELDS = {
    "format_version",
    "project_id",
    "profile_sha256",
    "stage_id",
    "phase",
    "adapter_sha256",
    "source_bindings",
    "source_checkouts",
    "selectors",
    "input_files",
    "dependencies",
    "profile_schema_version",
    "contract_release",
    "worker_adapter_sha256",
    "runtime_dependency_files",
    "runtime_adapter_executable",
    "runtime_adapter_executable_sha256",
    "human_dependency_evidence",
    "candidate_before",
}


def committed_stage_input_projection(directory: Path, expected: str) -> object | None:
    """Return only stage input bytes authenticated by an original receipt."""
    context_path = directory / "context.json"
    if not context_path.exists():
        return None
    context = json.loads(regular(context_path, "historical stage context").read_text())
    projections = [
        {key: value for key, value in context.items() if key != "output_directory"},
        {key: context[key] for key in LEGACY_STAGE_INPUT_FIELDS if key in context},
    ]
    committed = [value for value in projections if object_hash(value) == expected]
    if not committed:
        raise ContractError(
            "historical stage context does not reproduce input commitment"
        )
    return committed[0]


def completed_receipt(state: Path, stage_id: str, receipt_sha256: str) -> dict:
    active, historical = [], []
    locations = (
        (active, (state / "stages" / stage_id).glob("*/receipt.json")),
        (historical, (state / "historical-stages" / stage_id).glob("**/receipt.json")),
    )
    for matches, paths in locations:
        for path in paths:
            value = receipt(path)
            if value and value["receipt_sha256"] == receipt_sha256:
                stage_identity = (
                    path.parent.name if matches is active else path.parents[1].name
                )
                if value.get("stage_identity") != stage_identity:
                    raise ContractError(
                        f"policy-only prerequisite identity/path mismatch: {stage_id}"
                    )
                value = {
                    **value,
                    "stage_identity": stage_identity,
                    "_receipt_directory": str(path.parent),
                }
                for output in value.get("outputs", []):
                    artifact = regular(
                        path.parent / output["locator"],
                        "policy-only prerequisite output",
                    )
                    if file_hash(artifact) != output["sha256"]:
                        raise ContractError(
                            f"policy-only prerequisite changed: {stage_id}"
                        )
                matches.append(value)
    matches = active if active else historical
    if not matches or any(
        item.get("status") not in {"COMPLETE", "REUSED"} for item in matches
    ):
        raise ContractError(f"policy-only prerequisite is unavailable: {stage_id}")
    if len(matches) > 1:
        copies = {
            object_hash(
                {
                    "receipt": {
                        key: value
                        for key, value in item.items()
                        if not key.startswith("_")
                    },
                    "outputs": item.get("outputs", []),
                    "committed_stage_inputs": committed_stage_input_projection(
                        Path(item["_receipt_directory"]), item["input_sha256"]
                    ),
                }
            )
            for item in matches
        }
        if len(copies) != 1:
            raise ContractError(
                f"policy-only prerequisite has conflicting retained evidence: {stage_id}"
            )
    return min(matches, key=lambda item: item["_receipt_directory"])


def technical_input_lineage(profile: dict, base: Path) -> str:
    values = []
    for stage in sorted(
        profile["automation"]["stages"], key=lambda item: item["stage_id"]
    ):
        if stage["phase"] in POLICY_ONLY_PHASES:
            continue
        inputs = []
        for configured in stage.get("input_files", []):
            material = material_file(
                base, configured, f"technical stage input {configured}"
            )
            inputs.append(
                {
                    "resolved_locator": material["locator"],
                    "sha256": material["sha256"],
                    "size": material["size"],
                }
            )
        values.append({"stage_id": stage["stage_id"], "input_files": inputs})
    return object_hash(values)


def legacy_technical_input_lineage(
    profile: dict, base: Path, state: Path, receipts: dict[str, dict]
) -> str:
    values = []
    for stage in sorted(
        profile["automation"]["stages"], key=lambda item: item["stage_id"]
    ):
        if stage["phase"] in POLICY_ONLY_PHASES:
            continue
        configured = stage.get("input_files", [])
        old_inputs = []
        if configured:
            stage_receipt = receipts[stage["stage_id"]]
            context_path = Path(stage_receipt["_receipt_directory"]) / "context.json"
            context = json.loads(
                regular(context_path, "legacy technical stage context").read_text()
            )
            if context.get("format_version") != FORMAT:
                raise ContractError(
                    f"unsupported legacy stage-input commitment version: {stage['stage_id']}"
                )
            commitment = {
                key: context[key] for key in LEGACY_STAGE_INPUT_FIELDS if key in context
            }
            committed_hash = object_hash(commitment)
            if (
                committed_hash != stage_receipt.get("input_sha256")
                or committed_hash != stage_receipt["stage_identity"]
            ):
                raise ContractError(
                    f"legacy technical stage context is not committed by its receipt: {stage['stage_id']}"
                )
            for value in context.get("input_files", []):
                old_inputs.append(
                    {
                        "resolved_locator": str(Path(value["locator"]).resolve()),
                        "sha256": value["sha256"],
                        "size": value["size"],
                    }
                )
            if {item["resolved_locator"] for item in old_inputs} != {
                str(absolute(base, value)) for value in configured
            }:
                raise ContractError(
                    f"legacy technical stage input manifest differs from the profile: {stage['stage_id']}"
                )
        values.append({"stage_id": stage["stage_id"], "input_files": old_inputs})
    return object_hash(values)


def policy_only_technical_admission(
    profile: dict,
    profile_identity: dict,
    prior_workflow: dict,
    state: Path,
    candidate: Path,
    prior_receipts: dict[str, dict],
    current_input_lineage: str,
    verified_policy_replacement: dict | None = None,
    source_checkouts: dict[str, str] | None = None,
) -> str:
    current_candidate_lineage = technical_candidate_lineage(candidate)
    expected_candidate = (
        prior_workflow.get("technical_candidate_lineage_sha256")
        if prior_workflow.get("technical_lineage_version") == TECHNICAL_LINEAGE_VERSION
        else None
    )
    expected_inputs = (
        prior_workflow.get("technical_input_lineage_sha256")
        if prior_workflow.get("technical_lineage_version") == TECHNICAL_LINEAGE_VERSION
        else None
    )
    if expected_candidate is None or expected_inputs is None:
        sidecar_path = state / "policy-only-technical-lineage.json"
        sidecar = (
            json.loads(sidecar_path.read_text()) if sidecar_path.is_file() else None
        )
        if sidecar:
            claimed = sidecar.pop("content_hash", None)
            if (
                claimed != object_hash(sidecar)
                or sidecar.get("base_workflow_sha256")
                != prior_workflow.get("workflow_sha256")
                or sidecar.get("technical_lineage_version") != TECHNICAL_LINEAGE_VERSION
            ):
                raise ContractError("policy-only technical-lineage sidecar is stale")
            sidecar["content_hash"] = claimed
            expected_candidate = sidecar["technical_candidate_lineage_sha256"]
            expected_inputs = sidecar["technical_input_lineage_sha256"]
        else:
            if prior_workflow.get("candidate") != candidate_state(candidate):
                raise ContractError(
                    "legacy policy-only workflow candidate changed before lineage binding"
                )
            expected_inputs = legacy_technical_input_lineage(
                profile, Path(profile_identity["locator"]).parent, state, prior_receipts
            )
            expected_candidate = current_candidate_lineage
            sidecar = {
                "base_workflow_sha256": prior_workflow.get("workflow_sha256"),
                "technical_candidate_lineage_sha256": expected_candidate,
                "technical_input_lineage_sha256": expected_inputs,
                "technical_lineage_version": TECHNICAL_LINEAGE_VERSION,
            }
            sidecar["content_hash"] = object_hash(sidecar)
            atomic_json(sidecar_path, sidecar)
    if current_candidate_lineage != expected_candidate:
        raise ContractError("policy-only candidate technical lineage changed")
    if current_input_lineage != expected_inputs:
        raise ContractError("policy-only technical input lineage changed")
    if prior_workflow.get("technical_state_transition") and not prior_workflow.get(
        "technical_adjudication_transition"
    ):
        try:
            technical_state_correction.verify_transition(
                state,
                candidate,
                profile,
                profile_identity,
                prior_workflow,
                prior_receipts,
                current_input_lineage,
                technical_candidate_lineage,
            )
        except technical_state_correction.CorrectionError as error:
            raise ContractError(str(error)) from error
    if prior_workflow.get("technical_state_transition") and not policy_state_is_current(
        candidate, Path(profile_identity["locator"]).parent, required=True
    ):
        if verified_policy_replacement is None:
            raise ContractError(
                "technical-state correction policy evidence expired"
            )
        replacement = policy_refresh_bundle(
            Path(verified_policy_replacement["locator"]),
            profile["project"]["project_id"],
        )
        if replacement["sha256"] != verified_policy_replacement["sha256"]:
            raise ContractError(
                "technical-state correction policy replacement changed"
            )
    if prior_workflow.get("technical_adjudication_transition"):
        try:
            technical_adjudication.verify_transition(
                state,
                candidate,
                profile,
                profile_identity,
                prior_workflow,
                prior_receipts,
                current_input_lineage,
                technical_candidate_lineage,
                source_checkouts,
                ({
                    item["component_id"]: item["revision"]
                    for item in profile["project"].get("components", [])
                } or None),
            )
        except technical_adjudication.AdjudicationError as error:
            raise ContractError(str(error)) from error
    return current_candidate_lineage


def policy_refresh_bundle(path: Path, project_id: str) -> dict:
    path = regular(path.resolve(), "policy refresh bundle")
    value = json.loads(path.read_text())
    if (
        value.get("format_version") != POLICY_REFRESH_FORMAT
        or value.get("project_id") != project_id
    ):
        raise ContractError("policy refresh bundle identity mismatch")
    sources = value.get("sources")
    required = {"PROGRAMME_POLICY", "CURRENT_TICKETS"}
    if (
        not isinstance(sources, list)
        or {item.get("source_kind") for item in sources} != required
    ):
        raise ContractError(
            "policy refresh bundle must bind policy and current tickets"
        )
    if len(sources) != len(required):
        raise ContractError("policy refresh source kinds must be unique")
    for source in sources:
        if source.get("retrieval_status") != "SUCCESS":
            raise ContractError("policy refresh source was not successfully collected")
        if (
            not isinstance(source.get("collection_scope"), str)
            or not source["collection_scope"]
        ):
            raise ContractError("policy refresh collection scope is missing")
        evidence = source.get("evidence", {})
        locator = evidence.get("locator")
        digest = evidence.get("sha256")
        if not isinstance(locator, str) or not re.fullmatch(
            r"[0-9a-f]{64}", str(digest)
        ):
            raise ContractError("policy refresh source identity is incomplete")
        artifact = absolute(path.parent, locator)
        try:
            artifact.relative_to(path.parent)
        except ValueError as error:
            raise ContractError(
                "policy refresh source escapes its isolated bundle"
            ) from error
        if file_hash(regular(artifact, "policy refresh source")) != digest:
            raise ContractError("policy refresh source content changed")
        if not all(
            isinstance(source.get(field), str) and source[field]
            for field in ("source_id", "source_locator", "retrieved_at", "expires_at")
        ):
            raise ContractError(
                "policy refresh source identity/timestamps are incomplete"
            )
        try:
            retrieved = datetime.fromisoformat(
                source["retrieved_at"].replace("Z", "+00:00")
            ).timestamp()
            expires = datetime.fromisoformat(
                source["expires_at"].replace("Z", "+00:00")
            ).timestamp()
        except (AttributeError, ValueError):
            raise ContractError("policy refresh timestamps are invalid")
        now = time.time()
        if retrieved > now or now >= expires or expires - retrieved > 86400:
            raise ContractError("policy refresh bundle is outside its freshness window")
    body = {**value, "locator": str(path), "sha256": file_hash(path)}
    return body


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
    adapter_identity = object_hash(command_identity(base, adapter))
    worker_adapter = stage.get("worker_adapter")
    worker_identity = (
        object_hash(command_identity(base, worker_adapter)) if worker_adapter else None
    )
    runtime_values = list(stage.get("runtime_dependency_files", []))
    provider_mode = (
        provider_execution_mode(profile, profile_identity)
        if stage.get("phase") in METIS_PROVIDER_PHASES
        else None
    )
    provider_runtime = provider_mode == "LIVE"
    if provider_runtime and not any(
        absolute(base, value) == default_runtime_manifest() for value in runtime_values
    ):
        runtime_values.append(str(default_runtime_manifest()))
    runtime_dependencies = [
        runtime_dependency(base, value, f"stage runtime dependency {value}")
        for value in runtime_values
    ]
    if provider_runtime:
        manifest_dependencies = [
            item for item in runtime_dependencies if "runtime_identity_sha256" in item
        ]
        if len(manifest_dependencies) != 1:
            raise ContractError(
                "provider-backed stage requires one verified Metis runtime identity"
            )
        executable = command_executable(base, adapter, runtime_environment([]))
        if executable != Path(sys.executable).absolute():
            raise ContractError(
                "provider-backed adapter uses a different Python environment"
            )
        if any(
            os.environ.get(name) for name in ("PYTHONPATH", "PYTHONHOME", "UV_PYTHON")
        ):
            raise ContractError(
                "provider-backed adapter has an unsupported import override"
            )
        virtual_env = os.environ.get("VIRTUAL_ENV")
        if virtual_env and Path(virtual_env).absolute() != executable.parent.parent:
            raise ContractError(
                "provider-backed adapter has a conflicting virtual environment"
            )
        executable_sha256 = file_hash(executable.resolve())
        if executable_sha256 != manifest_dependencies[0]["python_executable_sha256"]:
            raise ContractError(
                "provider-backed adapter does not use the verified Python runtime"
            )
    inputs = {
        "format_version": FORMAT,
        "project_id": profile["project"]["project_id"],
        "profile_sha256": profile_identity["sha256"],
        "stage_id": stage["stage_id"],
        "phase": stage["phase"],
        "adapter_sha256": adapter_identity,
        "source_bindings": sources,
        "source_checkouts": checkouts,
        "selectors": {
            key: value
            for key, value in selectors.items()
            if key != "policy_refresh" or stage["phase"] in POLICY_ONLY_PHASES
        },
        "input_files": files,
        "dependencies": {
            key: dependency_receipts[key]["receipt_sha256"]
            for key in sorted(dependency_receipts)
        },
        "profile_schema_version": profile["schema_version"],
        "contract_release": profile_identity.get("contract_release"),
    }
    if worker_identity:
        inputs["worker_adapter_sha256"] = worker_identity
    if runtime_dependencies:
        inputs["runtime_dependency_files"] = runtime_dependencies
    if provider_runtime:
        inputs["runtime_adapter_executable"] = str(executable)
        inputs["runtime_adapter_executable_sha256"] = executable_sha256
    human_evidence = stage.get("human_dependency", {}).get("evidence")
    if human_evidence:
        path = absolute(base, human_evidence)
        inputs["human_dependency_evidence"] = (
            {"locator": str(path), "sha256": file_hash(path)}
            if path.is_file() and not path.is_symlink()
            else {"locator": str(path), "status": "MISSING"}
        )
    # The candidate is an output of authoritative integration.  Making its
    # mutable state an input to every stage invalidates already-completed
    # provider work on the first resume.  Pre-6.3 profiles retain their frozen
    # identity semantics; 6.3 relies on explicit dependency receipts instead.
    if profile.get("schema_version") not in {
        "6.3",
        "6.4",
        "6.5",
        "6.6",
        "6.6.1",
        "6.7",
        "6.8",
    } or stage["phase"] in {
        "PACKAGE_EXPORT",
        "POPULATION_SCOPED_REPORTING",
        "EXISTING_REPORT_FOLLOWUP",
    }:
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
    if context.get("runtime_adapter_executable"):
        argv[0] = context["runtime_adapter_executable"]
    env = runtime_environment(credentials)
    env["FIRMWARE_CAMPAIGN_CONTEXT"] = str(context_path)
    env["CAMPAIGN_DATABASE_URI"] = (
        f"file:{context['candidate_path']}?mode=ro&immutable=1"
    )
    env["CAMPAIGN_READER_LIMIT"] = str(context["reader_limit"])
    env["METIS_FIRMWARE_PROVIDER_CHECKPOINT_ROOT"] = context["provider_checkpoint_root"]
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
    local = (
        Path(__file__).resolve().parents[1].parent
        / "firmware-campaign-bootstrap/scripts/export_internal_review_packages.py"
    )
    workspace = (
        Path(__file__).resolve().parents[2].parent
        / "portable-firmware-campaign/.agents/skills/firmware-campaign-bootstrap/scripts/export_internal_review_packages.py"
    )
    for path in (local, workspace):
        if path.is_file() and not path.is_symlink():
            return path
    raise ContractError("capability-6.4 generic package exporter is unavailable")


def run_package_export(context: dict, work: Path) -> None:
    candidate_hash = context.get("candidate_before", {}).get("sha256")
    if not candidate_hash:
        raise ContractError("PACKAGE_EXPORT requires an immutable candidate identity")
    command = [
        sys.executable,
        str(package_exporter_path()),
        "--profile",
        context["profile_locator"],
        "--candidate",
        context["candidate_path"],
        "--project-directory",
        context["project_directory"],
        "--output",
        str(work),
        "--expected-candidate-sha256",
        candidate_hash,
    ]
    for component, path in sorted(context["source_checkouts"].items()):
        command += ["--source-path", f"{component}={path}"]
    for values in context.get("dependency_outputs", {}).values():
        if any(item["locator"].endswith("SEVERITY-INDEX.json") for item in values):
            command += ["--severity-path", str(Path(values[0]["locator"]).parent)]
        if any(item["locator"].endswith("POLICY-INDEX.json") for item in values):
            command += ["--policy-path", str(Path(values[0]["locator"]).parent)]
        if any(
            item["locator"].endswith("EXISTING-REPORT-FOLLOWUP-INDEX.json")
            for item in values
        ):
            command += ["--followup-path", str(Path(values[0]["locator"]).parent)]
    result = subprocess.run(
        command,
        cwd=context["project_directory"],
        env=runtime_environment([]),
        text=True,
        capture_output=True,
        check=False,
    )
    (work / "stdout.log").write_text(result.stdout)
    (work / "stderr.log").write_text(result.stderr)
    if result.returncode:
        raise ContractError(f"generic package export failed: {result.stderr.strip()}")


def run_severity_calibration(context: dict, work: Path) -> None:
    script = package_exporter_path().with_name("calibrate_severity.py")
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--profile",
            context["profile_locator"],
            "--candidate",
            context["candidate_path"],
            "--output",
            str(work),
        ],
        cwd=context["project_directory"],
        env=runtime_environment([]),
        text=True,
        capture_output=True,
        check=False,
    )
    (work / "stdout.log").write_text(result.stdout)
    (work / "stderr.log").write_text(result.stderr)
    if result.returncode:
        raise ContractError(
            f"generic severity calibration failed: {result.stderr.strip()}"
        )


def run_policy_reconciliation(context: dict, work: Path) -> None:
    script = package_exporter_path().with_name("reconcile_policy_scope.py")
    evidence = [
        Path(item["locator"])
        for values in context["dependency_outputs"].values()
        for item in values
        if item["locator"].endswith("policy-reconciliation-input.json")
    ]
    if len(evidence) != 1:
        raise ContractError(
            "POLICY_RECONCILIATION requires exactly one collected policy input"
        )
    release = json.loads(
        regular(script.parents[1] / "RELEASE.json", "policy-control release").read_text()
    )
    required_format = (
        "firmware-policy-reconciliation-input-v6.10"
        if release.get("version") in {"6.10.0", "6.11.0"}
        else "firmware-policy-reconciliation-input-v6.8"
    )
    if (
        context.get("profile_schema_version") == "6.8"
        and json.loads(
            regular(evidence[0], "policy reconciliation input").read_text()
        ).get("format_version")
        != required_format
    ):
        raise ContractError(
            f"schema-v6.8 reconciliation under capability {release.get('version')} "
            f"requires {required_format}"
        )
    clean_env = runtime_environment([])
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--candidate",
            context["candidate_path"],
            "--evidence",
            str(evidence[0]),
            "--project-directory",
            context["project_directory"],
            "--output",
            str(work),
        ],
        cwd=context["project_directory"],
        env=clean_env,
        text=True,
        capture_output=True,
        check=False,
    )
    (work / "stdout.log").write_text(result.stdout)
    (work / "stderr.log").write_text(result.stderr)
    if result.returncode:
        raise ContractError(
            f"generic policy reconciliation failed: {result.stderr.strip()}"
        )
    verifier = script.with_name("verify_policy_reconciliation.py")
    checked = subprocess.run(
        [
            sys.executable,
            str(verifier),
            context["candidate_path"],
            "--project-directory",
            context["project_directory"],
        ],
        cwd=context["project_directory"],
        env=clean_env,
        text=True,
        capture_output=True,
        check=False,
    )
    (work / "independent-verifier.json").write_text(checked.stdout)
    if checked.returncode:
        raise ContractError(
            f"generic policy verification failed: {checked.stdout.strip()}"
        )


def run_population_scoped_reporting(context: dict, work: Path) -> None:
    script = package_exporter_path().with_name("population_scoped_reporting.py")
    candidate_hash = context.get("candidate_before", {}).get("sha256")
    if not candidate_hash:
        raise ContractError(
            "POPULATION_SCOPED_REPORTING requires an immutable candidate identity"
        )
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            context["candidate_path"],
            "--expected-candidate-sha256",
            candidate_hash,
            "--project-directory",
            context["project_directory"],
            "--output-json",
            str(work / "POPULATION-SCOPED-REPORT.json"),
            "--output-markdown",
            str(work / "POPULATION-SCOPED-REPORT.md"),
        ],
        cwd=context["project_directory"],
        env=runtime_environment([]),
        text=True,
        capture_output=True,
        check=False,
    )
    (work / "stdout.log").write_text(result.stdout)
    (work / "stderr.log").write_text(result.stderr)
    if result.returncode:
        raise ContractError(
            f"generic population-scoped reporting failed: {result.stderr.strip()}"
        )


def run_existing_report_followup(context: dict, work: Path) -> None:
    script = package_exporter_path().with_name("assess_existing_report_followup.py")
    candidate_hash = context.get("candidate_before", {}).get("sha256")
    if not candidate_hash:
        raise ContractError(
            "EXISTING_REPORT_FOLLOWUP requires an immutable candidate identity"
        )
    command = [
        sys.executable,
        str(script),
        "--candidate",
        context["candidate_path"],
        "--profile",
        context["profile_locator"],
        "--project-directory",
        context["project_directory"],
        "--output",
        str(work),
        "--expected-candidate-sha256",
        candidate_hash,
    ]
    routing = [
        item["locator"]
        for item in context.get("input_files", [])
        if item["locator"].endswith("INTERNAL-PSIRT-ROUTING-INDEX.json")
    ]
    if len(routing) > 1:
        raise ContractError("EXISTING_REPORT_FOLLOWUP has ambiguous routing evidence")
    if routing:
        command += ["--routing-evidence", routing[0]]
    result = subprocess.run(
        command,
        cwd=context["project_directory"],
        env=runtime_environment([]),
        text=True,
        capture_output=True,
        check=False,
    )
    (work / "stdout.log").write_text(result.stdout)
    (work / "stderr.log").write_text(result.stderr)
    if result.returncode:
        raise ContractError(
            f"generic existing-report follow-up failed: {result.stderr.strip()}"
        )


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
            if context.get("profile_schema_version")
            in ("6", "6.2", "6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7", "6.8")
            and packet.get("contract_version")
            not in (
                {"6"}
                if context.get("profile_schema_version") == "6"
                else (
                    {"6.2", "6.2.0"}
                    if context.get("profile_schema_version") == "6.2"
                    else (
                        {"6.3", "6.3.0"}
                        if context.get("profile_schema_version") == "6.3"
                        else (
                            {"6.4", "6.4.0"}
                            if context.get("profile_schema_version") == "6.4"
                            else (
                                {"6.5", "6.5.0"}
                                if context.get("profile_schema_version") == "6.5"
                                else (
                                    {"6.6", "6.6.0", "6.6.1"}
                                    if context.get("profile_schema_version")
                                    in {"6.6", "6.6.1"}
                                    else (
                                        {"6.7", "6.7.0"}
                                        if context.get("profile_schema_version")
                                        == "6.7"
                                        else {"6.8", "6.8.0"}
                                    )
                                )
                            )
                        )
                    )
                )
            )
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


def retire_stage_result(state: Path, final: Path, current: dict, reason: str) -> None:
    """Preserve a superseded complete or blocked result before recomputation."""
    history = (
        state
        / "historical-stages"
        / current["stage_id"]
        / current["stage_identity"]
        / f"{current['receipt_sha256']}-{reason}"
    )
    if not history.exists():
        history.parent.mkdir(parents=True, exist_ok=True)
        os.replace(final, history)
    else:
        shutil.rmtree(final)


def current_evidence_needs_refresh(stage: dict, final: Path, current: dict) -> bool:
    if stage["phase"] not in CURRENT_EVIDENCE_PHASES or current.get("status") not in {
        "COMPLETE",
        "REUSED",
    }:
        return False
    if stage.get("refresh_on_resume") is True:
        return True
    maximum_age = stage.get("max_evidence_age_seconds", 86400)
    if not isinstance(maximum_age, int) or not 0 <= maximum_age <= 604800:
        raise ContractError("current evidence maximum age must be 0..604800 seconds")
    return time.time() - (final / "receipt.json").stat().st_mtime >= maximum_age


def policy_state_is_current(
    candidate: Path, project: Path, required: bool = False
) -> bool:
    """Revalidate persisted policy evidence before a cached policy result is trusted."""
    if not candidate.is_file():
        return not required
    try:
        with sqlite3.connect(
            f"file:{candidate.resolve()}?mode=ro&immutable=1", uri=True
        ) as database:
            if not database.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='policy_rule_evidence_condition'"
            ).fetchone():
                return not required
    except sqlite3.DatabaseError:
        return not required
    verifier = package_exporter_path().with_name("verify_policy_reconciliation.py")
    checked = subprocess.run(
        [
            sys.executable,
            str(verifier),
            str(candidate),
            "--project-directory",
            str(project),
        ],
        cwd=project,
        env=runtime_environment([]),
        text=True,
        capture_output=True,
        check=False,
    )
    return checked.returncode == 0


def restore_candidate(candidate: Path, before: dict, backup: Path) -> dict:
    """Restore the exact pre-stage candidate after an unauthorized direct mutation."""
    for suffix in ("-wal", "-shm", "-journal"):
        Path(str(candidate) + suffix).unlink(missing_ok=True)
    if before.get("exists"):
        if not backup.exists():
            raise ContractError("candidate recovery copy is unavailable")
        regular(backup, "candidate recovery copy")
        if candidate_state(backup) != before:
            raise ContractError("candidate recovery copy does not match its commitment")
        descriptor, name = tempfile.mkstemp(
            dir=candidate.parent, prefix=".candidate-restore.", suffix=".db"
        )
        os.close(descriptor)
        replacement = Path(name)
        try:
            shutil.copy2(backup, replacement)
            replacement.chmod(0o600)
            os.replace(replacement, candidate)
        finally:
            replacement.unlink(missing_ok=True)
    elif candidate.exists():
        candidate.unlink()
    restored = candidate_state(candidate)
    if restored != before:
        raise ContractError("candidate recovery did not restore the prior identity")
    return restored


def pending_commit_path(control: Path) -> Path:
    return control / "pending-commit.json"


def pending_commit_record(
    control: Path,
    work: Path,
    stage: dict,
    inputs: dict,
    receipt_body: dict,
    before: dict,
    after: dict,
) -> Path:
    """Durably bind staged candidate bytes and outputs before promotion."""
    value = {
        "format_version": PENDING_COMMIT_FORMAT,
        "candidate_before": before,
        "candidate_after": after,
        "input_sha256": receipt_body["input_sha256"],
        "receipt_sha256": receipt_body["receipt_sha256"],
        "result_directory": str(work),
        "stage_id": stage["stage_id"],
        "phase": stage["phase"],
        "stage_identity": receipt_body["stage_identity"],
        "stage_inputs": inputs,
    }
    value["content_hash"] = object_hash(value)
    path = pending_commit_path(control)
    atomic_json(path, value)
    return path


def _pending_directory(path: Path, root: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ContractError(f"{label} is unavailable")
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ContractError(f"{label} escapes campaign state") from error
    return resolved


def _pending_archive_directory(
    path: Path, archive: Path, conflict: str, label: str
) -> Path | None:
    """Classify an optional archive entry with lstat before following its path."""
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(mode):
        raise ContractError(
            f"failed pending-commit archive has conflicting {conflict}"
        )
    return _pending_directory(path, archive, label)


def _verified_pending_receipt(
    directory: Path, pending: dict, label: str
) -> dict | None:
    path = directory / "receipt.json"
    if not path.exists():
        return None
    value = receipt(regular(path, label))
    if (
        not value
        or value.get("receipt_sha256") != pending["receipt_sha256"]
        or value.get("stage_id") != pending["stage_id"]
        or value.get("phase") != pending["phase"]
        or value.get("stage_identity") != pending["stage_identity"]
        or value.get("input_sha256") != pending["input_sha256"]
        or value.get("candidate_before") != pending["candidate_before"]
        or value.get("candidate_after") != pending["candidate_after"]
    ):
        raise ContractError("pending candidate receipt conflicts with its commitment")
    for output in value.get("outputs", []):
        artifact = regular(directory / output["locator"], "pending candidate output")
        if (
            file_hash(artifact) != output["sha256"]
            or artifact.stat().st_size != output["size"]
        ):
            raise ContractError("pending candidate output conflicts with its receipt")
    return value


def _pending_fallback(
    state: Path,
    candidate: Path,
    control: Path,
    work: Path,
    pending: dict,
    reason: str,
) -> dict:
    """Restore the predecessor through an idempotent fallback transaction."""
    before = pending["candidate_before"]
    archive = (
        state
        / "failed-pending-commits"
        / pending["stage_id"]
        / pending["stage_identity"]
        / pending["content_hash"]
    )
    archive_parent = archive.parent
    archive_parent.mkdir(parents=True, exist_ok=True)
    _pending_directory(
        archive_parent,
        state / "failed-pending-commits",
        "failed pending-commit archive parent",
    )
    recovery_body = {
        "format_version": PENDING_COMMIT_FORMAT,
        "pending_content_hash": pending["content_hash"],
        "result": "PREDECESSOR_RESTORED",
        "reason": reason,
        "candidate": before,
    }

    def valid_record(path: Path) -> dict:
        record = json.loads(regular(path, "pending fallback record").read_text())
        claimed = record.pop("content_hash", None)
        if (
            claimed != object_hash(record)
            or set(record) != set(recovery_body)
            or any(
                record[key] != recovery_body[key]
                for key in recovery_body
                if key != "reason"
            )
            or not isinstance(record.get("reason"), str)
        ):
            raise ContractError("conflicting failed pending-commit archive exists")
        return record

    def incomplete_initialization(path: Path) -> bool:
        entries = list(path.iterdir())
        return all(
            entry.is_file()
            and not entry.is_symlink()
            and entry.name.startswith(".recovery.json.")
            and entry.name.endswith(".tmp")
            for entry in entries
        )

    # R4 could expose its initialization directory before recovery.json. Preserve
    # that fragment and replace only the complete directory atomically.
    if archive.exists() and not (archive / "recovery.json").exists():
        archive = _pending_directory(
            archive, archive_parent, "incomplete failed pending-commit archive"
        )
        if not incomplete_initialization(archive):
            raise ContractError("conflicting failed pending-commit archive exists")
        rows = [
            {"name": item.name, "sha256": file_hash(item), "size": item.stat().st_size}
            for item in sorted(archive.iterdir())
        ]
        fragment = archive_parent / (
            f".{pending['content_hash']}.incomplete-{object_hash(rows)}"
        )
        if fragment.exists():
            raise ContractError("conflicting fallback initialization fragment exists")
        os.replace(archive, fragment)
        archive = archive_parent / pending["content_hash"]

    if not archive.exists():
        complete_preparations = []
        prefix = f".{pending['content_hash']}.preparing."
        for preparation in sorted(archive_parent.glob(prefix + "*")):
            preparation = _pending_directory(
                preparation, archive_parent, "pending fallback preparation"
            )
            if (preparation / "recovery.json").exists():
                if set(item.name for item in preparation.iterdir()) != {
                    "recovery.json"
                }:
                    raise ContractError(
                        "pending fallback preparation has conflicting material"
                    )
                valid_record(preparation / "recovery.json")
                complete_preparations.append(preparation)
            elif not incomplete_initialization(preparation):
                raise ContractError("pending fallback preparation is invalid")
        if len(complete_preparations) > 1:
            raise ContractError("multiple complete pending fallback preparations exist")
        if complete_preparations:
            preparation = complete_preparations[0]
        else:
            preparation = Path(
                tempfile.mkdtemp(dir=archive_parent, prefix=prefix)
            )
            record = {**recovery_body, "content_hash": object_hash(recovery_body)}
            atomic_json(preparation / "recovery.json", record)
        os.replace(preparation, archive)

    archive = _pending_directory(
        archive, state / "failed-pending-commits", "failed pending-commit archive"
    )
    record = valid_record(archive / "recovery.json")
    reason = record["reason"]
    if set(path.name for path in archive.iterdir()) - {
        "recovery.json",
        "result",
        "control",
    }:
        raise ContractError("failed pending-commit archive has unexpected material")
    archived_result_path = archive / "result"
    archived_result = _pending_archive_directory(
        archived_result_path,
        archive,
        "results",
        "archived pending candidate result",
    )
    if work.exists() and archived_result is not None:
        raise ContractError("failed pending-commit archive has conflicting results")
    archived_control = _pending_archive_directory(
        archive / "control",
        archive,
        "controls",
        "archived pending candidate control",
    )
    if archived_control is not None:
        raise ContractError("failed pending-commit archive has conflicting controls")

    # All archive components have been checked before candidate or result changes.
    if candidate_state(candidate) != before:
        restore_candidate(candidate, before, control / "candidate-prior.db")
    if work.exists():
        os.replace(work, archived_result_path)
    os.replace(control, archive / "control")
    return {"result": "PREDECESSOR_RESTORED", "reason": reason}


def recover_pending_commits(
    state: Path, candidate: Path, profile: dict, profile_identity: dict
) -> list[dict]:
    """Serialize and recover prepared candidate commits before stage reuse."""
    lock_path = state / "authoritative-integrator.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ContractError(
                "pending candidate recovery blocked by active writer lock"
            ) from error
        return _recover_pending_commits_locked(
            state, candidate, profile, profile_identity
        )


def _recover_pending_commits_locked(
    state: Path, candidate: Path, profile: dict, profile_identity: dict
) -> list[dict]:
    """Complete or roll back prepared candidate commits before stage reuse."""
    recovered = []
    stages = {item["stage_id"]: item for item in profile["automation"]["stages"]}
    for marker in sorted(state.glob(".candidate-*/pending-commit.json")):
        control = _pending_directory(marker.parent, state, "pending candidate control")
        pending = json.loads(regular(marker, "pending candidate commitment").read_text())
        claimed = pending.pop("content_hash", None)
        required = {
            "format_version",
            "candidate_before",
            "candidate_after",
            "input_sha256",
            "receipt_sha256",
            "result_directory",
            "stage_id",
            "phase",
            "stage_identity",
            "stage_inputs",
        }
        if (
            set(pending) != required
            or claimed != object_hash(pending)
            or pending.get("format_version") != PENDING_COMMIT_FORMAT
            or pending.get("stage_id") not in stages
            or stages[pending["stage_id"]]["phase"] != pending.get("phase")
            or pending.get("input_sha256") != object_hash(pending.get("stage_inputs"))
            or pending["stage_inputs"].get("profile_sha256")
            != profile_identity["sha256"]
        ):
            raise ContractError("pending candidate commitment is invalid or stale")
        pending["content_hash"] = claimed
        work_path = Path(pending["result_directory"])
        final_path = (
            state / "stages" / pending["stage_id"] / pending["stage_identity"]
        )
        work = None
        if work_path.exists():
            work = _pending_directory(
                work_path, state / "stages", "pending candidate result"
            )
        final = None
        if final_path.exists():
            final = _pending_directory(
                final_path, state / "stages", "committed candidate result"
            )
        staged_receipt = (
            _verified_pending_receipt(work, pending, "pending candidate receipt")
            if work
            else None
        )
        final_receipt = (
            _verified_pending_receipt(final, pending, "committed candidate receipt")
            if final
            else None
        )
        if staged_receipt and final_receipt:
            raise ContractError("pending candidate has duplicate committed results")
        before = pending["candidate_before"]
        after = pending["candidate_after"]
        backup = control / "candidate-prior.db"
        if before.get("exists") and candidate_state(backup) != before:
            raise ContractError("pending candidate recovery copy conflicts with predecessor")
        current = candidate_state(candidate)
        if final_receipt:
            if current != after:
                raise ContractError("committed candidate receipt conflicts with candidate")
        elif not staged_receipt:
            recovered.append(
                _pending_fallback(
                    state,
                    candidate,
                    control,
                    work_path,
                    pending,
                    "pending result or receipt is unavailable",
                )
            )
            continue
        elif current == before:
            staged = control / "candidate-stage.db"
            if candidate_state(staged) != after:
                recovered.append(
                    _pending_fallback(
                        state,
                        candidate,
                        control,
                        work_path,
                        pending,
                        "pending candidate bytes are unavailable",
                    )
                )
                continue
            staged.chmod(0o600)
            os.replace(staged, candidate)
            if candidate_state(candidate) != after:
                raise ContractError("pending candidate promotion changed its identity")
        elif current != after:
            recovered.append(
                _pending_fallback(
                    state,
                    candidate,
                    control,
                    work_path,
                    pending,
                    "authoritative candidate does not match pending transaction",
                )
            )
            continue
        if not final_receipt:
            final_path.parent.mkdir(parents=True, exist_ok=True)
            os.replace(work, final_path)
            final_receipt = _verified_pending_receipt(
                final_path, pending, "recovered candidate receipt"
            )
        if candidate_state(candidate) != after or not final_receipt:
            raise ContractError("pending candidate recovery did not commit atomically")
        recovered.append(
            {
                "result": "PENDING_COMMIT_COMPLETED",
                "stage_id": pending["stage_id"],
                "receipt_sha256": pending["receipt_sha256"],
                "candidate_sha256": after.get("sha256"),
            }
        )
        settled = (
            state
            / "settled-pending-commits"
            / pending["stage_id"]
            / pending["stage_identity"]
            / pending["receipt_sha256"]
        )
        if settled.exists():
            raise ContractError("conflicting settled pending-commit archive exists")
        settled.parent.mkdir(parents=True, exist_ok=True)
        os.replace(control, settled)
        shutil.rmtree(settled)
    return recovered


def record_candidate_observation(
    state: Path, stage: dict, identity: str, before: dict, after: dict
) -> None:
    """Retain candidate access audit separately from material stage identity."""
    observation = {
        "stage_id": stage["stage_id"],
        "phase": stage["phase"],
        "stage_identity": identity,
        "candidate_before": before,
        "candidate_after": after,
    }
    path = (
        state
        / "stage-audit"
        / stage["stage_id"]
        / identity
        / f"{object_hash(observation)}.json"
    )
    if not path.exists():
        atomic_json(path, observation)


def verify_staged_candidate(candidate: Path) -> None:
    uri = f"file:{candidate}?mode=ro&immutable=1"
    try:
        with sqlite3.connect(uri, uri=True) as database:
            quick = database.execute("PRAGMA quick_check").fetchall()
            foreign = database.execute("PRAGMA foreign_key_check").fetchall()
    except sqlite3.DatabaseError as error:
        raise ContractError(
            "staged candidate is not a valid SQLite database"
        ) from error
    if quick != [("ok",)] or foreign:
        raise ContractError("staged candidate failed SQLite integrity checks")


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
    quarantine = state / "CANDIDATE-QUARANTINED.json"
    if quarantine.exists():
        raise ContractError(f"candidate is quarantined pending recovery: {quarantine}")
    current = receipt(final / "receipt.json")
    unresolved_dependencies = any(
        dep["status"] not in {"COMPLETE", "REUSED"}
        for dep in dependency_receipts.values()
    )
    dependency_blocks = unresolved_dependencies and not stage.get(
        "continue_on_blocked_dependencies", False
    )
    human_class, detail = check_human(stage, Path(profile_identity["locator"]).parent)
    policy_dependent = stage["phase"] in POLICY_ONLY_PHASES
    policy_current = (
        policy_state_is_current(
            candidate,
            Path(profile_identity["locator"]).parent,
            profile.get("schema_version") == "6.8",
        )
        if policy_dependent
        else True
    )
    policy_refreshable = stage["phase"] in CURRENT_EVIDENCE_PHASES | {
        "POLICY_RECONCILIATION"
    }
    if not policy_current and not policy_refreshable:
        raise ContractError("policy-dependent output uses stale or unverified evidence")
    if current and not policy_current:
        retire_stage_result(state, final, current, "policy-evidence-refresh")
        current = None
    elif (
        current
        and current.get("status") == "BLOCKED"
        and not dependency_blocks
        and not human_class
    ):
        retire_stage_result(state, final, current, "resolved")
        current = None
    elif current and current_evidence_needs_refresh(stage, final, current):
        retire_stage_result(state, final, current, "refresh")
        current = None
    if current:
        for item in current.get("outputs", []):
            path = regular(final / item["locator"], "reused stage output")
            if file_hash(path) != item["sha256"]:
                raise ContractError(
                    f"completed stage output changed: {stage['stage_id']}"
                )
        return current
    if (
        stage.get("phase") in METIS_PROVIDER_PHASES
        and provider_execution_mode(profile, profile_identity) == "FROZEN_REPLAY"
    ):
        raise ContractError("frozen provider replay has no reusable completed receipt")
    if dependency_blocks:
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
    preserve_control = False
    pending_path = None
    fully_committed = False
    control = Path(
        tempfile.mkdtemp(dir=state, prefix=f".candidate-{stage['stage_id']}.")
    )
    try:
        writer = stage["phase"] in {
            "CANDIDATE_BUILD",
            "AUTHORITATIVE_INTEGRATION",
            "SEVERITY_CALIBRATION",
            "POLICY_RECONCILIATION",
        }
        if writer:
            lock_path = state / "authoritative-integrator.lock"
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            lock_descriptor = lock_path.open("a+")
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = candidate_state(candidate)
        backup = control / "candidate-prior.db"
        if before.get("exists"):
            shutil.copy2(candidate, backup)
            backup.chmod(0o400)
        execution_candidate = control / "candidate-stage.db"
        if before.get("exists"):
            shutil.copy2(candidate, execution_candidate)
        if not writer and execution_candidate.exists():
            execution_candidate.chmod(0o400)
        dependency_outputs = {}
        for dep, value in dependency_receipts.items():
            root = Path(
                value.get(
                    "_receipt_directory",
                    state / "stages" / dep / value["stage_identity"],
                )
            )
            dependency_outputs[dep] = [
                {**item, "locator": str(root / item["locator"])}
                for item in value.get("outputs", [])
            ]
        context = {
            **inputs,
            "candidate_path": str(execution_candidate),
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
            "dependency_statuses": {
                dep: value["status"] for dep, value in dependency_receipts.items()
            },
            "authoritative_integrator": stage["phase"]
            in {
                "AUTHORITATIVE_INTEGRATION",
                "SEVERITY_CALIBRATION",
                "POLICY_RECONCILIATION",
            },
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
        after = candidate_state(execution_candidate)
        if not writer and after != before:
            raise ContractError(
                f"non-authoritative stage changed candidate: {stage['stage_id']}"
            )
        if candidate_state(candidate) != before:
            raise ContractError(
                f"stage changed the authoritative candidate directly: {stage['stage_id']}"
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
        if not writer:
            if execution_candidate.exists():
                execution_candidate.unlink()
            if backup.exists():
                backup.unlink()
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
                    if profile.get("schema_version")
                    in ("6", "6.2", "6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7", "6.8")
                    and packet.get("contract_version")
                    not in (
                        {"6"}
                        if profile.get("schema_version") == "6"
                        else (
                            {"6.2", "6.2.0"}
                            if profile.get("schema_version") == "6.2"
                            else (
                                {"6.3", "6.3.0"}
                                if profile.get("schema_version") == "6.3"
                                else (
                                    {"6.4", "6.4.0"}
                                    if profile.get("schema_version") == "6.4"
                                    else (
                                        {"6.5", "6.5.0"}
                                        if profile.get("schema_version") == "6.5"
                                        else (
                                            {"6.6", "6.6.0", "6.6.1"}
                                            if profile.get("schema_version")
                                            in {"6.6", "6.6.1"}
                                            else (
                                                {"6.7", "6.7.0"}
                                                if profile.get("schema_version")
                                                == "6.7"
                                                else {"6.8", "6.8.0"}
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
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
            "campaign_write_attempts": 0
            if stage["phase"] != "AUTHORITATIVE_INTEGRATION"
            else stage.get("campaign_write_attempts", 0),
        }
        if writer or "candidate_before" in inputs:
            body.update({"candidate_before": before, "candidate_after": after})
        body["receipt_sha256"] = object_hash(body)
        atomic_json(temp / "receipt.json", body)
        if writer:
            if profile.get("schema_version") not in {"4", "5"}:
                verify_staged_candidate(execution_candidate)
            pending_path = pending_commit_record(
                control, temp, stage, inputs, body, before, after
            )
            execution_candidate.chmod(0o600)
            candidate.parent.mkdir(parents=True, exist_ok=True)
            os.replace(execution_candidate, candidate)
            committed = candidate_state(candidate)
            if committed != after:
                raise ContractError("atomic candidate replacement changed its identity")
        if not writer:
            record_candidate_observation(state, stage, identity, before, after)
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(temp, final)
        if writer:
            verified = _verified_pending_receipt(
                final, json.loads(pending_path.read_text()), "committed candidate receipt"
            )
            if not verified or candidate_state(candidate) != after:
                raise ContractError("candidate commit failed final verification")
            fully_committed = True
            settled = (
                state
                / "settled-pending-commits"
                / stage["stage_id"]
                / identity
                / body["receipt_sha256"]
            )
            if settled.exists():
                raise ContractError("conflicting settled pending-commit archive exists")
            settled.parent.mkdir(parents=True, exist_ok=True)
            os.replace(control, settled)
            shutil.rmtree(settled)
        return body
    except BaseException:
        # Once the commitment is durable, recovery owns both candidate and result
        # replacement. Do not split the transaction from this generic error path.
        if pending_path is not None:
            preserve_control = True
            raise
        if fully_committed:
            preserve_control = True
            raise
        recovery = {"candidate_before": before if "before" in locals() else None}
        changed = False
        if "before" in locals():
            try:
                changed = candidate_state(candidate) != before
            except ContractError:
                changed = True
        if changed:
            try:
                recovery["candidate_restored"] = restore_candidate(
                    candidate, before, backup
                )
                recovery["result"] = "RESTORED"
            except BaseException as error:
                recovery["result"] = "QUARANTINED"
                recovery["error"] = str(error)
                if backup.exists():
                    recovery.update(
                        {
                            "recovery_backup": str(backup),
                            "recovery_backup_sha256": file_hash(backup),
                        }
                    )
                    preserve_control = True
                atomic_json(quarantine, recovery)
        failed = state / "failed-stages" / stage["stage_id"] / identity
        if not failed.exists():
            failed.parent.mkdir(parents=True, exist_ok=True)
            os.replace(temp, failed)
        if pending_path and pending_path.exists():
            shutil.copy2(pending_path, failed / "pending-commit.json")
        if recovery.get("result"):
            atomic_json(failed / "candidate-recovery.json", recovery)
        raise
    finally:
        if lock_descriptor:
            lock_descriptor.close()
        if temp.exists():
            shutil.rmtree(temp)
        if control.exists() and not preserve_control:
            shutil.rmtree(control)


def run(args: argparse.Namespace) -> dict:
    candidate = Path(args.candidate).resolve()
    policy_only = bool(getattr(args, "policy_only", False))
    correction_path = getattr(args, "technical_state_correction", None)
    approval_path = getattr(args, "technical_state_approval", None)
    correction_mode = bool(correction_path or approval_path)
    adjudication_path = getattr(args, "technical_adjudication", None)
    adjudication_approval = getattr(args, "technical_adjudication_approval", None)
    adjudication_mode = bool(adjudication_path or adjudication_approval)
    selector_files = [
        material_file(Path.cwd(), x, "selector")
        for x in (
            []
            if policy_only or correction_mode or adjudication_mode
            else args.ticket_selector + args.confluence_selector
        )
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
    refresh_path = getattr(args, "policy_refresh_bundle", None)
    if adjudication_mode and (not adjudication_path or not adjudication_approval):
        raise ContractError(
            "technical adjudication requires adjudication and approval artifacts"
        )
    if adjudication_mode and (
        correction_mode or policy_only or refresh_path or args.credential_env
    ):
        raise ContractError(
            "technical adjudication is a separate credential-free execution mode"
        )
    if correction_mode and (not correction_path or not approval_path):
        raise ContractError("technical-state correction requires correction and approval artifacts")
    if correction_mode and (policy_only or refresh_path or args.credential_env):
        raise ContractError("technical-state correction is a separate credential-free execution mode")
    if policy_only and not refresh_path:
        raise ContractError("policy-only execution requires an isolated refresh bundle")
    if refresh_path and not policy_only:
        raise ContractError("policy refresh promotion requires policy-only execution")
    if policy_only and args.credential_env:
        raise ContractError("policy-only execution cannot receive credentials")
    refresh = (
        policy_refresh_bundle(Path(refresh_path), profile["project"]["project_id"])
        if refresh_path
        else None
    )
    selectors = {
        "tickets": selector_files[: len(args.ticket_selector)]
        if not policy_only
        else [],
        "confluence": selector_files[len(args.ticket_selector) :]
        if not policy_only
        else [],
    }
    if refresh:
        selectors["policy_refresh"] = [
            {
                "locator": refresh["locator"],
                "sha256": refresh["sha256"],
                "sources": [
                    {
                        "source_kind": item["source_kind"],
                        "retrieval_status": item["retrieval_status"],
                        "collection_scope": item["collection_scope"],
                        "evidence_sha256": item["evidence"]["sha256"],
                        "retrieved_at": item.get("retrieved_at"),
                        "expires_at": item.get("expires_at"),
                    }
                    for item in refresh["sources"]
                ],
            }
        ]
    stages = {x["stage_id"]: x for x in profile["automation"]["stages"]}
    try:
        technical_state_correction.recover(
            state, candidate, profile_identity, candidate_state, restore_candidate,
            technical_candidate_lineage,
        )
    except technical_state_correction.CorrectionError as error:
        raise ContractError(str(error)) from error
    try:
        technical_adjudication.recover(
            state,
            candidate,
            candidate_state,
            checkouts,
            {
                item["component_id"]: item["revision"]
                for item in profile["project"].get("components", [])
            },
        )
    except technical_adjudication.AdjudicationError as error:
        raise ContractError(str(error)) from error
    recover_pending_commits(state, candidate, profile, profile_identity)
    current_technical_inputs = technical_input_lineage(
        profile, Path(profile_identity["locator"]).parent
    )
    if adjudication_mode:
        workflow_path = regular(state / "workflow.json", "existing full workflow")
        prior_workflow = json.loads(workflow_path.read_text())
        prior_workflow["_locator"] = str(workflow_path)
        if prior_workflow.get("profile_sha256") != profile_identity["sha256"]:
            raise ContractError("technical adjudication changed the campaign profile")
        prior_hashes = prior_workflow.get("stages", {})
        if set(prior_hashes) != set(stages):
            raise ContractError(
                "technical adjudication lacks complete predecessor stage closure"
            )
        prior_receipts = {
            key: completed_receipt(state, key, prior_hashes[key])
            for key in sorted(stages)
        }
        if prior_workflow.get("technical_state_transition") and not prior_workflow.get(
            "technical_adjudication_transition"
        ):
            try:
                technical_state_correction.verify_transition(
                    state,
                    candidate,
                    profile,
                    profile_identity,
                    prior_workflow,
                    prior_receipts,
                    current_technical_inputs,
                    technical_candidate_lineage,
                )
            except technical_state_correction.CorrectionError as error:
                raise ContractError(str(error)) from error
        try:
            return technical_adjudication.apply_with_lock(
                adjudication_path=Path(adjudication_path),
                approval_path=Path(adjudication_approval),
                project_id=profile["project"]["project_id"],
                project=Path(profile_identity["locator"]).parent,
                state=state,
                candidate=candidate,
                profile=profile,
                profile_identity=profile_identity,
                prior_workflow=prior_workflow,
                receipts=prior_receipts,
                current_technical_inputs=current_technical_inputs,
                technical_lineage=technical_candidate_lineage,
                candidate_state=candidate_state,
                source_checkouts=checkouts,
                source_revisions={
                    item["component_id"]: item["revision"]
                    for item in profile["project"].get("components", [])
                },
            )
        except technical_adjudication.AdjudicationError as error:
            raise ContractError(str(error)) from error
    if correction_mode:
        workflow_path = regular(state / "workflow.json", "existing full workflow")
        prior_workflow = json.loads(workflow_path.read_text())
        prior_workflow["_locator"] = str(workflow_path)
        if prior_workflow.get("profile_sha256") != profile_identity["sha256"]:
            raise ContractError("technical-state correction changed the campaign profile")
        prior_hashes = prior_workflow.get("stages", {})
        if set(prior_hashes) != set(stages):
            raise ContractError("technical-state correction lacks complete stage closure")
        prior_receipts = {
            key: completed_receipt(state, key, prior_hashes[key]) for key in sorted(stages)
        }
        project = Path(profile_identity["locator"]).parent
        if not policy_state_is_current(candidate, project, required=True):
            raise ContractError("technical-state correction requires current verified policy evidence")
        try:
            return technical_state_correction.apply_with_lock(
                correction_path=Path(correction_path),
                approval_path=Path(approval_path),
                project_id=profile["project"]["project_id"],
                project=project,
                state=state,
                candidate=candidate,
                profile=profile,
                profile_identity=profile_identity,
                prior_workflow=prior_workflow,
                receipts=prior_receipts,
                current_technical_inputs=current_technical_inputs,
                technical_lineage=technical_candidate_lineage,
                candidate_state=candidate_state,
            )
        except technical_state_correction.CorrectionError as error:
            raise ContractError(str(error)) from error
    if policy_only:
        workflow_path = regular(state / "workflow.json", "existing full workflow")
        prior_workflow = json.loads(workflow_path.read_text())
        if prior_workflow.get("profile_sha256") != profile_identity["sha256"]:
            raise ContractError("policy-only refresh changed the campaign profile")
        prior_stage_hashes = prior_workflow.get("stages", {})
        if set(prior_stage_hashes) != set(stages):
            raise ContractError(
                "policy-only refresh lacks complete prior stage closure"
            )
        prior_receipts = {
            key: completed_receipt(state, key, prior_stage_hashes[key])
            for key in sorted(stages)
        }
        policy_only_technical_admission(
            profile,
            profile_identity,
            prior_workflow,
            state,
            candidate,
            prior_receipts,
            current_technical_inputs,
            verified_policy_replacement=refresh,
            source_checkouts=checkouts,
        )
        selected = {
            key for key, stage in stages.items() if stage["phase"] in POLICY_ONLY_PHASES
        }
        completed = {key: prior_receipts[key] for key in sorted(set(stages) - selected)}
        pending = {key: {**stages[key], "credential_env": []} for key in selected}
    else:
        prior_workflow = None
        pending = dict(stages)
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
        "technical_candidate_lineage_sha256": technical_candidate_lineage(candidate),
        "technical_input_lineage_sha256": current_technical_inputs,
        "technical_lineage_version": TECHNICAL_LINEAGE_VERSION,
        "execution_mode": "POLICY_ONLY" if policy_only else "FULL",
        "provider_phase_dispatches_permitted": 0
        if policy_only
        else sum(stage["phase"] in METIS_PROVIDER_PHASES for stage in stages.values()),
    }
    if prior_workflow:
        final["base_workflow_sha256"] = prior_workflow["workflow_sha256"]
        if prior_workflow.get("technical_state_transition"):
            final["technical_state_transition"] = prior_workflow["technical_state_transition"]
        if prior_workflow.get("technical_adjudication_transition"):
            final["technical_adjudication_transition"] = prior_workflow[
                "technical_adjudication_transition"
            ]
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
    p.add_argument("--policy-only", action="store_true")
    p.add_argument("--policy-refresh-bundle", type=Path)
    p.add_argument("--technical-state-correction", type=Path)
    p.add_argument("--technical-state-approval", type=Path)
    p.add_argument("--technical-adjudication", type=Path)
    p.add_argument("--technical-adjudication-approval", type=Path)
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
