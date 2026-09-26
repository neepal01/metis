# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed exact-build import of portable indirect-call evidence."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import ExternalCallTargetEvidence

CONFIG_FORMAT = "metis.external-indirect-import/v1"
EVIDENCE_SCHEMA = "metis.indirect-call-evidence/v2"
AUTHORITY = "CANDIDATE_STATIC"
IMPORTED_EVENT = "external_indirect_evidence_imported"
_SHA = frozenset("0123456789abcdef")


class ExternalIndirectEvidenceError(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_sha(value: object, label: str) -> str:
    value = str(value or "")
    if len(value) != 64 or any(character not in _SHA for character in value):
        raise ExternalIndirectEvidenceError(f"{label} must be lowercase SHA-256")
    return value


def _regular(base: Path, value: object, label: str) -> Path:
    raw = Path(str(value or ""))
    if not raw.is_absolute():
        raw = base / raw
    if raw.is_symlink():
        raise ExternalIndirectEvidenceError(f"{label} must not be a symlink: {raw}")
    path = raw.resolve()
    if not path.is_file():
        raise ExternalIndirectEvidenceError(f"{label} must be a regular file: {path}")
    return path


def _directory(base: Path, value: object, label: str) -> Path:
    raw = Path(str(value or ""))
    if not raw.is_absolute():
        raw = base / raw
    if raw.is_symlink():
        raise ExternalIndirectEvidenceError(f"{label} must not be a symlink: {raw}")
    path = raw.resolve()
    if not path.is_dir():
        raise ExternalIndirectEvidenceError(f"{label} must be a directory: {path}")
    return path


def _mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ExternalIndirectEvidenceError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list:
    if not isinstance(value, list):
        raise ExternalIndirectEvidenceError(f"{label} must be an array")
    return value


def _exact_keys(value: dict, required: set[str], label: str) -> None:
    missing = required - set(value)
    extra = set(value) - required
    if missing or extra:
        raise ExternalIndirectEvidenceError(
            f"{label} keys differ (missing={sorted(missing)}, extra={sorted(extra)})"
        )


def _git_head(codebase: Path) -> str:
    try:
        value = subprocess.check_output(
            ["git", "-C", str(codebase), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=15,
        ).strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ExternalIndirectEvidenceError(
            "external indirect evidence requires an exact Git source checkout"
        ) from exc
    if subprocess.run(
        ["git", "-C", str(codebase), "diff", "--quiet", value, "--"],
        capture_output=True,
        check=False,
        timeout=30,
    ).returncode:
        raise ExternalIndirectEvidenceError(
            "source checkout has tracked modifications; external edges are stale"
        )
    return value


def _load(config_path: str, codebase_path: str) -> tuple[dict, dict, str, str]:
    codebase = Path(codebase_path).resolve()
    config_file = _regular(Path.cwd(), config_path, "external import configuration")
    try:
        config = _mapping(json.loads(config_file.read_text()), "external import configuration")
    except json.JSONDecodeError as exc:
        raise ExternalIndirectEvidenceError("external import configuration is not valid JSON") from exc
    _exact_keys(
        config,
        {
            "format_version", "evidence", "evidence_sha256", "source_commit",
            "build_id", "build_identity_sha256", "build_manifest",
            "build_manifest_sha256", "image", "build_root",
        },
        "external import configuration",
    )
    if config["format_version"] != CONFIG_FORMAT:
        raise ExternalIndirectEvidenceError("unsupported external import configuration version")
    evidence_file = _regular(config_file.parent, config["evidence"], "indirect evidence")
    artifact_sha = _sha256(evidence_file)
    if artifact_sha != _require_sha(config["evidence_sha256"], "evidence_sha256"):
        raise ExternalIndirectEvidenceError("indirect evidence SHA-256 mismatch")
    try:
        artifact = _mapping(json.loads(evidence_file.read_text()), "indirect evidence")
    except json.JSONDecodeError as exc:
        raise ExternalIndirectEvidenceError("indirect evidence is not valid JSON") from exc
    _exact_keys(
        artifact,
        {"schema_version", "source", "build", "tools", "sites", "summary", "ledger"},
        "indirect evidence",
    )
    if artifact["schema_version"] != EVIDENCE_SCHEMA:
        raise ExternalIndirectEvidenceError("unsupported indirect evidence schema")
    source = _mapping(artifact["source"], "source identity")
    _exact_keys(source, {"git_commit", "files_sha256"}, "source identity")
    build = _mapping(artifact["build"], "build identity")
    _exact_keys(build, {"id", "identity_sha256", "image", "runtime_reachability"}, "build identity")
    if any(
        artifact_value != config_value
        for artifact_value, config_value in (
            (source["git_commit"], config["source_commit"]),
            (build["id"], config["build_id"]),
            (build["identity_sha256"], config["build_identity_sha256"]),
            (build["image"], config["image"]),
        )
    ):
        raise ExternalIndirectEvidenceError("configured source/build identity does not match the artifact")
    _require_sha(build["identity_sha256"], "build.identity_sha256")
    if build["runtime_reachability"] != "unproven":
        raise ExternalIndirectEvidenceError("portable static evidence must remain runtime-unproven")
    if _git_head(codebase) != source["git_commit"]:
        raise ExternalIndirectEvidenceError("source revision mismatch; indirect evidence is stale")
    manifest_file = _regular(config_file.parent, config["build_manifest"], "exact build manifest")
    if _sha256(manifest_file) != _require_sha(config["build_manifest_sha256"], "build_manifest_sha256"):
        raise ExternalIndirectEvidenceError("build manifest SHA-256 mismatch")
    try:
        manifest = _mapping(json.loads(manifest_file.read_text()), "exact build manifest")
    except json.JSONDecodeError as exc:
        raise ExternalIndirectEvidenceError("exact build manifest is not valid JSON") from exc
    manifest_build = _mapping(manifest.get("build"), "build manifest build")
    manifest_source = _mapping(manifest.get("source"), "build manifest source")
    if any(
        observed != expected
        for observed, expected in (
            (manifest.get("identity_sha256"), config["build_identity_sha256"]),
            (manifest_build.get("id"), config["build_id"]),
            (_mapping(manifest_build.get("context"), "build context").get("image"), config["image"]),
            (manifest_source.get("commit"), config["source_commit"]),
            (manifest_source.get("clean"), True),
        )
    ):
        raise ExternalIndirectEvidenceError("build manifest identity does not match the import")
    build_root = _directory(config_file.parent, config["build_root"], "exact build root")
    files = _mapping(source["files_sha256"], "source.files_sha256")
    if not files:
        raise ExternalIndirectEvidenceError("source identity has no file hashes")
    for name, expected in sorted(files.items()):
        name = str(name)
        expected = _require_sha(expected, f"source hash for {name}")
        root = build_root if name.startswith("@build/") else codebase
        relative = name.removeprefix("@build/")
        if not relative or os.path.isabs(relative) or ".." in Path(relative).parts:
            raise ExternalIndirectEvidenceError(f"invalid source identity path: {name}")
        path = _regular(root, relative, f"source identity file {name}")
        if _sha256(path) != expected:
            raise ExternalIndirectEvidenceError(f"source/build hash mismatch; stale edge: {name}")
    summary = _mapping(artifact["summary"], "summary")
    _exact_keys(summary, {"generated_sites", "generated_edges", "traversal_eligible_edges", "non_target_states"}, "summary")
    sites = _list(artifact["sites"], "sites")
    ledger = _list(artifact["ledger"], "ledger")
    if len(sites) != summary["generated_sites"]:
        raise ExternalIndirectEvidenceError("site count does not reconcile")
    if sum(len(_mapping(site, "site").get("candidates", [])) for site in sites) != summary["generated_edges"]:
        raise ExternalIndirectEvidenceError("candidate count does not reconcile")
    if sum(
        candidate.get("eligible_for_traversal") is True
        for site in sites
        for candidate in _list(_mapping(site, "site").get("candidates"), "site candidates")
    ) != summary["traversal_eligible_edges"]:
        raise ExternalIndirectEvidenceError("traversal-eligible count does not reconcile")
    if len(ledger) != summary["non_target_states"]:
        raise ExternalIndirectEvidenceError("unresolved ledger count does not reconcile")
    site_ids = [str(_mapping(site, "site").get("id") or "") for site in sites]
    if any(not site for site in site_ids) or len(site_ids) != len(set(site_ids)):
        raise ExternalIndirectEvidenceError("site IDs must be unique and non-empty")
    return config, artifact, artifact_sha, _sha256(config_file)


def cache_identity(config_path: str, codebase_path: str) -> dict[str, object]:
    config, artifact, artifact_sha, config_sha = _load(config_path, codebase_path)
    return {
        "authority": AUTHORITY,
        "config_sha256": config_sha,
        "artifact_sha256": artifact_sha,
        "source_commit": config["source_commit"],
        "build_id": config["build_id"],
        "build_identity_sha256": config["build_identity_sha256"],
        "build_manifest_sha256": config["build_manifest_sha256"],
        "image": config["image"],
        "runtime_reachability": artifact["build"]["runtime_reachability"],
    }


def _normalized(path: object) -> str:
    return os.path.normpath(str(path or "")).replace("\\", "/")


def _node_for(graph: CodeGraph, file_path: str, function: str, line: int):
    matches = [
        node for node in graph.nodes.values()
        if _normalized(node.file_path) == _normalized(file_path)
        and node.name == function
        and node.line_number <= line <= (node.end_line or node.line_number)
    ]
    return matches[0] if len(matches) == 1 else None


def _call_for(node, site: dict):
    matches = []
    expression = str(site.get("expression") or "")
    for location_name in ("expansion", "spelling"):
        location = _mapping(site.get(location_name), f"{location_name} location")
        if _normalized(location.get("file")) != _normalized(node.file_path):
            continue
        line = int(location.get("line") or 0)
        offset = int(location.get("offset") or -1)
        by_span = [
            call for call in node.call_sites
            if call.kind in {"direct", "member", "indirect"}
            and call.symbol in expression
            and call.line == line
            and call.start_byte <= offset < max(call.end_byte, call.start_byte + 1)
        ]
        if len(by_span) == 1:
            matches.extend(by_span)
            continue
        by_line = [
            call for call in node.call_sites
            if call.kind in {"direct", "member", "indirect"}
            and call.symbol in expression
            and call.line == line
        ]
        if len(by_line) == 1:
            matches.extend(by_line)
    matches = list({(call.line, call.start_byte, call.end_byte, call.symbol): call for call in matches}.values())
    return matches[0] if len(matches) == 1 else None


def apply(
    graph: CodeGraph,
    *,
    config_path: str,
    codebase_path: str,
    progress_callback: Callable[[dict[str, object]], None] | None = None,
) -> tuple[CodeGraphDiagnostic, ...]:
    config, artifact, artifact_sha, config_sha = _load(config_path, codebase_path)
    admitted = already_present = review_only = rejected = unresolved = inventory_failures = 0
    unique_edges: set[tuple[str, str]] = set()
    diagnostics: list[CodeGraphDiagnostic] = []

    def reject(site: dict, reason: str, *, candidate: dict | None = None) -> None:
        nonlocal rejected
        rejected += 1
        target = (candidate or {}).get("target", {})
        diagnostics.append(
            CodeGraphDiagnostic(
                file_path=str(_mapping(site.get("caller"), "caller").get("file") or ""),
                line=int(_mapping(site.get("caller"), "caller").get("line") or 1),
                severity="warning",
                code="codegraph.external_indirect_rejected",
                message=(
                    f"external indirect {site.get('id')} target "
                    f"{_mapping(target, 'target').get('function', '<none>')} rejected: {reason}"
                ),
            )
        )

    for site in artifact["sites"]:
        site = _mapping(site, "site")
        if site.get("build_id") != config["build_id"] or site.get("image") != config["image"]:
            raise ExternalIndirectEvidenceError("site build identity mismatch")
        caller = _mapping(site.get("caller"), "caller")
        if set(caller) != {"definition_id", "file", "function", "line", "column"}:
            raise ExternalIndirectEvidenceError("caller schema mismatch")
        caller_node = _node_for(graph, str(caller["file"]), str(caller["function"]), int(caller["line"]))
        call = _call_for(caller_node, site) if caller_node is not None else None
        candidates = _list(site.get("candidates"), "site candidates")
        if not candidates:
            if site.get("status") == "unresolved":
                unresolved += 1
            elif site.get("status") == "parser-indexer-mapping-failure":
                inventory_failures += 1
            else:
                raise ExternalIndirectEvidenceError("candidate-free site has an unknown disposition")
        for candidate in candidates:
            candidate = _mapping(candidate, "candidate")
            required = {"target", "evidence", "resolvers", "confidence", "eligible_for_traversal", "runtime_reachability"}
            if set(candidate) != required:
                raise ExternalIndirectEvidenceError("candidate schema mismatch")
            if candidate["eligible_for_traversal"] is not True:
                review_only += 1
                continue
            target = _mapping(candidate["target"], "target")
            if set(target) != {"id", "function", "file", "line", "address", "representation"}:
                raise ExternalIndirectEvidenceError("target schema mismatch")
            if candidate["runtime_reachability"] != "unproven" or target["representation"] != "source+exact-elf-symbol":
                raise ExternalIndirectEvidenceError("eligible edge has invalid authority or representation")
            if caller_node is None:
                reject(site, "caller function did not map uniquely", candidate=candidate)
                continue
            if call is None:
                reject(site, "callsite did not map uniquely at the exact coordinate", candidate=candidate)
                continue
            target_node = _node_for(graph, str(target["file"]), str(target["function"]), int(target["line"]))
            if target_node is None:
                reject(site, "target function did not map uniquely", candidate=candidate)
                continue
            candidate_sha = hashlib.sha256(_canonical(candidate)).hexdigest()
            evidence = ExternalCallTargetEvidence(
                target_id=target_node.unique_name,
                site_id=str(site["id"]),
                artifact_sha256=artifact_sha,
                evidence_sha256=candidate_sha,
                build_id=str(config["build_id"]),
                confidence=str(candidate["confidence"]),
                resolvers=tuple(str(value) for value in _list(candidate["resolvers"], "resolvers")),
                target_preexisting=target_node.unique_name in call.target_ids,
            )
            pair = (caller_node.unique_name, target_node.unique_name)
            was_present = target_node.unique_name in call.target_ids
            evidence_identity = (evidence.site_id, evidence.target_id, evidence.evidence_sha256)
            evidence_rows = call.external_target_evidence
            if not any(
                (item.site_id, item.target_id, item.evidence_sha256) == evidence_identity
                for item in evidence_rows
            ):
                evidence_rows = (*evidence_rows, evidence)
            updated = replace(
                call,
                kind="indirect",
                target_ids=tuple(dict.fromkeys((*call.target_ids, target_node.unique_name))),
                targets_complete=False,
                external_target_evidence=evidence_rows,
            )
            caller_node.call_sites[caller_node.call_sites.index(call)] = updated
            call = updated
            caller_node.resolved_calls = list(dict.fromkeys((*caller_node.resolved_calls, target_node.unique_name)))
            unique_edges.add(pair)
            if was_present:
                already_present += 1
            else:
                admitted += 1
    event = {
        "event": IMPORTED_EVENT,
        "authority": AUTHORITY,
        "config_sha256": config_sha,
        "artifact_sha256": artifact_sha,
        "build_id": config["build_id"],
        "build_identity_sha256": config["build_identity_sha256"],
        "build_manifest_sha256": config["build_manifest_sha256"],
        "image": config["image"],
        "runtime_reachability": "unproven",
        "validated_candidate_edges": artifact["summary"]["generated_edges"],
        "traversal_eligible_candidates": artifact["summary"]["traversal_eligible_edges"],
        "admitted_candidates": admitted,
        "already_present_candidates": already_present,
        "unique_navigation_edges": len(unique_edges),
        "review_only_candidates": review_only,
        "unresolved_sites": unresolved,
        "source_inventory_mapping_failures": inventory_failures,
        "mapping_rejections": rejected,
        "unresolved_ledger_sha256": hashlib.sha256(_canonical(artifact["ledger"])).hexdigest(),
    }
    diagnostics.append(
        CodeGraphDiagnostic(
            file_path=str(config_path),
            severity="warning",
            code="codegraph.external_indirect_receipt",
            message=json.dumps(event, sort_keys=True, separators=(",", ":")),
        )
    )
    if progress_callback is not None:
        progress_callback(event)
    return tuple(diagnostics)
