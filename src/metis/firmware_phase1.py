"""Milestone-1 firmware scan, classification and reproduction-worker handoff."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import shutil
import subprocess
from tempfile import TemporaryDirectory
from typing import Any

import yaml
import pathspec


FORMAT = "metis-firmware-phase1-project-v1"
TAGS = {
    "TP_IN_SCOPE",
    "TP_OOS",
    "FP_NO_BUG",
    "HARDENING",
    "DEFERRED",
    "EMPTY_OR_FILTERED",
}
REPRODUCTIONS = {
    "PLATFORM_FAITHFUL_REPRODUCED",
    "SOFTWARE_DEFECT_REPRODUCED",
    "HARDWARE_BLOCKED",
    "UNRESOLVED",
    "NOT_APPLICABLE",
}
WORKER_RUNTIME = "gpt-5.6-cyber-xhigh-daybreak-red-env-key-v7"
FINAL_SEVERITIES = {"Critical", "High", "Medium", "Low", "None", "Unassessed"}
SEVERITY_ORDER = {name: index for index, name in enumerate(FINAL_SEVERITIES)}
SEVERITY_ORDER.update({"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
                       "None": 4, "Unassessed": 5})


class FirmwarePipelineError(ValueError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _hash_object(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _hash_file(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _augmented_worker_schema(path: Path) -> bytes:
    schema = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(schema, dict) or not isinstance(schema.get("properties"), dict):
        raise FirmwarePipelineError("worker schema is invalid")
    required = schema.get("required")
    if not isinstance(required, list):
        raise FirmwarePipelineError("worker schema required list is invalid")
    for name in ("final_severity", "severity_rationale"):
        if name not in required:
            required.append(name)
    schema["properties"]["final_severity"] = {
        "type": "string",
        "enum": sorted(FINAL_SEVERITIES),
    }
    schema["properties"]["severity_rationale"] = {
        "type": "string",
        "minLength": 1,
    }
    return _canonical(schema) + b"\n"


def _regular(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise FirmwarePipelineError(f"{label} must be a regular file: {path}")
    return path.resolve()


def _directory(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise FirmwarePipelineError(f"{label} must be a directory: {path}")
    return path.resolve()


def _relative(base: Path, value: object, label: str) -> Path:
    raw = Path(str(value or ""))
    if raw.is_absolute():
        raise FirmwarePipelineError(f"{label} must be relative to the project pack")
    path = (base / raw).resolve()
    try:
        path.relative_to(base.resolve())
    except ValueError as error:
        raise FirmwarePipelineError(f"{label} escapes the project pack") from error
    return path


def _load(path: Path) -> dict[str, Any]:
    locator = _regular(path, "firmware project config")
    value = json.loads(locator.read_text(encoding="utf-8"))
    expected = {
        "format_version",
        "project_id",
        "source",
        "source_commit",
        "metis_config",
        "custom_prompt",
        "output_directory",
        "worker_count",
        "worker_schema",
        "indirect_call_evidence",
        "scope",
        "content_hash",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise FirmwarePipelineError("firmware project config has unexpected fields")
    claimed = value.pop("content_hash")
    if claimed != _hash_object(value):
        raise FirmwarePipelineError("firmware project config content hash mismatch")
    value["content_hash"] = claimed
    value["_locator"] = locator
    if value["format_version"] != FORMAT or value["indirect_call_evidence"] != "DISABLED":
        raise FirmwarePipelineError("unsupported firmware project mode")
    if (
        not isinstance(value["worker_count"], int)
        or isinstance(value["worker_count"], bool)
        or not 1 <= value["worker_count"] <= 100
    ):
        raise FirmwarePipelineError("worker_count must be 1..100")
    scope = value["scope"]
    if not isinstance(scope, dict) or set(scope) != {"include", "exclude", "rules"}:
        raise FirmwarePipelineError("firmware scope definition is invalid")
    if not all(isinstance(scope[key], list) and all(isinstance(item, str) for item in scope[key]) for key in scope):
        raise FirmwarePipelineError("firmware scope entries must be strings")
    return value


def _git_commit(source: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def configure_cli(args):
    if args.interactive:
        raise FirmwarePipelineError("firmware project packs use non-interactive Metis")
    project = _load(Path(args.firmware_project_config))
    base = project["_locator"].parent
    source = _directory(_relative(base, project["source"], "source"), "source")
    if _git_commit(source) != project["source_commit"]:
        raise FirmwarePipelineError("source commit does not match the project pack")
    metis_config = _regular(_relative(base, project["metis_config"], "Metis config"), "Metis config")
    prompt = _regular(_relative(base, project["custom_prompt"], "custom prompt"), "custom prompt")
    schema = _regular(_relative(base, project["worker_schema"], "worker schema"), "worker schema")
    engine = yaml.safe_load(metis_config.read_text(encoding="utf-8"))
    configured = engine.get("metis_engine", {}) if isinstance(engine, dict) else {}
    if configured.get("review_code_include_paths") != project["scope"]["include"]:
        raise FirmwarePipelineError("scope include paths disagree with the Metis config")
    if configured.get("review_code_exclude_paths") != project["scope"]["exclude"]:
        raise FirmwarePipelineError("scope exclude paths disagree with the Metis config")
    # Keep each immutable project configuration in its own result generation.
    # This prevents a corrected scope pack from overwriting or consuming output
    # from an earlier, broader run.
    output = _relative(base, project["output_directory"], "output directory") / project[
        "content_hash"
    ][:12]
    output.mkdir(parents=True, exist_ok=True)
    if args.codebase_path != "." and Path(args.codebase_path).resolve() != source:
        raise FirmwarePipelineError("CLI codebase and project-pack source disagree")
    if args.config and Path(args.config).resolve() != metis_config:
        raise FirmwarePipelineError("CLI and project-pack Metis configs disagree")
    args.codebase_path = str(source)
    args.config = str(metis_config)
    args.custom_prompt = str(prompt)
    args.output_file = args.output_file or [str(output / "findings.sarif")]
    args.chroma_dir = str(output / "chromadb")
    args.project_schema = f"{project['project_id']}-{project['source_commit'][:8]}"
    args._firmware_phase1 = {**project, "_base": base, "_output": output, "_schema": schema}
    return args


def _published_sarif(paths: dict[str, list[str]]) -> Path:
    for stage in ("triage", "review"):
        for value in paths.get(stage, []):
            path = Path(value)
            if path.suffix.lower() == ".sarif":
                return _regular(path, "published Metis SARIF")
    raise FirmwarePipelineError("Metis did not publish SARIF")


def _sarif_records(path: Path) -> list[tuple[str, dict]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    records: list[tuple[str, dict]] = []
    seen = set()
    for run in payload.get("runs", []) if isinstance(payload, dict) else []:
        for result in run.get("results", []) if isinstance(run, dict) else []:
            if not isinstance(result, dict):
                continue
            properties = result.get("properties")
            finding_id = properties.get("metisFindingId") if isinstance(properties, dict) else None
            record_id = _hash_object({"metisFindingId": finding_id} if finding_id else result)
            if record_id in seen:
                raise FirmwarePipelineError(f"duplicate Metis finding identity: {record_id}")
            seen.add(record_id)
            records.append((record_id, result))
    return records


def _record_selected(project: dict, result: dict) -> bool:
    """Apply the bound project scope again when importing retained SARIF."""
    include = pathspec.GitIgnoreSpec.from_lines(
        project["scope"]["include"], backend="simple"
    )
    exclude = pathspec.GitIgnoreSpec.from_lines(
        project["scope"]["exclude"], backend="simple"
    )
    paths: list[str] = []
    for location in result.get("locations", []) if isinstance(result, dict) else []:
        try:
            uri = location["physicalLocation"]["artifactLocation"]["uri"]
        except (KeyError, TypeError):
            continue
        if not isinstance(uri, str):
            continue
        normalized = PurePosixPath(uri)
        if normalized.is_absolute() or ".." in normalized.parts:
            continue
        paths.append(str(normalized))
    return any(include.match_file(path) and not exclude.match_file(path) for path in paths)


def _artifact_evidence(base: Path, result: dict) -> None:
    evidence = result.get("artifacts")
    if not isinstance(evidence, list):
        raise FirmwarePipelineError("worker result lacks artifact evidence")
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "role"}:
            raise FirmwarePipelineError("worker artifact binding is invalid")
        path = _regular(_relative(base, item["path"], "worker artifact"), "worker artifact")
        if _hash_file(path) != item["sha256"]:
            raise FirmwarePipelineError("worker artifact hash mismatch")


def _preserve_source_artifacts(staging: Path, worktree: Path, result: Path) -> None:
    """Copy hash-bound source references out of the disposable checkout."""
    value = json.loads(_regular(result, "worker result").read_text(encoding="utf-8"))
    evidence = value.get("artifacts") if isinstance(value, dict) else None
    if not isinstance(evidence, list):
        return
    changed = False
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "role"}:
            continue
        relative = PurePosixPath(str(item["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            continue
        source_prefix = PurePosixPath(worktree.relative_to(staging).as_posix())
        try:
            source_relative = relative.relative_to(source_prefix)
        except ValueError:
            continue
        source = _regular(staging / relative, "worker source artifact")
        if _hash_file(source) != item["sha256"]:
            raise FirmwarePipelineError("worker source artifact hash mismatch")
        target_relative = PurePosixPath("evidence") / "source" / source_relative
        target = staging / target_relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if _hash_file(_regular(target, "preserved source artifact")) != item["sha256"]:
                raise FirmwarePipelineError("preserved source artifact conflicts")
        else:
            shutil.copyfile(source, target)
        item["path"] = target_relative.as_posix()
        changed = True
    if changed:
        result.write_bytes(_canonical(value) + b"\n")


def _validate_worker_result(path: Path, project: dict, record_id: str) -> dict:
    result = json.loads(_regular(path, "worker result").read_text(encoding="utf-8"))
    required = {
        "format_version",
        "project_id",
        "record_id",
        "technical_class",
        "programme_scope",
        "reproduction_level",
        "title",
        "rationale",
        "reopen_condition",
        "artifacts",
    }
    severity_fields = {"final_severity", "severity_rationale"}
    if not isinstance(result, dict) or set(result) not in {
        frozenset(required),
        frozenset(required | severity_fields),
    }:
        raise FirmwarePipelineError("worker result has unexpected fields")
    if result["format_version"] != "metis-firmware-phase1-worker-result-v1":
        raise FirmwarePipelineError("worker result version is invalid")
    if result["project_id"] != project["project_id"] or result["record_id"] != record_id:
        raise FirmwarePipelineError("worker result identity mismatch")
    tag = result["technical_class"]
    reproduction = result["reproduction_level"]
    if tag not in TAGS or reproduction not in REPRODUCTIONS:
        raise FirmwarePipelineError("worker result classification is invalid")
    if tag == "TP_IN_SCOPE" and result["programme_scope"] != "IN_SCOPE":
        raise FirmwarePipelineError("TP_IN_SCOPE requires an in-scope assessment")
    if tag == "TP_OOS" and result["programme_scope"] != "OOS":
        raise FirmwarePipelineError("TP_OOS requires an OOS assessment")
    if tag in {"FP_NO_BUG", "HARDENING", "EMPTY_OR_FILTERED"} and reproduction != "NOT_APPLICABLE":
        raise FirmwarePipelineError("non-TP result claims reproduction")
    if severity_fields.issubset(result):
        if result["final_severity"] not in FINAL_SEVERITIES:
            raise FirmwarePipelineError("worker final severity is invalid")
        if not isinstance(result["severity_rationale"], str) or not result["severity_rationale"].strip():
            raise FirmwarePipelineError("worker severity rationale is invalid")
    roles = {item.get("role") for item in result["artifacts"] if isinstance(item, dict)}
    if tag in {"TP_IN_SCOPE", "TP_OOS", "FP_NO_BUG"} and "source" not in roles:
        raise FirmwarePipelineError("decisive classification lacks hash-bound source evidence")
    if reproduction in {"PLATFORM_FAITHFUL_REPRODUCED", "SOFTWARE_DEFECT_REPRODUCED"}:
        if not {"positive", "negative_or_patched", "clean"}.issubset(roles):
            raise FirmwarePipelineError("reproduced result lacks its control triplet")
    _artifact_evidence(path.parent, result)
    return result


def _worker_prompt(project: dict, packet: Path, output: Path) -> str:
    rules = "\n".join(f"- {rule}" for rule in project["scope"]["rules"])
    return f"""Analyze and, where technically eligible, reproduce this one Metis firmware record.

Packet: {packet}
Evidence output directory: {output}

Open the packet and independently inspect the exact source. Use the legitimate production entry flow and the exact main-revision source. Do not modify the original checkout. Build only in the managed worktree. Do not use or run cppcheck. Do not treat a direct internal-function call as reproduction.

Programme search rules:
{rules}

Classify the record as exactly one of TP_IN_SCOPE, TP_OOS, FP_NO_BUG, HARDENING, DEFERRED, or EMPTY_OR_FILTERED. Keep technical validity and programme scope separate in the rationale. Attempt reproduction for every TP_IN_SCOPE record. If a faithful target is unavailable, retain TP_IN_SCOPE when technically established and use HARDWARE_BLOCKED or UNRESOLVED; never fabricate success. Successful or blocked reproduction levels belong only to TP results: FP_NO_BUG, HARDENING and EMPTY_OR_FILTERED must use NOT_APPLICABLE, while DEFERRED must use UNRESOLVED.

Set final_severity after considering the source, prerequisites, demonstrated impact, controls and reproduction outcome. This rating is independent of programme scope. A hardware-blocked issue may still be High or Critical when the boundary and impact are source-proven; a reproduced availability-only result may be Low or Medium. Use None for no qualifying security issue and Unassessed only when decisive evidence is unavailable. Explain any difference from sarif_result.properties.severity in severity_rationale.

A completed reproduction requires evidence files for a positive run, a patched/negative run and a clean control. Place evidence under the `evidence/` subdirectory of the evidence output directory. Copy every decisive source file or excerpt into `evidence/source/`; do not cite a path inside the disposable `source/` checkout as an artifact. In the final JSON, every artifact path must be relative to the evidence output directory and begin with `evidence/` (for example, `evidence/positive.log`), never absolute and never containing `..`. Return only JSON matching the supplied schema."""


def _run_one(project: dict, record: tuple[str, dict]) -> dict:
    record_id, sarif = record
    identity = _hash_object(
        {
            "project": project["content_hash"],
            "source": project["source_commit"],
            "record": sarif,
            "worker_runtime": WORKER_RUNTIME,
            "result_contract": "final-severity-v1",
        }
    )
    destination = project["_output"] / "pipeline" / "records" / record_id / identity
    result_path = destination / "result.json"
    if result_path.exists():
        return _validate_worker_result(result_path, project, record_id)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=f".{identity}.", dir=destination.parent) as temporary:
        staging = Path(temporary)
        source = _directory(project["_base"] / project["source"], "source")
        worktree = staging / "source"
        packet = {
            "format_version": "metis-firmware-phase1-record-v1",
            "project_id": project["project_id"],
            "record_id": record_id,
            "source_commit": project["source_commit"],
            "project_config_sha256": project["content_hash"],
            "sarif_result": sarif,
        }
        packet_path = staging / "packet.json"
        packet_path.write_bytes(_canonical(packet) + b"\n")
        result = staging / "result.json"
        schema = staging / "worker-result.schema.json"
        schema.write_bytes(_augmented_worker_schema(project["_schema"]))
        prepared = subprocess.run(
            [
                "git",
                "-C",
                str(source),
                "worktree",
                "add",
                "--detach",
                "--quiet",
                str(worktree),
                project["source_commit"],
            ],
            text=True,
            capture_output=True,
        )
        if prepared.returncode:
            raise FirmwarePipelineError(
                f"could not prepare isolated worker checkout: {prepared.stderr.strip()}"
            )
        command = [
            "codex",
            "exec",
            "--model",
            "gpt-5.6-cyber",
            "--config",
            'model_reasoning_effort="xhigh"',
            "--config",
            "model_providers.proxy.requires_openai_auth=false",
            "--config",
            'model_providers.proxy.env_key="OPENAI_API_KEY"',
            "--cyber-access-program",
            "daybreak_red",
            "--ephemeral",
            "--dangerously-bypass-approvals-and-sandbox",
            "--cd",
            str(worktree),
            "--add-dir",
            str(staging),
            "--output-schema",
            str(schema),
            "--output-last-message",
            str(result),
            _worker_prompt(project, packet_path, staging),
        ]
        try:
            completed = subprocess.run(command, text=True, capture_output=True)
            (staging / "worker.stdout.log").write_text(
                completed.stdout, encoding="utf-8"
            )
            (staging / "worker.stderr.log").write_text(
                completed.stderr, encoding="utf-8"
            )
            if not completed.returncode:
                _preserve_source_artifacts(staging, worktree, result)
        finally:
            removed = subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "worktree",
                    "remove",
                    "--force",
                    str(worktree),
                ],
                text=True,
                capture_output=True,
            )
            if removed.returncode:
                raise FirmwarePipelineError(
                    f"could not remove isolated worker checkout: {removed.stderr.strip()}"
                )
        if completed.returncode:
            blocker = staging / "worker.stderr.log"
            fallback = {
                "format_version": "metis-firmware-phase1-worker-result-v1",
                "project_id": project["project_id"],
                "record_id": record_id,
                "technical_class": "DEFERRED",
                "programme_scope": "UNRESOLVED",
                "reproduction_level": "UNRESOLVED",
                "title": str(
                    sarif.get("message", {}).get("text", "Metis result")
                    if isinstance(sarif.get("message"), dict)
                    else sarif.get("message", "Metis result")
                )[:500],
                "rationale": f"The downstream Codex worker exited {completed.returncode}; see its hash-bound blocker log.",
                "reopen_condition": "Resume the exact record with the declared worker/runtime.",
                "final_severity": "Unassessed",
                "severity_rationale": "Worker execution did not produce a valid assessment.",
                "artifacts": [
                    {
                        "path": blocker.name,
                        "sha256": _hash_file(blocker),
                        "role": "blocker",
                    }
                ],
            }
            result.write_bytes(_canonical(fallback) + b"\n")
        try:
            validated = _validate_worker_result(result, project, record_id)
        except FirmwarePipelineError as error:
            evidence: list[dict[str, str]] = []
            if result.is_file() and not result.is_symlink():
                rejected = staging / "worker-invalid-result.json"
                os.replace(result, rejected)
                evidence.append(
                    {
                        "path": rejected.name,
                        "sha256": _hash_file(rejected),
                        "role": "blocker",
                    }
                )
            validation_error = staging / "worker-validation-error.txt"
            validation_error.write_text(f"{error}\n", encoding="utf-8")
            evidence.append(
                {
                    "path": validation_error.name,
                    "sha256": _hash_file(validation_error),
                    "role": "blocker",
                }
            )
            fallback = {
                "format_version": "metis-firmware-phase1-worker-result-v1",
                "project_id": project["project_id"],
                "record_id": record_id,
                "technical_class": "DEFERRED",
                "programme_scope": "UNRESOLVED",
                "reproduction_level": "UNRESOLVED",
                "title": str(
                    sarif.get("message", {}).get("text", "Metis result")
                    if isinstance(sarif.get("message"), dict)
                    else sarif.get("message", "Metis result")
                )[:500],
                "rationale": "The downstream Codex worker returned a result that failed the Phase-1 evidence contract; see its hash-bound blocker evidence.",
                "reopen_condition": "Resume the exact record with the declared worker/runtime after correcting the result-contract violation.",
                "final_severity": "Unassessed",
                "severity_rationale": "Evidence validation failed before the assessment could be admitted.",
                "artifacts": evidence,
            }
            result.write_bytes(_canonical(fallback) + b"\n")
            validated = _validate_worker_result(result, project, record_id)
        os.rename(staging, destination)
        return validated


def _runtime_failure(result: dict) -> bool:
    return result["technical_class"] == "DEFERRED" and str(
        result["rationale"]
    ).startswith("The downstream Codex worker exited ")


def _severity(value: object) -> str:
    return value if isinstance(value, str) and value in FINAL_SEVERITIES else "Unassessed"


def _reproduction_display(value: str) -> str:
    if value in {"PLATFORM_FAITHFUL_REPRODUCED", "SOFTWARE_DEFECT_REPRODUCED"}:
        return "Reproduced"
    if value == "HARDWARE_BLOCKED":
        return "Blocked HW"
    return "-"


def _finding_report(project: dict, all_records: list[tuple[str, dict]], results: list[dict], filtered: set[str]) -> dict:
    result_by_id = {result["record_id"]: result for result in results}
    rows = []
    for record_id, sarif in all_records:
        properties = sarif.get("properties", {}) if isinstance(sarif.get("properties"), dict) else {}
        scanner_severity = _severity(properties.get("severity"))
        result = result_by_id.get(record_id)
        if result is None:
            if record_id not in filtered:
                raise FirmwarePipelineError("selected record is missing its result")
            result = {
                "technical_class": "EMPTY_OR_FILTERED",
                "programme_scope": "OOS",
                "reproduction_level": "NOT_APPLICABLE",
                "title": sarif.get("message", {}).get("text", "Metis result"),
                "final_severity": "None",
                "severity_rationale": "The exact project scope excluded this source before worker dispatch.",
            }
        final_severity = _severity(result.get("final_severity"))
        assessed = final_severity != "Unassessed"
        rows.append({
            "metis_id": properties.get("metisFindingId"),
            "record_id": record_id,
            "title": result["title"],
            "technical_class": result["technical_class"],
            "programme_scope": result["programme_scope"],
            "reproduction": _reproduction_display(result["reproduction_level"]),
            "metis_severity": scanner_severity,
            "final_severity": final_severity,
            "severity_changed": (final_severity != scanner_severity) if assessed else None,
            "severity_rationale": result.get("severity_rationale", "Legacy result has no independent final-severity assessment."),
        })
    rows.sort(key=lambda row: (
        min(SEVERITY_ORDER[row["metis_severity"]], SEVERITY_ORDER[row["final_severity"]]),
        row["title"],
    ))
    report = {
        "format_version": "metis-firmware-phase1-finding-report-v1",
        "project_id": project["project_id"],
        "source_commit": project["source_commit"],
        "input_sarif_sha256": project["_sarif_sha256"],
        "worker_runtime": WORKER_RUNTIME,
        "findings": rows,
    }
    report["content_hash"] = _hash_object(report)
    return report


def _write_finding_report(project: dict, report: dict) -> tuple[str, str]:
    relative_json = Path("pipeline") / f"findings-{report['content_hash']}.json"
    target_json = project["_output"] / relative_json
    target_json.parent.mkdir(parents=True, exist_ok=True)
    if not target_json.exists():
        target_json.write_bytes(_canonical(report) + b"\n")
    relative_md = relative_json.with_suffix(".md")
    target_md = project["_output"] / relative_md
    if not target_md.exists():
        lines = [
            f"# {project['project_id']} firmware findings",
            "",
            f"Total: {len(report['findings'])}",
            "",
            "| Final status | Metis ID | Finding | Metis severity | Final severity | Changed | Reproducer |",
            "|---|---|---|---|---|---|---|",
        ]
        for row in report["findings"]:
            changed = "Yes" if row["severity_changed"] is True else "No" if row["severity_changed"] is False else "Pending"
            title = str(row["title"]).replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {row['technical_class']} | `{str(row['metis_id'])[:8]}…` | {title} | {row['metis_severity']} | {row['final_severity']} | {changed} | {row['reproduction']} |"
            )
        target_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return relative_json.as_posix(), relative_md.as_posix()


def run_pipeline(args, published_paths: dict[str, list[str]]) -> None:
    project = args._firmware_phase1
    source = _directory(project["_base"] / project["source"], "source")
    if _git_commit(source) != project["source_commit"]:
        raise FirmwarePipelineError("source changed after Metis execution")
    sarif = _published_sarif(published_paths)
    project["_sarif_sha256"] = _hash_file(sarif)
    all_records = _sarif_records(sarif)
    records = [record for record in all_records if _record_selected(project, record[1])]
    filtered_ids = {record_id for record_id, _ in all_records} - {record_id for record_id, _ in records}
    filtered = len(filtered_ids)
    results: list[dict] = []
    remaining = records
    if records:
        first = _run_one(project, records[0])
        if _runtime_failure(first):
            raise FirmwarePipelineError(
                "downstream worker preflight failed; inspect its hash-bound blocker log"
            )
        results.append(first)
        remaining = records[1:]
    with ThreadPoolExecutor(max_workers=project["worker_count"]) as executor:
        results.extend(
            executor.map(lambda record: _run_one(project, record), remaining)
        )
    counts = {tag: 0 for tag in sorted(TAGS)}
    counts["EMPTY_OR_FILTERED"] = filtered
    reproductions = {status: 0 for status in sorted(REPRODUCTIONS)}
    for result in results:
        counts[result["technical_class"]] += 1
        reproductions[result["reproduction_level"]] += 1
    if sum(counts.values()) != len(all_records):
        raise FirmwarePipelineError("not every Metis record received one classification")
    finding_report = _finding_report(project, all_records, results, filtered_ids)
    report_json, report_md = _write_finding_report(project, finding_report)
    summary = {
        "format_version": "metis-firmware-phase1-summary-v2",
        "project_id": project["project_id"],
        "source_commit": project["source_commit"],
        "scanner_records": len(all_records),
        "scanner_records_selected": len(records),
        "scanner_records_scope_filtered": filtered,
        "input_sarif_sha256": project["_sarif_sha256"],
        "worker_runtime": WORKER_RUNTIME,
        "classifications": counts,
        "reproduction": reproductions,
        "indirect_call_evidence": "DISABLED",
        "cppcheck_used": False,
        "submission_ready": False,
        "finding_report": report_json,
        "finding_report_markdown": report_md,
    }
    summary["content_hash"] = _hash_object(summary)
    summary_path = project["_output"] / "pipeline" / f"summary-{summary['content_hash']}.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    if not summary_path.exists():
        summary_path.write_bytes(_canonical(summary) + b"\n")
    print(json.dumps(summary, sort_keys=True))


def run_pipeline_from_sarif(args, value: str) -> None:
    project = args._firmware_phase1
    source = _regular(
        _relative(project["_base"], value, "retained SARIF"), "retained SARIF"
    )
    run_pipeline(args, {"review": [str(source)]})
