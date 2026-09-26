# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Metis CLI launcher for the profile-driven firmware campaign."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

from metis_firmware_campaign import autonomous_campaign


def _profile(path: Path) -> dict:
    resolved = path.expanduser().resolve()
    if resolved.is_symlink() or not resolved.is_file():
        raise autonomous_campaign.ContractError(
            f"firmware campaign profile must be a regular file: {resolved}"
        )
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if value.get("schema_version") not in {"5", "6", "6.2", "6.3", "6.4", "6.5", "6.6", "6.6.1", "6.7"}:
        raise autonomous_campaign.ContractError(
            "Metis firmware campaign launch requires a schema-v5/v6 profile"
        )
    project_id = value.get("project", {}).get("project_id", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", project_id):
        raise autonomous_campaign.ContractError("invalid project ID")
    if value.get("automation", {}).get("format_version") != autonomous_campaign.FORMAT:
        raise autonomous_campaign.ContractError(
            "profile lacks the reusable autonomous firmware workflow"
        )
    return value


def _origin(checkout: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(checkout), "config", "--get", "remote.origin.url"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip()


def _repository_name(value: str) -> str:
    return value.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")


def _primary_component(profile: dict, checkout: Path) -> str:
    components = profile["project"]["components"]
    configured = (
        profile.get("automation", {}).get("metis_cli", {}).get("primary_component_id")
    )
    component_ids = {item["component_id"] for item in components}
    if configured:
        if configured not in component_ids:
            raise autonomous_campaign.ContractError(
                "automation.metis_cli.primary_component_id is unknown"
            )
        return configured
    if len(components) == 1:
        return components[0]["component_id"]
    origin = _origin(checkout)
    if origin:
        matches = [
            item["component_id"]
            for item in components
            if item["repository"] == origin
            or _repository_name(item["repository"]) == _repository_name(origin)
        ]
        if len(matches) == 1:
            return matches[0]
    raise autonomous_campaign.ContractError(
        "multi-component campaign profile must set "
        "automation.metis_cli.primary_component_id"
    )


def _configured_paths(profile_path: Path, profile: dict, kind: str) -> list[str]:
    launcher = profile.get("automation", {}).get("metis_cli", {})
    values = launcher.get(kind, [])
    if not isinstance(values, list) or any(
        not isinstance(value, str) for value in values
    ):
        raise autonomous_campaign.ContractError(
            f"automation.metis_cli.{kind} must be a list of paths"
        )
    return [str((profile_path.parent / value).resolve()) for value in values]


def _project_output(project_dir: Path, value: str, label: str) -> Path:
    output = (project_dir / value).resolve()
    try:
        output.relative_to(project_dir)
    except ValueError as exc:
        raise autonomous_campaign.ContractError(
            f"{label} must remain inside the campaign project directory"
        ) from exc
    return output


def _require_outside_source(output: Path, source: Path, label: str) -> None:
    try:
        output.relative_to(source)
    except ValueError:
        return
    raise autonomous_campaign.ContractError(
        f"{label} must remain outside the primary source checkout"
    )


def launch(
    *,
    profile_path: Path,
    codebase_path: Path,
    resume: bool,
    additional_source_paths: list[str] | None = None,
) -> int:
    """Run or resume the autonomous workflow from a Metis CLI invocation."""

    try:
        expanded_profile = profile_path.expanduser()
        if expanded_profile.is_symlink():
            raise autonomous_campaign.ContractError(
                f"firmware campaign profile must not be a symlink: {expanded_profile}"
            )
        resolved_profile = expanded_profile.resolve()
        profile = _profile(resolved_profile)
        expanded_codebase = codebase_path.expanduser()
        if expanded_codebase.is_symlink():
            raise autonomous_campaign.ContractError(
                f"codebase path must not be a symlink: {expanded_codebase}"
            )
        resolved_codebase = expanded_codebase.resolve()
        if not resolved_codebase.is_dir():
            raise autonomous_campaign.ContractError(
                f"codebase path must be a regular directory: {resolved_codebase}"
            )
        project_id = profile["project"]["project_id"]
        project_dir = resolved_profile.parent
        launcher = profile.get("automation", {}).get("metis_cli", {})
        candidate = _project_output(
            project_dir,
            launcher.get("candidate", f"candidate/{project_id}.candidate.db"),
            "candidate database",
        )
        state = _project_output(
            project_dir, launcher.get("state", "automation"), "campaign state"
        )
        _require_outside_source(candidate, resolved_codebase, "candidate database")
        _require_outside_source(state, resolved_codebase, "campaign state")
        if state.exists() and any(state.iterdir()) and not resume:
            raise autonomous_campaign.ContractError(
                "existing firmware campaign state requires --resume"
            )
        primary = _primary_component(profile, resolved_codebase)
        source_paths = [f"{primary}={resolved_codebase}"]
        additional = additional_source_paths or []
        components = [value.partition("=") for value in additional]
        component_ids = [component_id for component_id, _separator, _path in components]
        if primary in component_ids or len(component_ids) != len(set(component_ids)):
            raise autonomous_campaign.ContractError(
                "source checkout component assignments must be unique"
            )
        for component_id, separator, path_value in components:
            path = Path(path_value).expanduser()
            if not separator or not component_id or path.is_symlink():
                raise autonomous_campaign.ContractError(
                    "source path must be a nonsymlink COMPONENT=PATH assignment"
                )
            _require_outside_source(candidate, path.resolve(), "candidate database")
            _require_outside_source(state, path.resolve(), "campaign state")
        source_paths.extend(additional)
        arguments = argparse.Namespace(
            project_profile=resolved_profile,
            candidate=str(candidate),
            state=str(state),
            source=[],
            source_path=source_paths,
            ticket_selector=_configured_paths(
                resolved_profile, profile, "ticket_selectors"
            ),
            confluence_selector=_configured_paths(
                resolved_profile, profile, "confluence_selectors"
            ),
            credential_env=[],
        )
        result = autonomous_campaign.run(arguments)
    except (
        autonomous_campaign.ContractError,
        OSError,
        json.JSONDecodeError,
        sqlite3.Error,
        KeyError,
        ValueError,
        BlockingIOError,
    ) as exc:
        print(
            json.dumps({"result": "FAIL", "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"result": "PASS", **result}, sort_keys=True))
    return 0
