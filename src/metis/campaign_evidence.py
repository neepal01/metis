# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
from collections.abc import Mapping
from concurrent.futures import CancelledError
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any
from typing import Literal
from typing import Protocol

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import model_validator

CampaignQueryOperation = Literal[
    "prior_record",
    "root_fingerprint_variants",
    "tickets_conclusions_pocs",
    "project_findings_reproducers",
    "five_layer_dedup",
    "evidence_context_capsule",
    "call_paths",
    "build_graph_identity",
    "reproduction_reopen",
]
CampaignQueryStatus = Literal[
    "HIT", "MISS", "IDENTITY_REJECTED", "STALE", "INCOMPLETE", "UNAVAILABLE"
]
GraphEdgeAuthority = Literal[
    "CANDIDATE_STATIC",
    "SOURCE_CONFIRMED",
    "RUNTIME_CONFIRMED",
    "UNRESOLVED",
    "STALE",
    "REJECTED",
]


class CampaignEvidenceError(ValueError):
    """A campaign evidence boundary failed closed."""


class CampaignQueryLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_results: int = Field(default=20, ge=1, le=100)
    max_response_bytes: int = Field(default=64_000, ge=1, le=1_000_000)
    max_packet_bytes: int = Field(default=128_000, ge=1, le=2_000_000)
    max_database_bytes: int = Field(default=500_000_000, ge=1)
    adapter_timeout_seconds: int = Field(default=10, ge=1, le=60)
    max_worker_jobs: int = Field(default=10, ge=1, le=100)


class CampaignBuildGraph(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    build_id: str = Field(min_length=1)
    component_revisions: dict[str, str]
    platform: str = Field(min_length=1)
    image: str = Field(min_length=1)
    configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    toolchain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_locator: str | None = None
    graph_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    graph_status: GraphEdgeAuthority = "UNRESOLVED"

    @model_validator(mode="after")
    def require_complete_graph_reference(self) -> CampaignBuildGraph:
        if (self.graph_locator is None) != (self.graph_sha256 is None):
            raise ValueError("graph locator and graph hash must appear together")
        return self


class CampaignEvidenceProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal["metis-campaign-evidence-v1"]
    project_id: str = Field(min_length=1)
    schema_contract_version: str = Field(min_length=1)
    campaign_generation: str = Field(min_length=1)
    candidate_database: str = Field(min_length=1)
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    component_revisions: dict[str, str]
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    threat_model_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    historical_tickets_pocs_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    current_tickets_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    build_graph_registry: tuple[CampaignBuildGraph, ...]
    adapter_argv: tuple[str, ...]
    fallback_action: str = Field(min_length=1)
    limits: CampaignQueryLimits = Field(default_factory=CampaignQueryLimits)

    @model_validator(mode="after")
    def require_identity_and_adapter(self) -> CampaignEvidenceProfile:
        if not self.component_revisions or any(
            not key or not value for key, value in self.component_revisions.items()
        ):
            raise ValueError("component revisions cannot be empty")
        if not self.build_graph_registry:
            raise ValueError("build/graph registry cannot be empty")
        if not self.adapter_argv or any(not value for value in self.adapter_argv):
            raise ValueError("adapter argv cannot be empty")
        return self


class CampaignEvidenceConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: str = Field(min_length=1)
    packet_output: str | None = None


class CampaignEvidenceQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: CampaignQueryOperation
    identity: str | None = Field(default=None, max_length=1024)
    query: str | None = Field(default=None, max_length=4096)
    limit: int | None = Field(default=None, ge=1, le=100)


class CampaignGraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    caller: str = Field(min_length=1)
    callee: str = Field(min_length=1)
    authority: GraphEdgeAuthority
    evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_for_proof: bool = False

    @model_validator(mode="after")
    def protect_reachability(self) -> CampaignGraphEdge:
        if self.required_for_proof and self.authority not in {
            "SOURCE_CONFIRMED",
            "RUNTIME_CONFIRMED",
        }:
            raise ValueError("candidate or unresolved edge cannot prove reachability")
        return self


class CampaignFindingPacket(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal["metis-firmware-finding-v1"]
    record_id: str = Field(pattern=r"^metis:[0-9a-f]{32}$")
    external_id: str = Field(min_length=1)
    source_kind: str = Field(min_length=1)
    source_locator: str = Field(min_length=1)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_id: str = Field(min_length=1)
    component_id: str = Field(min_length=1)
    component_revision: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    image: str = Field(min_length=1)
    configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    schema_contract_version: str = Field(min_length=1)
    campaign_generation: str = Field(min_length=1)
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dependency_hashes: dict[str, str]
    build_graph_registry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    finding: dict[str, Any]
    metis_status: Literal["valid", "invalid", "inconclusive"]
    evidence_lookup_status: CampaignQueryStatus
    evidence_query_content_hashes: tuple[str, ...] = Field(min_length=1)
    graph_edges: tuple[CampaignGraphEdge, ...] = ()
    campaign_route: Literal["SEALED_CONTEXT", "NEW_ANALYSIS"]
    technical_class: Literal["DEFERRED"] = "DEFERRED"
    exact_source_validation_complete: Literal[False] = False
    creates_root: Literal[False] = False
    fp_no_bug_authorized: Literal[False] = False
    candidate_authorizes_governed_state: Literal[False] = False

    @model_validator(mode="after")
    def enforce_miss_and_status_limits(self) -> CampaignFindingPacket:
        if set(self.dependency_hashes) != {
            "policy",
            "threat_model",
            "historical_tickets_pocs",
            "current_tickets",
        } or any(
            len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in self.dependency_hashes.values()
        ):
            raise ValueError("finding dependency hashes are incomplete")
        expected_record_id = _finding_record_id(
            self.source_kind,
            self.external_id,
            self.source_locator,
            self.source_sha256,
            self.repository_id,
            self.component_id,
            self.component_revision,
            self.platform,
            self.image,
            self.configuration_sha256,
        )
        if self.record_id != expected_record_id:
            raise ValueError("finding record identity is not deterministic")
        if any(
            len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in self.evidence_query_content_hashes
        ):
            raise ValueError("evidence query content hashes must be SHA-256 identities")
        if (
            self.evidence_lookup_status != "HIT"
            and self.campaign_route != "NEW_ANALYSIS"
        ):
            raise ValueError(
                "database miss must emit an unmapped NEW_ANALYSIS candidate"
            )
        return self


class CampaignEvidenceBackend(Protocol):
    """Thread-safe read-only backend used by the campaign evidence capability."""

    @property
    def profile(self) -> CampaignEvidenceProfile: ...

    @property
    def profile_sha256(self) -> str: ...

    def query(self, query: CampaignEvidenceQuery) -> Mapping[str, Any]: ...


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _object_sha256(value: object) -> str:
    data = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(data).hexdigest()


def _finding_record_id(
    source_kind: str,
    external_id: str,
    source_locator: str,
    source_sha256: str,
    repository_id: str,
    component_id: str,
    component_revision: str,
    platform: str,
    image: str,
    configuration_sha256: str,
) -> str:
    identity = [
        source_kind,
        external_id,
        source_locator,
        source_sha256,
        repository_id,
        component_id,
        component_revision,
        platform,
        image,
        configuration_sha256,
    ]
    return f"metis:{_object_sha256(identity)[:32]}"


@dataclass(frozen=True, slots=True)
class _ProfileState:
    path: Path
    profile_sha256: str
    database: Path


class CommandCampaignEvidenceBackend:
    """Executes a profile-selected, separately versioned campaign adapter."""

    def __init__(self, profile_path: Path | str) -> None:
        self._state = self._load_profile(Path(profile_path))
        self._validate_database()

    @property
    def profile(self) -> CampaignEvidenceProfile:
        return self._profile

    @property
    def profile_sha256(self) -> str:
        return self._state.profile_sha256

    @property
    def database(self) -> Path:
        return self._state.database

    def query(self, query: CampaignEvidenceQuery) -> Mapping[str, Any]:
        before = self._validate_database()
        limit = min(
            query.limit or self.profile.limits.max_results,
            self.profile.limits.max_results,
        )
        request = {
            "format_version": "metis-campaign-query-v1",
            "operation": query.operation,
            "identity": query.identity,
            "query": query.query,
            "limit": limit,
            "database_uri": f"file:{self.database.as_posix()}?mode=ro&immutable=1",
            "expected": {
                "project_id": self.profile.project_id,
                "schema_contract_version": self.profile.schema_contract_version,
                "campaign_generation": self.profile.campaign_generation,
                "candidate_sha256": self.profile.candidate_sha256,
                "component_revisions": self.profile.component_revisions,
                "policy_sha256": self.profile.policy_sha256,
                "threat_model_sha256": self.profile.threat_model_sha256,
                "historical_tickets_pocs_sha256": self.profile.historical_tickets_pocs_sha256,
                "current_tickets_sha256": self.profile.current_tickets_sha256,
                "build_graph_registry": [
                    item.model_dump() for item in self.profile.build_graph_registry
                ],
            },
        }
        try:
            completed = subprocess.run(
                self.profile.adapter_argv,
                input=json.dumps(request, sort_keys=True, separators=(",", ":")),
                capture_output=True,
                text=True,
                timeout=self.profile.limits.adapter_timeout_seconds,
                cwd=self._state.path.parent,
                check=False,
            )
        except CancelledError:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            raise CampaignEvidenceError(
                f"campaign adapter failed closed: {exc}"
            ) from exc
        after = self._validate_database()
        if before != after:
            raise CampaignEvidenceError("candidate changed during campaign query")
        output_size = len(completed.stdout.encode())
        if output_size > self.profile.limits.max_response_bytes:
            raise CampaignEvidenceError(
                "campaign adapter response exceeds configured limit"
            )
        if completed.returncode != 0:
            detail = completed.stderr.strip()[:500]
            raise CampaignEvidenceError(
                f"campaign adapter rejected query ({completed.returncode}): {detail}"
            )
        try:
            adapter = json.loads(completed.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise CampaignEvidenceError(
                "campaign adapter returned corrupt JSON"
            ) from exc
        if not isinstance(adapter, Mapping):
            raise CampaignEvidenceError("campaign adapter response must be an object")
        return self._envelope(query, dict(adapter), limit)

    def _envelope(
        self, query: CampaignEvidenceQuery, adapter: dict[str, Any], limit: int
    ) -> dict[str, Any]:
        required_fields = {
            "evidence_hashes",
            "fallback",
            "limitations",
            "reason",
            "result",
            "result_content_sha256",
            "status",
            "uncertainty",
            "write_attempts",
        }
        if not required_fields <= set(adapter):
            raise CampaignEvidenceError("campaign adapter response is incomplete")
        status = adapter.get("status")
        if status not in CampaignQueryStatus.__args__:
            raise CampaignEvidenceError("campaign adapter returned invalid status")
        claimed = adapter.pop("result_content_sha256", None)
        if claimed != _object_sha256(adapter):
            raise CampaignEvidenceError("campaign adapter result content hash mismatch")
        if adapter.get("write_attempts") not in (0, None):
            raise CampaignEvidenceError("campaign adapter reported a write attempt")
        result = adapter.get("result")
        if not isinstance(result, list) or len(result) > limit:
            raise CampaignEvidenceError("campaign adapter result count is invalid")
        evidence_hashes = adapter.get("evidence_hashes")
        if not isinstance(evidence_hashes, list) or any(
            not isinstance(item, str) or len(item) != 64 for item in evidence_hashes
        ):
            raise CampaignEvidenceError("campaign evidence hashes are invalid")
        if not all(
            isinstance(adapter.get(key), expected)
            for key, expected in (
                ("reason", str),
                ("fallback", str),
                ("uncertainty", list),
                ("limitations", list),
            )
        ):
            raise CampaignEvidenceError("campaign adapter context is invalid")
        result_size = len(
            json.dumps(
                result, sort_keys=True, separators=(",", ":"), default=str
            ).encode()
        )
        if result_size > self.profile.limits.max_response_bytes:
            raise CampaignEvidenceError(
                "campaign adapter result exceeds configured limit"
            )
        dependencies = {
            "policy": self.profile.policy_sha256,
            "threat_model": self.profile.threat_model_sha256,
            "historical_tickets_pocs": self.profile.historical_tickets_pocs_sha256,
            "current_tickets": self.profile.current_tickets_sha256,
        }
        envelope = {
            "query": query.operation,
            "query_version": "campaign-evidence-v1",
            "status": status,
            "project_id": self.profile.project_id,
            "schema_contract_version": self.profile.schema_contract_version,
            "candidate_database_sha256": self.profile.candidate_sha256,
            "campaign_generation": self.profile.campaign_generation,
            "component_revisions": self.profile.component_revisions,
            "dependency_hashes": dependencies,
            "build_graph_registry": [
                item.model_dump() for item in self.profile.build_graph_registry
            ],
            "identity": query.identity,
            "limit": limit,
            "result": result,
            "hit_or_rejection_reason": str(adapter.get("reason") or ""),
            "evidence_content_hashes": sorted(set(evidence_hashes)),
            "uncertainty": list(adapter.get("uncertainty") or []),
            "limitations": list(adapter.get("limitations") or []),
            "fallback_action": str(
                adapter.get("fallback") or self.profile.fallback_action
            ),
            "authority": {
                key: False
                for key in (
                    "classification",
                    "reachability",
                    "scope",
                    "severity",
                    "rca",
                    "approval",
                    "reproduction",
                    "root_promotion",
                    "governed_write",
                )
            },
            "terminal_source_reread_required": True,
            "write_attempts": 0,
            "profile_sha256": self.profile_sha256,
        }
        envelope["result_content_sha256"] = _object_sha256(envelope)
        return envelope

    def _load_profile(self, path: Path) -> _ProfileState:
        if path.is_symlink() or not path.is_file():
            raise CampaignEvidenceError("campaign profile must be a regular file")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            self._profile = CampaignEvidenceProfile.model_validate(raw)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise CampaignEvidenceError(f"campaign profile is invalid: {exc}") from exc
        database = Path(self._profile.candidate_database)
        if not database.is_absolute():
            database = path.parent / database
        return _ProfileState(path.absolute(), _sha256(path), database.absolute())

    def _validate_database(self) -> str:
        path = self._state.database
        if path.is_symlink() or not path.is_file():
            raise CampaignEvidenceError("candidate database must be a regular file")
        if path.stat().st_size > self.profile.limits.max_database_bytes:
            raise CampaignEvidenceError("candidate database exceeds configured limit")
        for suffix in ("-wal", "-journal", "-shm"):
            if Path(f"{path}{suffix}").exists():
                raise CampaignEvidenceError("unexpected mutable database sidecar")
        actual = _sha256(path)
        if actual != self.profile.candidate_sha256:
            raise CampaignEvidenceError("candidate database identity mismatch")
        try:
            connection = sqlite3.connect(
                f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True, timeout=1
            )
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise CampaignEvidenceError("candidate database quick check failed")
        except sqlite3.Error as exc:
            raise CampaignEvidenceError(
                "candidate database cannot open immutable"
            ) from exc
        finally:
            try:
                connection.close()
            except UnboundLocalError:
                pass
        return actual


class CampaignEvidenceCapability:
    def __init__(
        self, profile_path: Path | str, packet_output: Path | str | None = None
    ) -> None:
        self._backend = CommandCampaignEvidenceBackend(profile_path)
        self._packet_output = Path(packet_output).resolve() if packet_output else None
        self._lock = RLock()

    @property
    def backend(self) -> CampaignEvidenceBackend:
        return self._backend

    def lookup(
        self,
        operation: CampaignQueryOperation,
        identity: str | None = None,
        query: str | None = None,
        limit: int | None = None,
    ) -> str:
        result = self._backend.query(
            CampaignEvidenceQuery(
                operation=operation, identity=identity, query=query, limit=limit
            )
        )
        return json.dumps(result, sort_keys=True, separators=(",", ":"))

    def export_packet(
        self,
        *,
        external_id: str,
        source_kind: str,
        source_locator: str,
        source_sha256: str,
        repository_id: str,
        component_id: str,
        component_revision: str,
        platform: str,
        image: str,
        configuration_sha256: str,
        observed_at: str,
        finding: Mapping[str, Any],
        metis_status: Literal["valid", "invalid", "inconclusive"],
        evidence_lookup_status: CampaignQueryStatus,
        evidence_query_content_hashes: tuple[str, ...],
        graph_edges: tuple[CampaignGraphEdge, ...] = (),
        resume: bool = False,
    ) -> dict[str, Any]:
        if self._packet_output is None:
            raise CampaignEvidenceError("campaign packet output is not configured")
        profile = self._backend.profile
        if not any(
            component_revision == build.component_revisions.get(component_id)
            and platform == build.platform
            and image == build.image
            and configuration_sha256 == build.configuration_sha256
            for build in profile.build_graph_registry
        ):
            raise CampaignEvidenceError(
                "finding source/platform/configuration is not in the bound build registry"
            )
        record_id = _finding_record_id(
            source_kind,
            external_id,
            source_locator,
            source_sha256,
            repository_id,
            component_id,
            component_revision,
            platform,
            image,
            configuration_sha256,
        )
        packet = CampaignFindingPacket(
            format_version="metis-firmware-finding-v1",
            record_id=record_id,
            external_id=external_id,
            source_kind=source_kind,
            source_locator=source_locator,
            source_sha256=source_sha256,
            repository_id=repository_id,
            component_id=component_id,
            component_revision=component_revision,
            platform=platform,
            image=image,
            configuration_sha256=configuration_sha256,
            observed_at=observed_at,
            project_id=profile.project_id,
            schema_contract_version=profile.schema_contract_version,
            campaign_generation=profile.campaign_generation,
            candidate_sha256=profile.candidate_sha256,
            profile_sha256=self._backend.profile_sha256,
            dependency_hashes={
                "policy": profile.policy_sha256,
                "threat_model": profile.threat_model_sha256,
                "historical_tickets_pocs": profile.historical_tickets_pocs_sha256,
                "current_tickets": profile.current_tickets_sha256,
            },
            build_graph_registry_sha256=_object_sha256(
                [item.model_dump() for item in profile.build_graph_registry]
            ),
            finding=dict(finding),
            metis_status=metis_status,
            evidence_lookup_status=evidence_lookup_status,
            evidence_query_content_hashes=evidence_query_content_hashes,
            graph_edges=graph_edges,
            campaign_route=(
                "SEALED_CONTEXT" if evidence_lookup_status == "HIT" else "NEW_ANALYSIS"
            ),
        )
        body = json.loads(packet.model_dump_json())
        packet_sha256 = _object_sha256(body)
        body["packet_sha256"] = packet_sha256
        encoded = (
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n"
        ).encode()
        if len(encoded) > profile.limits.max_packet_bytes:
            raise CampaignEvidenceError("campaign packet exceeds configured limit")
        output = self._packet_output
        output.mkdir(parents=True, exist_ok=True)
        with self._lock:
            matches = sorted(output.glob(f"{record_id}.*.json"))
            if matches:
                if not resume or len(matches) != 1:
                    raise CampaignEvidenceError("duplicate or replayed campaign packet")
                existing = json.loads(matches[0].read_text(encoding="utf-8"))
                if existing != json.loads(encoded):
                    raise CampaignEvidenceError("resume packet identity mismatch")
                return existing
            target = output / f"{record_id}.{packet_sha256}.json"
            descriptor, temp_name = tempfile.mkstemp(
                dir=output, prefix=f".{record_id}.", suffix=".tmp"
            )
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp_name, target)
            except BaseException:
                try:
                    Path(temp_name).unlink(missing_ok=True)
                except OSError:
                    pass
                raise
        return body

    def close(self) -> None:
        return
