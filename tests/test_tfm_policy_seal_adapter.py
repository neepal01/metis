from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sqlite3

import pytest


ROOT = Path(__file__).resolve().parents[2]
ADAPTER = (
    ROOT
    / "project-campaigns/trusted-firmware-m/runs/dd00ed4-6.7.4/adapters/campaign_adapter.py"
)
POLICY_TEST = (
    ROOT
    / "portable-firmware-campaign/.agents/skills/firmware-campaign-bootstrap/scripts/test_policy_decision_controls_v68.py"
)
REPORTER = POLICY_TEST.with_name("population_scoped_reporting.py")


def module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(value)
    return value


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def inputs(tmp_path: Path):
    fixture = module("tfm_seal_fixture", POLICY_TEST)
    reconciler = fixture.load()
    candidate = tmp_path / "candidate.db"
    fixture.candidate(candidate, reconciler)
    source, lease = fixture.evidence(tmp_path)
    evidence = fixture.input_file(tmp_path, reconciler, candidate, source, lease)
    applied = fixture.run(candidate, evidence, tmp_path, tmp_path / "policy")
    assert applied.returncode == 0, applied.stderr
    reporter = module("tfm_seal_reporter", REPORTER)
    population, errors = reporter.inspect(candidate, tmp_path)
    assert not errors
    with sqlite3.connect(candidate) as database:
        filing_route = database.execute(
            "SELECT filing_route FROM policy_reconciliation WHERE root_id='root:1'"
        ).fetchone()[0]

    adapter = module("tfm_seal_adapter", ADAPTER)
    adapter.RUN = tmp_path / "adapter-run"
    write(adapter.RUN / "analysis/frontier-manifest.json", {"frontier": "fixture"})
    write(
        adapter.RUN / "bootstrap-inputs/graph-linux/export-receipt.json",
        {"graph": "fixture"},
    )
    export = tmp_path / "export"
    package = export / "IN_SCOPE/root-1"
    report = package / "README.md"
    report.parent.mkdir(parents=True)
    report.write_text("fixture report\n")
    evidence_file = package / "artifacts/evidence.json"
    write(evidence_file, {"candidate_sha256": adapter.file_hash(candidate)})
    sums = package / "artifacts/SHA256SUMS"
    sums.write_text(f"{adapter.file_hash(evidence_file)}  evidence.json\n")
    manifest = {
        "root_id": "root:1",
        "scope": "IN_SCOPE",
        "candidate_sha256": adapter.file_hash(candidate),
        "files": [
            {
                "path": "README.md",
                "sha256": adapter.file_hash(report),
                "size": report.stat().st_size,
            },
            {
                "path": "artifacts/evidence.json",
                "sha256": adapter.file_hash(evidence_file),
                "size": evidence_file.stat().st_size,
            },
            {
                "path": "artifacts/SHA256SUMS",
                "sha256": adapter.file_hash(sums),
                "size": sums.stat().st_size,
            },
        ],
        "package_state": "REPRODUCTION_BLOCKED",
        "filing_route": filing_route,
    }
    manifest["content_hash"] = adapter.object_hash(manifest)
    write(package / "PACKAGE-MANIFEST.json", manifest)
    index = {
        "format_version": "firmware-internal-package-export-v6.8",
        "profile_sha256": "p" * 64,
        "candidate_sha256": adapter.file_hash(candidate),
        "counts": {"IN_SCOPE": 1, "OOS": 0, "UNRESOLVED": 0},
        "entries": [
            {
                "root_id": "root:1",
                "scope": "IN_SCOPE",
                "locator": "IN_SCOPE/root-1",
                "content_hash": manifest["content_hash"],
                "package_state": "REPRODUCTION_BLOCKED",
                "filing_route": filing_route,
            }
        ],
    }
    index["content_hash"] = adapter.object_hash(index)
    write(export / "INDEX.json", index)
    write(tmp_path / "POPULATION-SCOPED-REPORT.json", population)
    state = tmp_path / "state"
    write(
        state / "provider-budget.json",
        {
            "requests_started": 0,
            "requests_completed": 0,
            "errors": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
        },
    )
    ctx = {
        "candidate_path": str(candidate),
        "project_directory": str(tmp_path),
        "profile_sha256": "p" * 64,
        "provider_checkpoint_root": str(
            state / "provider-results/package-seal/identity"
        ),
        "dependency_outputs": {
            "package-export": [{"locator": str(export / "INDEX.json")}],
            "population-report": [
                {"locator": str(tmp_path / "POPULATION-SCOPED-REPORT.json")}
            ],
        },
        "dependency_statuses": {
            "package-export": "COMPLETE",
            "population-report": "COMPLETE",
        },
    }
    return adapter, candidate, ctx, index


def test_actual_tfm_seal_accepts_exact_bound_artifacts(tmp_path: Path) -> None:
    adapter, candidate, ctx, _ = inputs(tmp_path)
    before = adapter.file_hash(candidate)
    output = tmp_path / "seal"
    output.mkdir()
    adapter.package_seal(ctx, output)
    receipt = json.loads((output / "final-receipts.json").read_text())
    assert receipt["status"] == "CAMPAIGN_SEAL_CURRENT"
    assert adapter.file_hash(candidate) == before


@pytest.mark.parametrize(
    "mutation",
    [
        "candidate",
        "root",
        "population",
        "truncated-population",
        "file-set",
        "empty-package",
        "filing-route",
        "empty-nested-population",
        "nested-package-manifest",
        "stale-policy-source",
    ],
)
def test_actual_tfm_seal_rejects_same_count_stale_identity(
    tmp_path: Path, mutation: str
) -> None:
    adapter, _, ctx, index = inputs(tmp_path)
    if mutation == "candidate":
        index["candidate_sha256"] = "0" * 64
    elif mutation == "root":
        index["entries"][0]["root_id"] = "different-root"
    elif mutation in {
        "file-set",
        "empty-package",
        "filing-route",
        "nested-package-manifest",
    }:
        index_path = Path(ctx["dependency_outputs"]["package-export"][0]["locator"])
        manifest_path = (
            index_path.parent / index["entries"][0]["locator"] / "PACKAGE-MANIFEST.json"
        )
        manifest = json.loads(manifest_path.read_text())
        if mutation == "empty-package":
            for item in manifest["files"]:
                (manifest_path.parent / item["path"]).unlink()
        if mutation in {"file-set", "empty-package"}:
            manifest["files"] = []
        elif mutation == "filing-route":
            changed_route = (
                "NO_ACTION"
                if manifest["filing_route"] != "NO_ACTION"
                else "NEW_REPORT_CANDIDATE"
            )
            manifest["filing_route"] = changed_route
            index["entries"][0]["filing_route"] = changed_route
        else:
            write(
                manifest_path.parent / "nested/PACKAGE-MANIFEST.json",
                {"unlisted": True},
            )
        if mutation != "nested-package-manifest":
            manifest["content_hash"] = adapter.object_hash(
                {key: value for key, value in manifest.items() if key != "content_hash"}
            )
            index["entries"][0]["content_hash"] = manifest["content_hash"]
            write(manifest_path, manifest)
    elif mutation == "stale-policy-source":
        (tmp_path / "programme-policy.json").write_text("changed source\n")
    else:
        population = json.loads(
            Path(
                ctx["dependency_outputs"]["population-report"][0]["locator"]
            ).read_text()
        )
        if mutation == "truncated-population":
            population = {
                "candidate_sha256": population["candidate_sha256"],
                "root_view": population["root_view"],
            }
        elif mutation == "empty-nested-population":
            population["completion_predicates"] = {}
            population["auxiliary_subject_view"] = {}
        else:
            population["candidate_sha256"] = "0" * 64
        population["content_hash"] = adapter.object_hash(
            {key: value for key, value in population.items() if key != "content_hash"}
        )
        write(
            Path(ctx["dependency_outputs"]["population-report"][0]["locator"]),
            population,
        )
    if mutation not in {
        "population",
        "truncated-population",
        "empty-nested-population",
    }:
        index["content_hash"] = adapter.object_hash(
            {key: value for key, value in index.items() if key != "content_hash"}
        )
        write(Path(ctx["dependency_outputs"]["package-export"][0]["locator"]), index)
    rejected = tmp_path / "rejected"
    rejected.mkdir()
    with pytest.raises(RuntimeError):
        adapter.package_seal(ctx, rejected)
