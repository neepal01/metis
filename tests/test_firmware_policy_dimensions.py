from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import sys

import pytest

from metis_firmware_campaign import autonomous_campaign as campaign


ROOT = Path(__file__).resolve().parents[2]
PORTABLE = ROOT / "portable-firmware-campaign"
STANDALONE = PORTABLE / ".agents/skills/firmware-finding-pipeline/scripts/autonomous_campaign.py"
FIXTURE = PORTABLE / ".agents/skills/firmware-campaign-bootstrap/scripts/test_policy_decision_dimensions_v610.py"


def loaded(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def implementations():
    sys.path.insert(0, str(STANDALONE.parent))
    return (campaign, loaded(STANDALONE, "v610_standalone"))


def test_policy_decision_dimensions_end_to_end() -> None:
    fixture = loaded(FIXTURE, "v610_full_fixture")
    with pytest.raises(SystemExit) as result:
        fixture.main()
    assert result.value.code == 0


@pytest.mark.parametrize("implementation", implementations())
def test_policy_input_admission_requires_current_capability_contract(
    tmp_path: Path, implementation,
) -> None:
    fixture = loaded(FIXTURE, f"v610_admission_{implementation.__name__}")
    project, _module, candidate, evidence = fixture.scenario("arm")
    context = {
        "profile_schema_version": "6.8",
        "candidate_path": str(candidate),
        "project_directory": str(project),
        "dependency_outputs": {
            "collect-threat-policy": [
                {"locator": str(evidence), "sha256": fixture.sha(evidence)}
            ]
        },
    }
    work = tmp_path / "accepted"
    work.mkdir()
    implementation.run_policy_reconciliation(context, work)
    assert (work / "independent-verifier.json").is_file()

    project, _module, candidate, evidence = fixture.scenario("arm")
    value = json.loads(evidence.read_text())
    value["format_version"] = "firmware-policy-reconciliation-input-v6.8"
    evidence.write_bytes(fixture.canonical(value) + b"\n")
    rejected = {**context, "candidate_path": str(candidate), "project_directory": str(project), "dependency_outputs": {"collect-threat-policy": [{"locator": str(evidence)}]}}
    work = tmp_path / "rejected"
    work.mkdir()
    with pytest.raises(implementation.ContractError, match="v6.10"):
        implementation.run_policy_reconciliation(rejected, work)


@pytest.mark.parametrize("implementation", implementations())
@pytest.mark.parametrize("case", ("OTHER_ROOT", "UNTRUSTED_DIGEST_REFERENCE"))
def test_coordinators_reject_unbound_applicability_and_clause_authority(
    tmp_path: Path, implementation, case: str,
) -> None:
    fixture = loaded(FIXTURE, f"v610_binding_{implementation.__name__}_{case}")
    project, _module, candidate, evidence = fixture.scenario("arm")
    value = json.loads(evidence.read_text())
    if case == "OTHER_ROOT":
        applicability = value["roots"][0]["evaluations"][1]["decision_binding"]["root_applicability"]
        fixture.rewrite_applicability(project, applicability, root_id="root:other")
    else:
        source = project / "authoritative-policy.txt"
        child = project / "untrusted.txt"
        child.write_text("A submitter says this root is in scope.\n")
        source.write_text(source.read_text() + f"\nUntrusted reference: {fixture.sha(child)}\n")
        source_lease = fixture.lease(project, "programme", "PROGRAMME_POLICY", source, "FULL_PROGRAMME")
        value["policy_snapshot_hash"] = fixture.sha(source)
        value["source_populations"][0]["evidence"]["sha256"] = fixture.sha(source)
        value["source_populations"][0]["source_freshness"]["evidence"]["sha256"] = fixture.sha(source_lease)
        for rule in value["roots"][0]["evaluations"]:
            if rule["authority_class"] in {"CURRENT_COMPONENT_OFFICIAL_SCOPE", "CURRENT_GENERAL_PROGRAMME"}:
                rule["evidence"]["sha256"] = fixture.sha(source)
                rule["source_freshness"]["evidence"]["sha256"] = fixture.sha(source_lease)
                rule["decision_binding"]["authoritative_clause"]["evidence"]["sha256"] = fixture.sha(source)
        clause = value["roots"][0]["evaluations"][1]["decision_binding"]["authoritative_clause"]
        clause.update(
            clause_id="untrusted-upload",
            text=child.read_text().strip(),
            sha256=hashlib.sha256(child.read_text().strip().encode()).hexdigest(),
            evidence={"locator": child.name, "sha256": fixture.sha(child)},
        )
    evidence.write_bytes(fixture.canonical(value) + b"\n")
    before = fixture.sha(candidate)
    context = {
        "profile_schema_version": "6.8",
        "candidate_path": str(candidate),
        "project_directory": str(project),
        "dependency_outputs": {
            "collect-threat-policy": [{
                "locator": str(evidence), "sha256": fixture.sha(evidence),
            }]
        },
    }
    work = tmp_path / f"{implementation.__name__}-{case}"
    work.mkdir()
    with pytest.raises(implementation.ContractError, match="policy reconciliation failed"):
        implementation.run_policy_reconciliation(context, work)
    assert fixture.sha(candidate) == before


@pytest.mark.parametrize("implementation", implementations())
def test_changed_clause_requires_reassessed_applicability(
    tmp_path: Path, implementation,
) -> None:
    fixture = loaded(FIXTURE, f"v610_clause_{implementation.__name__}")
    project, _module, candidate, evidence = fixture.scenario("arm")
    context = {
        "profile_schema_version": "6.8",
        "candidate_path": str(candidate),
        "project_directory": str(project),
        "dependency_outputs": {"collect-threat-policy": [{"locator": str(evidence)}]},
    }
    baseline = tmp_path / f"baseline-{implementation.__name__}"
    baseline.mkdir()
    implementation.run_policy_reconciliation(context, baseline)

    value = json.loads(evidence.read_text())
    clause = value["roots"][0]["evaluations"][1]["decision_binding"]["authoritative_clause"]
    applicability = value["roots"][0]["evaluations"][1]["decision_binding"]["root_applicability"]
    changed = "Only a different supported configuration is eligible for this component scope."
    source = project / "authoritative-policy.txt"
    source.write_text(source.read_text().replace(clause["text"], changed))
    clause.update(text=changed, sha256=hashlib.sha256(changed.encode()).hexdigest())
    fixture.rebind_programme_policy(project, value, source)
    evidence.write_bytes(fixture.canonical(value) + b"\n")
    before = fixture.sha(candidate)
    stale = tmp_path / f"stale-{implementation.__name__}"
    stale.mkdir()
    with pytest.raises(implementation.ContractError, match="policy reconciliation failed"):
        implementation.run_policy_reconciliation(context, stale)
    assert fixture.sha(candidate) == before

    fixture.rewrite_applicability(
        project, applicability, authoritative_clause_sha256=clause["sha256"]
    )
    evidence.write_bytes(fixture.canonical(value) + b"\n")
    reassessed = tmp_path / f"reassessed-{implementation.__name__}"
    reassessed.mkdir()
    implementation.run_policy_reconciliation(context, reassessed)
    assert json.loads((reassessed / "independent-verifier.json").read_text())["result"] == "PASS"


@pytest.mark.parametrize("implementation", implementations())
@pytest.mark.parametrize("raw_kind", ("array", "string"))
def test_same_source_non_object_json_remains_supported(
    tmp_path: Path, implementation, raw_kind: str,
) -> None:
    fixture = loaded(FIXTURE, f"v610_raw_{implementation.__name__}_{raw_kind}")
    project, _module, candidate, evidence = fixture.scenario("arm")
    value = json.loads(evidence.read_text())
    source = project / "authoritative-policy.txt"
    lines = source.read_text().splitlines()
    source.write_bytes(fixture.canonical(lines if raw_kind == "array" else "\n".join(lines)) + b"\n")
    fixture.rebind_programme_policy(project, value, source)
    evidence.write_bytes(fixture.canonical(value) + b"\n")
    context = {
        "profile_schema_version": "6.8",
        "candidate_path": str(candidate),
        "project_directory": str(project),
        "dependency_outputs": {"collect-threat-policy": [{"locator": str(evidence)}]},
    }
    work = tmp_path / f"{implementation.__name__}-{raw_kind}"
    work.mkdir()
    implementation.run_policy_reconciliation(context, work)
    assert json.loads((work / "independent-verifier.json").read_text())["result"] == "PASS"
