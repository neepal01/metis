# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest

from metis.engine.codegraph import CallSite
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphResult
from metis.engine.codegraph import FunctionNode
from metis.engine.nodes.codegraph import CodeGraphConfiguration
from metis.engine.nodes.codegraph import CodeGraphService
from metis.engine.nodes.codegraph.external_indirect import CONFIG_FORMAT
from metis.engine.nodes.codegraph.external_indirect import ExternalIndirectEvidenceError
from metis.engine.nodes.codegraph.external_indirect import apply
from metis.engine.nodes.codegraph.external_indirect import cache_identity


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _case(tmp_path, *, review_only=False, ambiguous=False):
    source = tmp_path / "source"
    source.mkdir()
    (source / "caller.c").write_text("void caller(void) { fn(1); }\n")
    (source / "target.c").write_text("void target(int x) { (void)x; }\n")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "caller.c", "target.c"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "fixture"],
        check=True,
    )
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    build = tmp_path / "build"
    build.mkdir()
    (build / "generated.c").write_text("int generated;\n")
    build_manifest = tmp_path / "build-manifest.json"
    build_manifest.write_text(json.dumps({
        "schema_version": "fixture/v1",
        "identity_sha256": "a" * 64,
        "build": {"id": "build-1", "context": {"image": "tee.elf"}},
        "source": {"commit": revision, "clean": True},
    }, sort_keys=True))
    candidate = {
        "target": {
            "id": "tool-target",
            "function": "target",
            "file": "target.c",
            "line": 1,
            "address": "0x1000",
            "representation": "source+exact-elf-symbol",
        },
        "evidence": [{"resolver": "test"}],
        "resolvers": ["test"],
        "confidence": "exact-test",
        "eligible_for_traversal": not review_only,
        "runtime_reachability": "unproven",
    }
    sites = [{
        "id": "site-1", "build_id": "build-1", "image": "tee.elf",
        "status": "candidate",
        "caller": {"definition_id": "caller-def", "file": "caller.c", "function": "caller", "line": 1, "column": 21},
        "spelling": {"file": "caller.c", "line": 1, "col": 21, "offset": 20, "tokLen": 2},
        "expansion": {"file": "caller.c", "line": 1, "col": 21, "offset": 20, "tokLen": 2},
        "expression": "fn(1)", "candidates": [candidate],
    }]
    ledger = []
    artifact = {
        "schema_version": "metis.indirect-call-evidence/v2",
        "source": {"git_commit": revision, "files_sha256": {
            "caller.c": _sha(source / "caller.c"),
            "target.c": _sha(source / "target.c"),
            "@build/generated.c": _sha(build / "generated.c"),
        }},
        "build": {"id": "build-1", "identity_sha256": "a" * 64, "image": "tee.elf", "runtime_reachability": "unproven"},
        "tools": {}, "sites": sites,
        "summary": {"generated_sites": 1, "generated_edges": 1, "traversal_eligible_edges": 0 if review_only else 1, "non_target_states": len(ledger)},
        "ledger": ledger,
    }
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(artifact, sort_keys=True))
    config = {
        "format_version": CONFIG_FORMAT, "evidence": str(evidence),
        "evidence_sha256": _sha(evidence), "source_commit": revision,
        "build_id": "build-1", "build_identity_sha256": "a" * 64,
        "build_manifest": str(build_manifest),
        "build_manifest_sha256": _sha(build_manifest),
        "image": "tee.elf", "build_root": str(build),
    }
    config_path = tmp_path / "import.json"
    config_path.write_text(json.dumps(config, sort_keys=True))
    graph = CodeGraph()
    graph.add_node(FunctionNode(
        "caller-id", "caller.c", "caller", 1, end_line=1,
        calls=["fn"], call_sites=[CallSite("fn", 1, 1, kind="indirect", start_byte=20, end_byte=25)],
    ))
    graph.add_node(FunctionNode("target-id", "target.c", "target", 1, end_line=1))
    if ambiguous:
        graph.add_node(FunctionNode("target-id-2", "target.c", "target", 1, end_line=1))
    return source, build, config_path, graph


def test_exact_build_json_adds_candidate_static_navigation(tmp_path):
    source, _build, config, graph = _case(tmp_path)
    progress = []
    diagnostics = apply(graph, config_path=str(config), codebase_path=str(source), progress_callback=progress.append)
    call = graph.nodes["caller-id"].call_sites[0]
    assert graph.nodes["caller-id"].resolved_calls == ["target-id"]
    assert call.target_ids == ("target-id",)
    assert call.authoritative_target_ids == ()
    assert call.targets_complete is False
    assert call.external_target_evidence[0].authority == "CANDIDATE_STATIC"
    assert call.external_target_evidence[0].runtime_reachability == "unproven"
    assert progress[0]["admitted_candidates"] == 1
    assert progress[0]["mapping_rejections"] == 0
    assert diagnostics[-1].code == "codegraph.external_indirect_receipt"
    assert cache_identity(str(config), str(source))["authority"] == "CANDIDATE_STATIC"
    apply(graph, config_path=str(config), codebase_path=str(source))
    assert len(graph.nodes["caller-id"].call_sites[0].external_target_evidence) == 1


@pytest.mark.parametrize("mutation", ["source", "generated", "artifact_sha", "commit"])
def test_exact_identity_changes_fail_closed(tmp_path, mutation):
    source, build, config_path, graph = _case(tmp_path)
    if mutation == "source":
        (source / "caller.c").write_text("void caller(void) { fn(2); }\n")
    elif mutation == "generated":
        (build / "generated.c").write_text("int changed;\n")
    else:
        config = json.loads(config_path.read_text())
        config["evidence_sha256" if mutation == "artifact_sha" else "source_commit"] = "b" * 64
        config_path.write_text(json.dumps(config, sort_keys=True))
    with pytest.raises(ExternalIndirectEvidenceError):
        apply(graph, config_path=str(config_path), codebase_path=str(source))


def test_review_only_edge_remains_outside_navigation(tmp_path):
    source, _build, config, graph = _case(tmp_path, review_only=True)
    events = []
    apply(graph, config_path=str(config), codebase_path=str(source), progress_callback=events.append)
    assert graph.nodes["caller-id"].resolved_calls == []
    assert graph.nodes["caller-id"].call_sites[0].target_ids == ()
    assert events[0]["review_only_candidates"] == 1


def test_ambiguous_mapping_is_rejected_not_guessed(tmp_path):
    source, _build, config, graph = _case(tmp_path, ambiguous=True)
    events = []
    diagnostics = apply(graph, config_path=str(config), codebase_path=str(source), progress_callback=events.append)
    assert graph.nodes["caller-id"].resolved_calls == []
    assert events[0]["mapping_rejections"] == 1
    assert any(item.code == "codegraph.external_indirect_rejected" for item in diagnostics)


def test_codegraph_service_uses_and_persists_external_json(tmp_path):
    source, _build, config, source_graph = _case(tmp_path)

    class Provider:
        def build_graph(self, *, codebase_path, files, progress_callback=None):
            return CodeGraphResult(source_graph.copy(), tuple(files))

    repository = SimpleNamespace(
        get_code_files=lambda **_kwargs: ["caller.c", "target.c"],
        get_codegraph_registration=lambda _path: "fixture",
        get_language_name_for_path=lambda _path: "c",
        has_language_file_role=lambda _path, _role: False,
        analysis_source_for_path=lambda _path: None,
        profiled_source_fingerprint=None,
    )
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(source)),
        repository,
        {"fixture": lambda _context: Provider()},
        annotation_settings=CodeGraphConfiguration(
            external_indirect_call_evidence=str(config)
        ),
    )
    graph = service.load(service.materialize())
    call = graph.nodes["caller-id"].call_sites[0]
    assert call.target_ids == ("target-id",)
    assert call.external_target_evidence[0].authority == "CANDIDATE_STATIC"
