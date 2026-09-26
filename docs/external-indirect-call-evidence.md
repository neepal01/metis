# Exact-build indirect-call evidence

Metis can use a portable indirect-call artifact as supplemental code-graph navigation. The imported edges remain `CANDIDATE_STATIC`; they never prove runtime reachability, attacker delivery, a security effect, or a terminal campaign result.

Tree-sitter first builds Metis's canonical source nodes, callsites, and direct graph. The importer then validates and overlays exact-build candidates onto those nodes. It does not replace source parsing, skip an independent inventory, or create graph nodes from analyzer-specific target IDs.

Select exactly one build artifact for each Metis run. Do not combine QEMU Armv8-A and QEMU SBSA/SEL1 evidence in one code graph. Configure the normal Metis engine:

```yaml
metis_engine:
  codegraph:
    external_indirect_call_evidence: /absolute/path/to/import.json
```

The import file is build-specific JSON:

```json
{
  "format_version": "metis.external-indirect-import/v1",
  "evidence": "/path/to/portable-evidence-v2.json",
  "evidence_sha256": "lowercase-sha256",
  "source_commit": "exact-git-commit",
  "build_id": "artifact-build-id",
  "build_identity_sha256": "artifact-build-identity-sha256",
  "build_manifest": "/path/to/build-manifest.json",
  "build_manifest_sha256": "lowercase-sha256",
  "image": "tee.elf",
  "build_root": "/path/to/exact-build-artifacts"
}
```

Relative paths resolve from the import file. `build_root` supplies files represented as `@build/...` in the portable artifact. The ordinary source checkout supplies every other source hash.

Metis rejects the import before graph reuse or processing when the configuration, artifact hash, schema, source commit, tracked worktree, build identity, runtime authority, generated file, or source-file hash is stale or inconsistent. It imports only candidates where `eligible_for_traversal=true`, `representation=source+exact-elf-symbol`, and runtime reachability remains `unproven`. Review-only candidates are retained in the artifact but excluded from traversal. Ambiguous caller, callsite, or target mappings are reported and excluded rather than guessed.

The code-graph progress stream emits `external_indirect_evidence_imported` with the config and artifact hashes, exact build identity, candidate dispositions, unresolved-ledger hash, unique navigation edges, and mapping-rejection count. Every admitted callsite carries its site, candidate, artifact, build, resolver, confidence, and `CANDIDATE_STATIC` authority metadata into bounded Metis prompt evidence.

For firmware campaigns, bind the import JSON, portable artifact, generated build tree, and graph receipt as explicit stage inputs/outputs. Run each selected build separately. The campaign integrator may use candidate edges to choose source slices, but terminal results still require exact-source verification and runtime confirmation of any decisive indirect edge.
