<!--
SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
SPDX-License-Identifier: Apache-2.0
-->

# Autonomous firmware campaign

`--firmware-campaign PROFILE` selects the separately owned, restart-safe
firmware campaign rather than the ordinary Metis execution graph. The profile
must use schema v6 and provide the typed collection, candidate-build, provider
health/calibration, full-scan, packet-validation, integration, reproduction,
and package/seal adapters.

```bash
export OPENAI_API_KEY=...
uv run metis \
  --firmware-campaign /path/to/project/profile.json \
  --codebase-path /path/to/project/source \
  --resume
```

The profile directory owns its candidate database and workflow receipts by
default:

```text
profile.json
candidate/<project-id>.candidate.db
automation/
```

Set `automation.metis_cli.primary_component_id` for a multi-repository profile.
Pass every other exact checkout as `--firmware-source-path COMPONENT=PATH`.
Relative ticket/Confluence selector paths can be listed under
`automation.metis_cli.ticket_selectors` and
`automation.metis_cli.confluence_selectors`. Optional `candidate` and `state`
values override the default locations relative to the profile.

The launcher inherits only credential names already declared by stage
adapters. It does not print, hash, or persist their values. External systems
are read-only by contract, with each adapter retaining its own fail-closed
test. The candidate cannot authorize programme, production, ticket, severity,
disclosure, or root state.

The campaign is fail-closed and content-addressed. Existing state requires
`--resume`. Unchanged receipt identities are reused, while current-ticket and
threat/policy collections refresh when configured per resume or at their
bounded maximum age. Changed global profiles,
source checkouts, selectors, or candidate identities prevent reuse; changed
stage-specific adapters, inputs, or prerequisite receipts invalidate that
stage and its descendants. At most eleven read-only campaign validators run
concurrently. Candidate construction, authoritative integration and declared
candidate-mutating derived stages are serialized. Adapter subprocesses inherit a small
runtime allowlist and only the credentials declared for that stage. Readers use
isolated read-only candidate copies; writers use private staged copies which are
verified before atomic promotion.

Provider-backed profiles also bind the exact Metis implementation before a
completed stage can be reused. `runtime-identity-v1.json` covers the executable
Python version, direct and installed lock-resolved dependency versions,
`pyproject.toml`, `uv.lock`, and all
runtime files under `src/metis` and `src/metis_firmware_campaign`. The
coordinator recomputes that identity before checking a receipt. Changed runtime
content invalidates the provider stage and its descendants; a stale manifest
fails closed. New profiles declare `automation.provider_execution_mode=LIVE`,
including credential-free local providers. Legacy profiles may use a
`PROFILE.provider-execution.json` sidecar bound to their exact profile hash.
`FROZEN_REPLAY` retains historical receipt identity but cannot execute a
missing or invalidated provider stage.

Provider-backed stages automatically redirect the existing per-result review
checkpoint to a durable path beneath their content-addressed stage identity.
Each SQLite commit completes before a later callback or request can run, and
an unwritable checkpoint aborts the stage. A failed stage can therefore be
restarted with `--resume` without repeating completed provider calls. Source
identity also accepts Git-tracked symlinks only when their relative targets
resolve to regular files inside the same bound checkout; the link text and
target content are both hashed.

Metis discovery remains bounty-neutral and non-authorizing. Exact-source
counterevidence is required for `NO_BUG`; a `VALID_VULNERABILITY` requires the
complete attacker-to-effect proof tuple. Missing evidence remains deferred.
The selected adapters preserve software, partial-model, platform-faithful, and
target-blocked reproduction states with positive, negative/patched, and clean
controls.

Capability 6.6 adds one serialized built-in policy-reconciliation phase. It
consumes the structured current-ticket/policy output plus preserved
reproduction state, evaluates exact-owner, component-specific, matching
historical and general rules in precedence order, and atomically updates only
programme-scope evidence. Contested current sources fail to
`UNRESOLVED/CONTESTED`; technical class, reproduction and technical severity
remain invariant. PoC prose is never a runnable-reproducer receipt.

Capability 6.6.1 is a reporting-only patch. Its read-only population-report
stage derives scanner totals exclusively from `SCANNER` imports and keeps
auxiliary subjects, all campaign subjects, and unique roots separately
reconciled.

Capability 6.8 binds current policy and ticket decisions to separately hashed
source populations and a successful, unexpired refresh lease. It records
append-only scope transitions, preserves historical decisions as
non-authorizing history, and queues only roots whose technical, deduplication
or reproduction assumptions changed. Completion, evidence currency, scope
closure and submission readiness remain separate.

An already sealed workflow can apply separately authorized, source-read-only
staging artifacts without dispatching providers:

```bash
uv run --no-sync metis \
  --firmware-campaign /path/to/project/profile.json \
  --codebase-path /path/to/project/source \
  --resume --firmware-policy-only \
  --firmware-policy-refresh /path/to/isolated/refresh.json
```

The refresh source artifacts must remain beside the bundle. In policy-only
mode the coordinator verifies every prior technical/provider receipt, removes
connector and provider credentials from child environments, and executes only
collection-to-policy/report/package/seal phases. It is an orchestration
boundary, not an OS sandbox against malicious project adapters.

Default Metis behavior is unchanged when `--firmware-campaign` is absent.

Capability control 6.9 (REVIEW) adds a distinct non-executing correction path:

```bash
uv run --no-sync metis --firmware-campaign /path/to/profile.json \
  --codebase-path /path/to/source --resume \
  --firmware-technical-state-correction /path/to/correction.json \
  --firmware-technical-state-approval /path/to/approval.json
```

It does not weaken policy-only lineage admission. It permits only the recorded
four-field `validation_run` transition and one exact unresolved queue row,
verifies current policy evidence and complete immutable provider prerequisites,
and uses the authoritative-writer lock plus exact prepared-byte recovery. The
transition commits every reopen request present at correction time. Later
policy-reconciliation queue indexes extend that commitment: requests may gain
evidence-backed resolution, but cannot silently disappear or change identity.
This does not freeze the queue count or reject legitimate additions. The
project-specific root, run and mutation belong only in the correction artifact.
A recorded human authorization is required; an artifact hash alone is not
treated as approval. Bound approval and evidence locators are absolute and
remain stable after the transition is archived. Recovery preflights every
destination, including `recovery.json`, before authoritative mutation; only an
exact record for the pending transaction is reusable. An expired predecessor
can enter only the already-verified fresh policy-refresh lane. This REVIEW
control does not authorize providers, targets, release or submission.

## Triage-only before/after benchmark

`python -m metis_firmware_campaign.triage_benchmark` compares result files from
separately authorized baseline and candidate triage runs. The case manifest must
bind each SARIF record and exact source identity to an evidence-backed expected
triage status. The harness itself never invokes a provider and rejects any input
that claims provider authorization.

This comparison measures triage quality only. It does not measure discovery
recall, code-graph coverage, reproducer quality, or whole-pipeline superiority.
Running either provider-backed side requires separate approval.
