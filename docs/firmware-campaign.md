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
`--resume`. Unchanged receipt identities are reused. Changed global profiles,
source checkouts, selectors, or candidate identities prevent reuse; changed
stage-specific adapters, inputs, or prerequisite receipts invalidate that
stage and its descendants. At most eleven read-only campaign validators run
concurrently. Candidate construction and authoritative integration are the
only serialized candidate-writer phases.

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

Default Metis behavior is unchanged when `--firmware-campaign` is absent.
