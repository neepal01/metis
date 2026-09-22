# Campaign evidence backend

`campaign_evidence` is an optional, non-default capability that lets Metis
workers navigate an existing firmware campaign without making campaign
decisions. It is disabled unless the operator selects the capability and
provides a hash-bound project profile.

The generic backend validates the immutable SQLite identity and delegates
project SQL to an external, versioned adapter. Metis core contains no project
paths, schemas, ticket prefixes, classifications, targets, or query SQL.
Each response identifies the project, schema, campaign generation, database,
dependencies, evidence content, limitations, uncertainty, and fallback. It
also explicitly denies classification, root creation, and governed-state
authority.

## Configure one bounded run

Add the capability to an overlay rather than to `src/metis/metis.yaml`:

```yaml
engine:
  triage:
    enabled_capabilities: [campaign_evidence]

capabilities:
  campaign_evidence:
    profile: .metis/campaign-profile.json
    packet_output: .metis/campaign-packets
```

The profile supplies the exact candidate database and its SHA-256, project and
schema identity, campaign generation, source/component revisions, policy,
threat-model, ticket and PoC hashes, content-addressed graph registry, a
versioned adapter command, and strict result/output limits. The backend rejects
symlinks, database sidecars, identity drift, failed dependency checks, corrupt
results, nonzero write attempts, or output above the profile limits.

## Authority and lifecycle

A hit is bounded pre-triage navigation evidence. A miss becomes
`NEW_ANALYSIS`, not a new root. Scanner `VALID` is only a plausible survivor;
scanner `INVALID` is not `FP_NO_BUG`. Candidate indirect edges do not establish
reachability. Every packet remains `DEFERRED`, non-authorizing, and subject to
terminal exact-source reread until the separately operated firmware pipeline
validates it.

Workers can query one frozen database concurrently but can only export one
disjoint, schema-validated packet through temporary-file plus atomic-rename.
An exact checkpoint resume can reuse the same packet identity; replay or
conflicting content is rejected. One campaign integrator validates and orders
the frozen packet population before candidate generation. It remains the sole
owner of classification, deduplication, technical roots, severity, RCA,
authorization, reproduction, accounting, and sealing.

The reference adapter and atomic staging bundle are distributed in the
separate `metis_firmware_campaign` integration package. They are outside Metis
core so other project profiles can use different schema adapters without
importing governed decisions from another firmware project.
