# AI Recommendation Quality Review (v0.9)

**Goal:** Surface review cues for human operators inspecting LLM remediation guidance. Do **not** claim that AI commands are safe, correct, or that an attack occurred.

## Data and trust boundaries

- Provider output is untrusted and is schema-validated with `AdvisorOutput` before storage.
- The separate `recommendation_review.py` module runs deterministic local checks on bounded output; it never executes generated commands or performs AWS mutations.
- Review entries are computed at read time for both new and existing cached recommendations; old records are preserved. They are **not** part of the model's output or the LLM cache fingerprint.
- Original scan metadata (check ID, severity, source) is kept separate from AI hypotheses and unverified operating conditions. No success or compromise probability is inferred.
- Cross-origin and server write-token enforcement remain mandatory for `PUT /api/v1/findings/{finding_id}/ai/runs/{run_id}/feedback`; this is **not** user authentication.
- Engineer feedback is recorded per AI analysis run with a bounded note; local single-operator only.

## Current heuristic patterns

| Check | Trigger | Review reminder |
|---|---|---|
| `SG_ADD_ONLY` | Security group finding with `authorize-security-group-ingress`, without a clear modification/removal step | Adding a narrow rule does not remove the existing permissive one. |
| `CLOUDTRAIL_AUTH_LOG` | AI proposes CloudTrail as evidence for SSH/RDP login/connection | CloudTrail is not host authentication or packet logs. |
| `DESTRUCTIVE_OPERATION` | Specific remove/destroy/delete command patterns | Require approvals, dependency review, backup and rollback. |
| `UNSUPPORTED_COMPROMISE` | Specific confirmed-compromise language | Prowler configuration findings are not proof of compromise. |

These patterns intentionally trade coverage for precision, but may still flag legitimate suggestions or miss unsafe ones. For example, they do **not** prove AWS CLI parameter correctness, permissions, impact, resource reachability or rollback viability.

## API shape

Existing `/api/v1/findings/{id}/ai/history` and `/ai/analyze` responses now include optional `analysis.review` with `scan_evidence`, `unverified_conditions`, `alerts`, `activity_evidence`, and a disclaimer. Old results remain readable. Writes to the feedback route require a local write token and accept `rating = helpful | needs_correction` plus up to 500 characters of note. `prompt_version` is persisted for new runs; old runs have `unknown-legacy`.

## Manual review checklist

Before an engineer applies changes, verify exact resource ownership, existing rules/policies, network paths, privileges, service dependencies, affected users, change approval, rollback plan, and independent follow-up scan. Never paste generated commands into a privileged shell without reading them and checking the current provider documentation.
