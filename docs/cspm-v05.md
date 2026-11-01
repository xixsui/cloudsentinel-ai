# CSPM v0.5 — Human-in-the-loop remediation

## Goal

CloudSentinel AI helps a cloud/security engineer find Prowler misconfigurations, understand their potential consequences, obtain AI-assisted guidance, **make cloud changes themselves**, and verify through a later independent scan. The app **never writes AWS configurations**.

## Finding detail tabs

1. **Overview & Evidence** — scanner check ID, account/region/resource, timestamp, raw evidence, source references.
2. **Weakness & ATT&CK** — locally reviewed mappings from *exact* Prowler check IDs. A weakness **category** is not a CVE. `CWE-732` is only a candidate for actual S3 public permissions and requires manual review. `T1530`, `T1021.004`, `T1021.001` are only **potential attacker techniques**, not observed behavior or probabilities. Missing preventative controls by themselves have **no** ATT&CK mapping.
3. **AI Remediation** — locally reviewed baseline guidance always visible offline. AI analysis optional and requires explicit click and user-configured provider; models can hallucinate. Do **not** automatically execute AI-generated commands.
4. **Remediation Tracking** — local single-user owner, status, notes and action history. Cases live in separate SQLite tables and do not overwrite original Prowler findings.

## Status model

```text
Open → In Progress → Pending Verification → Verified (only with newer Prowler PASS)
       └──────────────→ Accepted Risk / False Positive (requires rationale)
Verified → In Progress (explicit reopening)
```

`Verified` is **not** user-selectable. To verify, a later OCSF report must have:

- the *same stable finding ID* (Prowler `finding_info.uid`), and a `PASS` status;
- a **different** `unmapped.scan_id` from a recorded baseline FAIL for that finding;
- an event timestamp **after** the engineer's `Pending Verification` update;
- a baseline FAIL with event timestamp earlier than that new PASS.

Importing an old scan repeatedly does **not** verify remediation. Existing v0.4 imported findings predate the new scan-evidence ledger; they can be tracked now, but for automated verification a baseline FAIL must be recorded in v0.5 followed by a later independent PASS scan. You do **not** need to re-import your old report for viewing and AI guidance, only if you want it recorded in the v0.5 scan ledger.

This verification is **based on scanner-reported observations, not cryptographic attestation**. Imported OCSF files may be altered, source UID stability depends on Prowler version, and a PASS may not prove effective runtime security. An engineer should inspect the actual cloud configuration. The app does not validate AWS credentials for manually imported OCSF data.

## Optional integrations

Legacy Wazuh, VPC Flow Logs, threat alerts and Incident Investigation pages are retained for backward compatibility. They are **not required** for the CSPM workflow. Their data do not automatically become confirmed incidents in the misconfiguration detail view.

## Limitations

- **Single-user local prototype**, no authentication, RBAC or tamper-evident audit log.
- Mapping coverage is intentionally limited. For unknown checks, display category/applicability review, no invented CWE/ATT&CK/CVE.
- Security information in OCSF files, exports, SQLite and AI prompts may be sensitive. Do not commit them to public GitHub. Read provider privacy terms before sending raw evidence.
- Demo Mode never runs live AWS scans. Existing synthetic findings are labeled; keep them separate from historical Prowler data.
- A current AWS account is required to validate live scanning and remediation; no live environment was accessible during v0.5 development.

### Mapping references

- MITRE ATT&CK T1530 — https://attack.mitre.org/techniques/T1530/
- MITRE ATT&CK T1021.004 — https://attack.mitre.org/techniques/T1021/004/
- MITRE ATT&CK T1021.001 — https://attack.mitre.org/techniques/T1021/001/
- CWE-732 — https://cwe.mitre.org/data/definitions/732.html (mapping requires review)
