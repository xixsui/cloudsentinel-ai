# Incident Investigation Workbench (v0.4)

CloudSentinel AI provides a **local, single-user** investigation workspace, not a hosted or authenticated SOC. The incident page works in WSL2 Ubuntu **without AWS credentials or LLM keys** once demo cases have been seeded.

## From observations to cases

```text
Prowler / Wazuh / Suricata → normalized Findings
                                 ↓
                      correlation candidate
                       explicit entity & time
                                 ↓
                  optional LLM interpretation
                                 ↓
                          Incident case
                                 ↓
                     local analyst workflow
```

`python -m mock_data.generate` seeds nine **synthetic** source findings and two candidate incident cases. Demo cases are explicitly labeled, contain no live LLM narrative and **do not indicate a compromise**. Re-running the seed or rescanning does not reset manually updated case status, assignment or resolution rationale.

## Workspace features

- Case queue: totals, status, source severity, explained risk scores, filters and case selection.
- **Evidence timeline** sorted chronologically, with source, time, severity, resource and raw event evidence.
- **ATT&CK technique candidates:** conservative matches for supported event types only; links to authoritative ATT&CK documentation.
- **Risk scoring:** transparent, fixed-point heuristic. It is not a probability, CVSS score, or an AI model confidence value.
- **Analyst workflow:** `New` → `Investigating` → `Resolved` / `False Positive`; reopen a closed case as `Investigating`. Legacy `Analyzed` cases remain readable. Status and assignee updates and investigation notes are recorded in a local `incident_activity` SQLite table.
- **Case report:** downloadable JSON summary with metadata, ATT&CK evidence, score factors and analyst activity. Raw evidence is intentionally excluded; IDs and comments still require careful handling.

### Supported ATT&CK evidence rules

These are three **local hardcoded rules**, not a general ATT&CK or detection-as-code engine. A match describes observed behavior rather than malicious intent.

| Detector | Evidence condition | ATT&CK technique | Tactic |
|---|---|---|---|
| Wazuh `5712` | `failed_attempts >= 10` | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | Credential Access |
| Suricata `2010937` | `ports_scanned >= 20` | [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | Discovery |
| Wazuh `80200` | `api == 'GetObject'` and `count >= 100` | [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) | Collection |

Rule IDs and counts must be checked against real detector semantics before use in a production setting. Arbitrary severities, titles, `compliance` tags, or unmatched rules **cannot** establish a mapping. Configuration exposure alone receives no ATT&CK technique.

### Fixed score explanation

`score_finding`: base score from normalized severity (`Critical=80, High=60, Medium=40, Low=20, Informational=5`), plus `+6` for a threat finding, `+8` for one supported rule-evidence match, `+8` for an explicitly true `public` / `public_access` exposure flag. Cap 100.

`score_incident`: highest *linked finding severity* base score, plus up to `+8` for additional linked observations (`+4` each), `+7` for 2+ independent source labels, `+5` when misconfiguration and threat findings co-occur, and `+4` when at least one explicit ATT&CK evidence rule matches. Cap 100. **No linked evidence ⇒ score 0.**

Suggested buckets: `85–100 Critical`, `65–84 High`, `40–64 Medium`, `20–39 Low`, `0–19 Informational`. Scores have not been statistically calibrated; do not infer percentage likelihood. Labels and weights are hypotheses for triage and should be tuned and measured against a validated labeled corpus before operational use.

## Trust and hosting limitations

- The analyst's `actor` label is **self-entered**; it does not prove a user's identity. `incident_activity` is an application-level local audit *log*, not immutable or tamper-evident storage.
- There is no login, RBAC, tenant isolation, encryption-at-rest or per-user authorization. Keep Streamlit bound to `127.0.0.1`; **do not expose it to a public network** or use it for sensitive multi-user operations.
- AI narrative is explicitly marked unverified; no autonomous remediation is performed.
- Imported telemetry and evidence can include IPs, ARNs or personal data. Review before export or external LLM use.
- The current workbench is usable without live AWS, but live Prowler / Wazuh integration remains unverified in this release.

## Offline acceptance test

```bash
cd ~/cloudsentinel-ai
source .venv/bin/activate
python -m mock_data.generate
python -m pytest -q  # if pytest is installed
CLOUDSENTINEL_DEMO=1 python -m streamlit run dashboard/app.py --server.address 127.0.0.1
```

Visit **Incident Investigation**. Review the two synthetic cases, inspect evidence, assign one to a local analyst, move it to `Investigating`, leave a note, close with a justification, reopen, export JSON, and restart Streamlit to check that changes persist.
