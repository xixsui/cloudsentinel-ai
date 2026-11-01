# CloudSentinel AI v0.5 architecture note

Primary workflow: **Prowler/AWS/OCSF → normalized misconfiguration finding → reviewed CWE/ATT&CK candidate mapping → AI/manual recommendation → engineer-managed fix → independent rescan verification**. No autonomous modification of AWS resources.

- `ai_module/posture.py`: exact check-ID rules, with conservative unknown mappings.
- `ai_module/remediation_tracker.py`: separate SQLite case/scan/audit data; does not mutate the original Prowler evidence.
- `dashboard/remediation_ui.py`: four-tab CSPM finding workbench.
- `dashboard/pages/7_Remediation_Tracker.py`: local work queue.
- `prowler_module/scanner.py`: existing FAIL ingestion plus PASS/FAIL observation tracking for revalidation.

Legacy optional Wazuh/Suricata/flow/incident modules remain, but cloud misconfiguration remediation is the primary product goal. See [CSPM verification methodology](cspm-v05.md).

---

# Architecture & trust boundaries

**Data flow:** Prowler OCSF, Wazuh OpenSearch records and S3 VPC Flow Logs each transform into the `Finding` Pydantic model. `Database` persists evidence as local SQLite records. The optional `AIAnalyzer` uses third-party provider SDKs and stores explanations/cache. Streamlit displays findings, analysis and incidents.

**Separation of responsibilities:** A collector maps telemetry to evidence; candidate selector (`ai_module/correlation.py`) chooses related records *without AI*; `AIAnalyzer` asks LLM to interpret a bounded candidate list; dashboard displays that output as analyst decision support.

**Trust boundaries:** AWS data, Wazuh event content, user-pasted paths and LLM JSON are untrusted; all of them must be validated at ingestion and presentation. API keys should remain in system Keyring or environment variables. HTTPS is required for Wazuh and certificate validation defaults on. No automated remediation or account mutations are in scope.

**Runtime boundaries:** SQLite is single-machine; Streamlit is a locally bound process. Scheduler lives in the Streamlit process; stopping the web process stops scheduled work. Scanners use credentials supplied by the host, and the user should grant only necessary read permissions.

**Next steps:** structured event provenance (scan_id, source_event_id, ingestion time), schema migration tooling, per-asset identity resolution, typed detection rules, retention policies, authentication for any eventual hosted version. See [roadmap](roadmap.md).


## Interactive UI scan path (v0.3)

`Dashboard → Cloud Connections (session-scoped STS test) → Scan Center → ScanManager (single worker) → Prowler subprocess (child-only credentials) → unique OCSF output → ProwlerScanner → SQLite → Misconfigurations / Overview`. The offline path is `Dashboard → Scan Center (demo) → synthetic Prowler-like findings → SQLite`. The offline import path is `Uploaded OCSF JSON → validated event list → ProwlerScanner.ingest_events() → SQLite`.

The legacy Settings Full Pipeline has its own server-side credential settings and is intentionally separate from the session-scoped AWS connector.


## Local investigation workflow (v0.4)

`Incident` in SQLite → `dashboard/pages/3_Correlated_Incidents.py` filterable case queue → evidence timeline and local rules in `ai_module/investigation.py` → analyst status/assignee/note update in `Database.update_incident_workflow()` → `incident_activity` append-only-by-application log. Correlation upserts no longer reset analyst triage state. See [Investigation](investigation.md) for rule coverage and trust limits.
