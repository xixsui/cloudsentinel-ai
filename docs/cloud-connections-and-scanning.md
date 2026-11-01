# Cloud Connections & Scan Center (v0.3)

This document describes the **interactive scan workflow**. This project is a **local, trusted, single-operator research prototype**: it has no application login, role-based access control, per-user storage isolation, CSRF protection for a multi-user deployment, or deployment hardening. **Never expose the Streamlit port to the public internet.**

## Offline first — no AWS account required

Run the app in offline mode:

```bash
python -m mock_data.generate
CLOUDSENTINEL_DEMO=1 streamlit run dashboard/app.py --server.address 127.0.0.1
```

Windows PowerShell:

```powershell
python -m mock_data.generate
$env:CLOUDSENTINEL_DEMO="1"
streamlit run dashboard/app.py --server.address 127.0.0.1
```

1. Open **Cloud Connections** to see why AWS calls are disabled.
2. Open **Scan Center**, choose a scan profile and services, and click **Run demo scan**.
3. The scanner imports a subset of `mock_data.generate.build_mock_findings()` filtered by the selected services. Its success is labeled **synthetic/demo**, not a Prowler result.
4. Visit **Misconfigurations** or **Overview** to investigate the generated records.
5. **Import OCSF JSON** also works offline (even in non-demo mode). You can import a local Prowler report containing a JSON array of OCSF events, or an object with a `findings`, `events`, or `results` list. Only `FAIL` status results are saved.

No AWS request, Prowler CLI, or LLM is used during the simulated scan. Every generated fixture has `raw_evidence.synthetic_demo=true`. The demo offers a UX walkthrough, *not* security-coverage or accuracy validation. If you later move to live AWS scanning, stop Streamlit and archive `data/findings.db` to another local `.db` file first, then restart Streamlit to create a clean production-test workspace. Otherwise the Overview will include mixed demo and real findings and shows a warning banner.

## Live AWS connection (optional)

**Prerequisites:** Python dependencies, AWS CLI or SDK credential configuration, optional Prowler v5 CLI (`pip install prowler`) in the same Python environment as Streamlit, and a deliberately read-only IAM identity with sufficient permissions for the checks selected. See Prowler's official AWS permissions documentation for the chosen version. Never use an AWS root key.

Recommended methods in **Cloud Connections**:

| Method | Recommended use | Credential persistence |
|---|---|---|
| AWS CLI profile / IAM Identity Center | Local workstation, AWS SSO, role profiles | Configured by AWS tooling outside this app; profile *name* in browser session |
| IAM role / default credential chain | EC2 instance role, container or environment role | Managed by runtime; no keys entered into UI |
| Temporary STS credentials | Short-lived manual demonstration | Stored in Streamlit server session memory **only**, not config/database |

**Cloud Connections** calls `sts:GetCallerIdentity` with a short timeout and displays the account and principal ARN. This only validates identity; it does **not** prove Prowler permissions. You can disconnect to discard the session-scoped credentials. All live scan jobs receive credentials through a **child-process environment**, not a global `os.environ` mutation.

**Scan Center**:

1. Requires a verified Cloud Connections identity, a detectable `prowler` executable, and non-demo mode.
2. Lets you select from explicit allowed services (`iam`, `s3`, `ec2`, `vpc`, `cloudtrail`, `rds`, `kms`, `cloudwatch`, `guardduty`, `config`), a region, and a 5–60 minute timeout.
3. Runs a **single** background Prowler process at a time using safe, list-based subprocess arguments (never `shell=True`).
4. Writes output into a unique, excluded local folder, parses Prowler JSON-OCSF, and upserts `FAIL` findings into SQLite.
5. Shows queued/running/completed/failed status in a session-scoped activity list. Refresh status to check long jobs.
6. Keeps scan reports in local `prowler-scans/` (excluded from Git), and displays only generic exception messages instead of command stderr, which could contain sensitive values.

**Important limitations:** Region selection is passed to Prowler with `--filter-region` (Prowler v5). Prowler may need extra privileges to read each service. Some Prowler checks cover global services rather than only the selected region. A Prowler subprocess can continue after browser disconnect until its timeout. A verification does not guarantee the session token has not expired. The local process can see child environment credentials while scans run. This is **not** a hosted, multi-user cloud account onboarding system; hosting would require app authentication, per-user authorisation and isolation, encryption at rest, key lifecycle, queue isolation, structured audit logging, job cancellation, and stronger data retention controls.

### Example AWS SSO profile

```bash
aws configure sso --profile security-auditor
aws sso login --profile security-auditor
aws sts get-caller-identity --profile security-auditor
```

Then launch Streamlit **without** `CLOUDSENTINEL_DEMO=1`, choose **AWS profile** in Cloud Connections, type `security-auditor`, and click **Test AWS connection**.

## Security boundaries

- No AWS keys, tokens, or secrets are saved in project settings or SQLite by the new Cloud Connections UI. Session secrets may still live temporarily in Streamlit/server process memory.
- Never deploy to Streamlit Community Cloud or a shared URL with its credential form enabled. Protect the app at the network and auth layers before any such deployment.
- Live scan output, imported OCSF files, and SQLite findings may contain real account IDs, private addresses, resource metadata, and IAM identifiers. Keep them out of Git.
- Scan Center deliberately does **not** send findings to LLM providers. AI analysis is a separate, explicitly configured workflow.
- Full Pipeline and Auto-sync under **Settings & Operations** are **legacy server-side integrations** and do not use the Cloud Connections browser-session credential by default. For scoped, identity-aware scans use Scan Center.
