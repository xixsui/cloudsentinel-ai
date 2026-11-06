# CloudSentinel AI

Local AWS security posture workspace with optional AI-assisted remediation guidance.

**Preview release — Linux/WSL, single operator, localhost only.** No login/RBAC or multi-user isolation. Do not expose the UI or API publicly. Real AWS scan and AI provider end-to-end acceptance remain outstanding; offline tests are not a substitute.

## Run locally

Install Python 3.12 and Node.js 22, then run `bash scripts/setup-linux.sh` inside Linux/WSL. Start with `bash scripts/start-linux.sh` (Linux) or **Start CloudSentinel.cmd** (Windows). Use the matching stop script to stop only CloudSentinel.

Settings includes workspace backup/restore; credentials are excluded. API recovery guidance appears only when the local API is unavailable. AWS connection details are available in Settings.

## Start here

- [Installation and first use](docs/getting-started.md)
- [Scanning, snapshots and verification](docs/web-scanning.md)
- [AI settings](docs/ai-settings.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

The application starts empty. Import your own Prowler OCSF JSON, or connect AWS in Settings and explicitly authorize a scan. No credentials or AI subscription are needed to browse the empty workspace. Synthetic fixtures in `mock_data/scan_history` are optional and must be imported as synthetic data.

## Implemented

- AWS connection settings, read-only resource inventory and diagnostics.
- Prowler setup in a separate Linux environment; service/region selection, cancellation and persisted job history.
- OCSF import, finding filters, immutable snapshots for new imports and report comparison.
- Remediation tracking and explicit rechecks; only matching fresh PASS evidence can verify a case.
- Optional AI providers with backend credentials, prompt preview, best-effort redaction and explicit consent.
- Local finding/history deletion and actionable scan failure guidance.

No remediation commands are executed automatically. A failed check is not evidence of an attack; a PASS is not proof of complete account security. Prowler errors with only an exit code cannot be reliably attributed to a specific AWS cause.

## Interface

Screenshots show an empty, disconnected workspace. No real AWS accounts, credentials or scan reports are displayed.

### Overview and first use

![Empty workspace overview](docs/images/overview.png)

<details>
<summary>Scan readiness and settings</summary>

![Scan readiness checks](docs/images/scans.png)

![AWS connection settings with empty credential fields](docs/images/settings.png)

</details>

## Development

```bash
python -m pip install pytest httpx
python -m pytest -q
cd apps/web
npm run build
```
