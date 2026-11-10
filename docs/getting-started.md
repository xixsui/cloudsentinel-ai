# Installation and first use

## Requirements

Linux or WSL2 (Ubuntu recommended), Python 3.12 with venv support, Node.js 22 and npm. Internet access is needed to install dependencies. Prowler is optional for importing existing reports.

Extract the source into your Linux home directory for better filesystem performance. In WSL, Windows `C:\Users` is `/mnt/c/Users`, not `C:/Users`.

From the extracted project root, install the pinned Linux/WSL environment once (Python 3.12 and Node.js 22):

```bash
bash scripts/setup-linux.sh
```

This installs into the Linux user environment `~/.venvs/cloudsentinel-ai` (override with `CLOUDSENTINEL_VENV` for both setup and start), uses `requirements-linux-py312.lock` and `npm ci` with `apps/web/package-lock.json`, then builds the UI. It does not install OS packages or Prowler. The Python lock targets Linux Python 3.12; the broader requirements files remain available for developers testing other Python versions.

## Start and stop

Linux desktop or terminal:

```bash
bash scripts/start-linux.sh
bash scripts/stop-linux.sh
```

Windows: double-click **Start CloudSentinel.cmd** or **Stop CloudSentinel.cmd** after completing setup inside WSL. Scripts use your default WSL distribution. To choose another, run `powershell -File scripts/start-windows.ps1 -Distro Ubuntu-24.04` (use the matching distribution for stop). If the checkout is inside the Linux filesystem, use the Linux commands inside WSL instead.

The start script opens the browser where supported and runs both services on loopback. The stop script stops only this project's managed processes; it does not shut down WSL or other applications. Stop interrupts active scans/installations, so wait for them to complete first. Foreground development remains available with `bash scripts/start-web.sh` and Ctrl+C.

Open http://127.0.0.1:3000. Startup progress and errors are in `.runtime/service.log`; the log is private runtime data and ignored by Git. Ports 3000/8000 must be free. A second start does not create duplicate services. A port conflict does not kill unrelated processes.

Windows paths with spaces are supported. WSL file access on `/mnt/c` can be slower; Linux users should keep the checkout in their home directory. Never run setup/start with sudo.

## Connection status

When the local API health check fails, a recovery notice offers Check connection and Reload page. Healthy connections do not show a banner. AWS connection details remain in Settings; the Overview resource inventory appears only when AWS is connected. A timeout advises checking operation state before retrying writes. Reload after service recovery to refresh page data.

Overview shows a short getting-started hint while AWS is disconnected and no reports or findings are stored. Connecting AWS or importing a report hides the hint. Finding filters appear once stored reports or findings are available.

## Backup and restore

Settings → Backup and restore downloads a versioned JSON archive (maximum 20 MB / 100,000 records). It includes findings, scan evidence/snapshots, remediation history, incidents and saved AI analysis/feedback. AWS/AI credentials, app settings, transient scan jobs and AI cache are excluded. Evidence and notes can contain sensitive information; keep archives private.

Select an archive to validate and preview record counts, then type RESTORE to replace current data. The exact previewed content is checked again before the atomic replacement. A private pre-restore recovery archive is saved under `~/.local/share/cloudsentinel/recovery/`. You can restore that JSON through the same interface. Active scans or data writes block export/restore. Restored Verified states are historical records, not fresh verification. Invalid archives are rejected without replacing data.

## First use

1. The workspace is empty by default. Scan History accepts your own Prowler OCSF JSON (10 MB / 20,000 events maximum).
2. For live scanning, configure AWS in Settings. You must provide an authorized identity and appropriate read permissions. The tool does not create IAM users or grant permissions.
3. Settings → Prowler scanner detects or installs the supported scanner in an isolated Linux environment. Then refresh scan status.
4. Confirm account, region and services before starting. No scan runs automatically.
5. Optional: configure an AI provider in Settings, inspect the prompt preview and consent before sending evidence externally. Redaction is best effort.

## Storage and backup

Runtime SQLite data is created under `data/`; backend credentials/preferences may also reside outside the project in the Linux user environment. Never upload either to GitHub. Removing findings does not remove saved credentials.

Before replacing your installation, stop the launcher and back up runtime data privately. Do not put backups inside the Git repository. The release contains neither real scan data nor preconfigured credentials.

## Troubleshooting

- **Local API unavailable:** start the complete application with `bash scripts/start-linux.sh` or Start CloudSentinel.cmd, then use port 3000.
- **Expired credentials:** renew/sign in, reconnect in Settings, then explicitly retry.
- **Read denied:** review supported read-access diagnostics with your account administrator; do not grant unrestricted permissions just to suppress errors.
- **Old snapshot unavailable:** reimport the original report. Current findings are not substituted for missing historical evidence.

This is a local preview, not a hardened hosted service. See [web scanning limits](web-scanning.md).

## Installation diagnostics

Run `bash scripts/check-linux.sh` on Linux/WSL, or double-click **Check CloudSentinel.cmd** on Windows. Use `powershell -File scripts/check-windows.ps1 -Distro Ubuntu-24.04` to choose a WSL distribution. The check reports the application Python environment, imports, dependency consistency, Node.js/npm, frontend installation, disk space, ports and local API health. It does not install packages, read credentials, call AWS/AI, or stop other processes. Startup runs the prerequisite checks automatically. For machine-readable output, use `bash scripts/check-linux.sh --json`.

## Guided AWS connection

Settings explains temporary credentials, backend profiles, role/environment credentials and IAM user access keys. Verify the returned account before running read-access diagnostics. Diagnostics name the inventory API operations that failed; these are a subset of the permissions Prowler may need, and do not prove complete scan access. No IAM policies are changed automatically.

Temporary credentials can include an optional operator-supplied expiration. It is not inferred from the token or verified by STS. Unknown expiration is explicitly shown as unknown. At a supplied expiry, new inventory/scan connections are blocked until reconnecting; ongoing scans still depend on AWS's actual credential validity. Temporary credentials are memory-only. See [AWS temporary credential documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html).

## Preview an imported report

Scan History → Preview report validates a JSON report before adding it to your workspace. Review the account, scan time, event/outcome counts, repeated observations and exact-report duplicate notice, then choose Confirm import. A report with no FAIL findings still appears in Scan History. Validation uses a private temporary database that is removed after preview; it does not add report data to the workspace or send evidence to AI. Changing the file or synthetic label requires another preview. Errors identify the event number where possible. Importing older evidence preserves newer current findings and does not verify remediation.
