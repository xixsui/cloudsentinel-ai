# Web scans, account scope, onboarding and diagnostics

Open Home → Run Prowler scan, or Scan History → Run a Prowler scan. Connect AWS in
Settings first. The form displays the account, selected region and allowlisted services.
Explicit consent is required to submit a job. No scan starts on page load or connection.

The backend rechecks the identity before launch and accepts only reports whose account
matches the selected account. Changing/disconnecting AWS does not change an already
running job: use Cancel to stop that job. The UI shows phase-based progress, timestamps,
outcomes and an imported scan link. It does not invent a percentage or claim full account
coverage. Read failures within Prowler can still mean incomplete check coverage.

## Local scanner setup

Settings → Prowler scanner now detects the local executable and reports its version.
If missing, explicitly approve the download and click Install Prowler. Setup installs
the tested version 5.46.0 from PyPI in `~/.venvs/cloudsentinel-prowler-managed-5.46.0`,
separate from application dependencies. Existing or server-configured scanners are
never overwritten. No installation, scan or AWS request starts on page load.

The UI polls preparation, installation and verification stages; only successful version
verification publishes the new scanner. Installation is bounded to 20 minutes plus up
to two minutes of environment creation. Errors use controlled messages rather than raw
package logs. Retry reuses the dedicated partial environment. Backend restarts show an
incomplete setup as retryable; setup is not automatically resumed. Keep WSL/backend
running until completion. A process lock prevents overlapping installs.

The installer does not inherit AWS/AI secrets, user pip indexes or Python paths. It
requires Linux/WSL, Python 3.10+, venv support, disk space and access to PyPI; it does not
install WSL, Python or OS packages. AWS credentials and read permissions remain the
user's responsibility. Existing scanners with failed version checks require manual
repair. This release does not upgrade or uninstall existing scanners.

Manual alternative:

Linux/WSL single-worker deployment is required. Install the official CLI in its own
environment so the application's dependencies remain separate:

```bash
python3 -m venv ~/.venvs/cloudsentinel-prowler
~/.venvs/cloudsentinel-prowler/bin/pip install prowler
```

The backend discovers `CLOUDSENTINEL_PROWLER_BIN` (server-managed executable path), then
`prowler` in PATH, then `~/.venvs/cloudsentinel-prowler/bin/prowler`. This implementation
was checked against Prowler 5.46.0 local CLI help. Exit codes 0 and 3 permit report
validation; other exits never import partial output. Prowler documents code 3 as checks
with FAIL results: https://github.com/prowler-cloud/prowler/discussions/5142

One job runs at a time. Default deadline: 30 minutes (API allows 1–60 minutes).
Cancellation and timeout terminate the process group and discard partial output. Linux
parent-death signalling stops the direct scanner when its API parent exits. Restarted
jobs become `interrupted`; they are never resumed or silently imported. The validated
report is capped at 10 MB / 20,000 events; reduce scope for larger scans. Temporary files
are private and cleaned on normal completion/failure/cancellation. An abrupt OS/process
crash may leave an owner-only temporary directory for OS temp cleanup.

Command arguments come from a fixed allowlist, no shell or browser-supplied command.
AWS credentials are passed through child environment only. Application/AI secrets and
Prowler Cloud upload tokens are not inherited. Raw stdout/stderr are not saved or exposed.
Jobs persist only account, scope, timestamps, controlled messages and imported scan ID.
Clear-all removes job history too and is blocked while a scan is active. Completed
imports use the existing transactional report importer; no automatic remediation-state
verification is asserted.

## Account and scan scope

Home and Findings have account/scan selectors. AWS resource inventory stays bound to the
currently connected account; stored findings selectors are independent and explicitly
labelled. Home shows accounts and latest finding evidence time. Scan History shows report
account IDs and distinguishes web scans from file imports.

Scan selectors now read immutable normalized FAIL snapshots, including finding details.
Older reports without a snapshot require reimporting the original report; current data
is never substituted. Reimporting older evidence does not roll current findings back.
Snapshot details are read-only; workflow counters/status are explicitly current.
Selected deletion removes the selected finding's snapshot details as well as its current
record. Scan summaries retain observations until Clear all findings and history.

## Explicit finding rechecks

Set a case In Progress, then Pending Verification. The finding page can launch a live
service-scoped scan for its account and region; confirmation is required. This scans the
service, not just one resource. Only the exact captured provider/account/region/resource/
check/version identity is evaluated. A new, unambiguous, timestamped PASS after both the
baseline and verification request sets Verified and records the scan in activity history.
FAIL remains pending with Still failing. Missing, manual, conflicting, stale or changed
version results are Unable to confirm. A workflow change during scanning blocks automatic
verification. Synthetic or incomplete baselines cannot be live-verified. No AWS changes
are applied. Normal imports and general scans do not automatically verify cases.

## AI sending preview

Preview sending content prepares the application prompt locally, without contacting a
provider. Standard mode masks identifiers; Minimal also omits title and description.
Redaction is best effort, not guaranteed anonymization. Consent applies to the displayed
provider/model and preview hash. Changed evidence, destination or sharing mode requires a
fresh preview. Raw events and credentials are never in the prompt. Provider SDK formatting
and structured-output schema instructions are additional to the displayed application
prompt. Previously saved analyses retain their original provider/model labels.

## First use and diagnostics

With no imported reports or findings, Home offers two paths: upload existing OCSF JSON
(no AWS credentials required), or connect AWS and run a scan. It displays AWS, scanner
and optional AI readiness. It never seeds demonstration records automatically.

Settings → AWS read-access diagnostics runs the supported inventory listing asynchronously.
It reports service failures, expired/invalid credentials, access denied, throttling and
network failures with controlled text. It does not echo SDK exception details, grant
permissions or claim a complete Prowler permission audit. Inventory results are shared
with Home and invalidated when switching/disconnecting the AWS identity.

Validation uses isolated databases, fake credential identities and fake CLI subprocesses.
Actual AWS scanning remains an operator-initiated acceptance check.
