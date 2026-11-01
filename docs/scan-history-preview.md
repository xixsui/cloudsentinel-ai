# Scan History preview — 2026-10-27

## Import and startup fix — 2026-10-27

The current importer atomically writes scan history **and FAIL Findings**, so imported results appear in Overview and Misconfigurations. It preserves workflow state and never runs the legacy automatic verifier. Earlier sections below describe the original history-only preview and are superseded on this point.

Event time accepts OCSF epoch milliseconds, legacy Prowler epoch seconds, and timezone-bearing RFC3339 strings. A naive `time_dt` is not assigned an assumed timezone; the numeric event time is used when present. Conflicting numeric/aware timestamps remain ineligible for comparison. Check identity prefers `finding_info.analytic.uid` before deriving a check ID from a finding UID.

Reimporting identical report content refreshes the derived snapshot under the original ID and import time. This repairs old missing timestamp parsing without creating a new scan. Synthetic findings have separate IDs so importing a demo cannot relabel existing real evidence. Scan table counts are unique check/resource observations, whereas Findings retain the original Prowler finding identities; duplicate observations can make these totals differ.

For daily local use in Ubuntu-24.04, stop the old development launcher with Ctrl+C, then run:

```bash
source /home/example-user/.venvs/cloudsentinel-ai/bin/activate
cd /mnt/c/Users/example-user/Desktop/cloudsentinel-ai
bash scripts/start-web.sh
```

This production launcher builds once when needed and reuses the build until source/configuration changes. Both servers remain loopback-only with the same origin and write-token safeguards. `start-web-dev.sh` remains available for active UI development. Production startup avoids on-demand development compilation; it does not eliminate all Windows-mounted filesystem overhead.

Validation: 113 Python tests passed; Next.js production build passed. A local temporary-database check against the operator's supplied report found 530 events, 265 stored FAIL Findings, 528 unique check/resource observations (263 FAIL, 260 PASS, 5 MANUAL). Reimport kept 265 Findings and one scan. No private report data is included in source or fixtures. Real cloud/API execution and interactive browser checks remain untested.

This increment builds on the supplied v0.9 archive. The original ZIP and Desktop project are unchanged. It delivers offline report history and before/after comparison, not the entire v1.0 roadmap.

## Architecture and compatibility

Existing flow: Next.js same-origin proxy → FastAPI → SQLite. Existing tables hold findings, AI analysis/cache, incidents/activity, advisor runs/feedback, remediation cases/activity and the legacy scan verification observations. Streamlit retains AWS connection and scanning.

New flow: `/scans` file selection → protected `POST /api/v1/scans/import` → `ScanHistory` → additive `scan_runs` table. `GET /api/v1/scans` lists the latest 200 imports; `GET /api/v1/scans/compare?before=<id>&after=<id>` compares two imports. Invalid input returns 422; missing runs return 404. Writes retain the existing server token and browser origin checks.

`scan_runs` stores a SHA-256 import ID, import time, latest event time, source, operator-declared synthetic flag, original event count and a JSON snapshot of normalized observations. Each observation includes provider, account, region, resource, check, version, source scan ID, result, event time and comparability. Snapshot storage is deliberately separate from the legacy `scan_observations` verification ledger. It is an additive table; no old records are rewritten or inferred from current FAIL findings. Full raw reports are not stored.

Identical event arrays (including reordering) and the same synthetic flag reuse an existing run. Changed report content creates a separate immutable import. This hash is an import identity, not proof of a new independent scan or report authenticity. Historical imports do not alter findings, AI history, feedback, notes or remediation state. Back up an existing database before deploying any update; rollback can leave the additive table in place.

## Comparison policy

- Match provider + account + region + resource + check ID + check version; when check version is absent, use product version, otherwise `unknown`. Two unknown versions may match, so semantic equivalence cannot be guaranteed.
- Require timezone-bearing, non-future event times. Compare event chronology, never upload order. Reports with missing/invalid times remain visible but cannot be compared.
- New: a comparable FAIL newly appears, or follows a PASS. This means newly observed in this pair, not necessarily newly introduced in AWS.
- Persisting: a later comparable FAIL follows a FAIL.
- Resolved: a later comparable PASS follows a FAIL. This is a scanner outcome, not remediation workflow verification.
- Not Rechecked: missing check, MANUAL/unknown/conflicting result, incomplete identity, stale event, multiple resources or same supplied upstream scan ID. The label also covers evidence that is present but insufficient for comparison.
- Different versions/resources/accounts/regions are separate observations. A missing old FAIL remains Not Rechecked, even if another resource passes.
- Contradictory duplicate results aggregate to CONFLICT. Duplicate identities with inconsistent event times or source scan IDs are ineligible for resolution.
- Synthetic and historical runs cannot be compared to each other. The label is supplied by the local operator, not automatically authenticated.

The UI masks the account column. Resource IDs can still contain sensitive information; this is not complete anonymization. Imports are not sent to an AI provider. The browser limits selected files to 10 MB; the API limits imports to 20,000 events, but does not yet enforce a streaming byte limit. Keep the service local-only.

## Try the offline example

Use the existing WSL project setup and launcher. Do not reuse the Windows `.venv` or `node_modules` under WSL; create/install dependencies for that environment.

```bash
cd /path/to/updated/cloudsentinel-ai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-api.txt pytest httpx
cd apps/web
npm install
npm run build
cd ../..
bash scripts/start-web-dev.sh
```

Open `http://127.0.0.1:3000/scans`.

1. Select `mock_data/scan_history/before.json`, enable **Synthetic demo data**, and import.
2. Import `after.json` with the same synthetic label.
3. Choose the January 1 scan as Before and January 2 as After.
4. Expect one New, one Persisting, one Resolved and one Not Rechecked.
5. Reimport either file: the number of runs must not increase.
6. Reverse the comparison: expect a chronology error. Remediation statuses remain unchanged.

## Remaining work

Connect live scan jobs and legacy imports to the history ledger; add explicit scan scope/completeness and job status; normalize/index observations for larger datasets and paginate results; bound request bytes on the server; integrate history evidence with the existing baseline/pending-time verification transaction; add browser end-to-end coverage. No live AWS/Prowler or external AI provider verification was performed for this increment.

The original handoff's complete Phase B is therefore not finished. The first offline import/history/comparison slice is usable independently, with no automatic promotion to Verified.

## Verification and changed files

Validated on Windows with Python 3.12.10 on 2026-10-27:

- Existing suite: 85 passed after dependency setup and the initial API addition (not a pristine pre-edit baseline).
- Final suite: `python -m pytest tests/ -q --tb=short` — 107 passed, 29 existing UTC deprecation warnings.
- Origin policy: `node --test apps/web/tests/localOrigin.test.mjs` — 10 passed; Node emitted an existing module-type warning.
- Production build: `node node_modules/next/dist/bin/next build` — passed, including `/scans` and TypeScript checks.
- Browser interactions, WSL execution, live AWS/Prowler and external AI providers were not exercised.

Initial sandbox runs could not create pytest temporary directories or Next.js prerender output; authorized runs outside the sandbox passed. Dependencies follow the supplied version ranges; the new pnpm lock records the frontend resolution. The optional `unrs-resolver` install script is disabled; production build does not require it.

New files: `ai_module/scan_history.py`, `tests/test_scan_history.py`, `apps/web/src/app/scans/page.tsx`, `mock_data/scan_history/before.json`, `mock_data/scan_history/after.json`, this document, and frontend pnpm lock/workspace files.

Modified files: `backend_api/app.py`, Next.js proxy route, `Shell.tsx`, `globals.css`, `README.md` and `CHANGELOG.md`. Next.js also refreshed its generated `next-env.d.ts` during the build. No changes were made to the legacy scanner or remediation verifier.
