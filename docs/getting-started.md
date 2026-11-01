# Installation and first use

## Requirements

Linux or WSL2 (Ubuntu recommended), Python 3.10+ with venv support, Node.js 22 and npm. Internet access is needed to install dependencies. Prowler is optional for importing existing reports.

Extract the source into your Linux home directory for better filesystem performance. In WSL, Windows `C:\Users` is `/mnt/c/Users`, not `C:/Users`.

From the extracted project root:

```bash
python3 -m venv ~/.venvs/cloudsentinel-ai
source ~/.venvs/cloudsentinel-ai/bin/activate
python -m pip install -r requirements.txt -r requirements-api.txt
cd apps/web
npm install
cd ../..
bash scripts/start-web.sh
```

Open http://127.0.0.1:3000 . Keep the launcher running; Ctrl+C stops the services. The launcher builds the UI as needed and starts both frontend and backend with the matching local write token. Running `npm run dev` alone does not start the API.

If Python reports missing venv support, install the Python venv package for your Linux distribution first. If a port is busy, stop your previous launcher before retrying. This release does not install OS packages automatically.

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

- **Local API unavailable:** start the complete application with `bash scripts/start-web.sh`, then use port 3000.
- **Expired credentials:** renew/sign in, reconnect in Settings, then explicitly retry.
- **Read denied:** review supported read-access diagnostics with your account administrator; do not grant unrestricted permissions just to suppress errors.
- **Old snapshot unavailable:** reimport the original report. Current findings are not substituted for missing historical evidence.

This is a local preview, not a hardened hosted service. See [web scanning limits](web-scanning.md).
