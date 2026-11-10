#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
if ! command -v node >/dev/null && [[ -s "${NVM_DIR:-$HOME/.nvm}/nvm.sh" ]]; then
  source "${NVM_DIR:-$HOME/.nvm}/nvm.sh"
fi
command -v python3 >/dev/null || { echo 'Install Python 3.12 and venv support first.'; exit 1; }
command -v npm >/dev/null || { echo 'Install Node.js 22 and npm first.'; exit 1; }
node -e 'if(Number(process.versions.node.split(".")[0])!==22){console.error("Use Node.js 22 for this release.");process.exit(1)}'
python3 scripts/doctor.py --startup
python3 scripts/service.py start
if [[ -z "${WSL_DISTRO_NAME:-}" ]] && command -v xdg-open >/dev/null; then xdg-open http://127.0.0.1:3000 >/dev/null 2>&1 || true; fi
