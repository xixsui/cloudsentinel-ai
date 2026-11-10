#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
if ! command -v node >/dev/null && [[ -s "${NVM_DIR:-$HOME/.nvm}/nvm.sh" ]]; then
  source "${NVM_DIR:-$HOME/.nvm}/nvm.sh"
fi
command -v python3 >/dev/null || { echo 'Install Python 3.12 with venv support, then run bash scripts/setup-linux.sh.'; exit 1; }
python3 scripts/doctor.py "$@"
