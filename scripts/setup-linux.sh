#!/usr/bin/env bash
# Run once on Linux, or inside WSL. No sudo or automatic OS package changes.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
if ! command -v node >/dev/null && [[ -s "${NVM_DIR:-$HOME/.nvm}/nvm.sh" ]]; then
  source "${NVM_DIR:-$HOME/.nvm}/nvm.sh"
fi
command -v python3.12 >/dev/null || { echo 'Install Python 3.12 and its venv support first.'; exit 1; }
command -v npm >/dev/null || { echo 'Install Node.js 22 and npm first.'; exit 1; }
node -e 'if(Number(process.versions.node.split(".")[0])!==22){console.error("Use Node.js 22.");process.exit(1)}'
env_dir="${CLOUDSENTINEL_VENV:-$HOME/.venvs/cloudsentinel-ai}"
if [[ ! -d "$env_dir" ]]; then python3.12 -m venv "$env_dir"; fi
"$env_dir/bin/python" -c 'import sys; assert sys.version_info[:2]==(3,12), "Existing application environment must use Python 3.12"'
"$env_dir/bin/python" -m pip install -r requirements-linux-py312.lock
"$env_dir/bin/python" -m pip check
(cd apps/web && npm ci --no-audit --no-fund && npm run build)
echo 'Setup complete. Start with bash scripts/start-linux.sh.'
