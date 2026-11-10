#!/usr/bin/env bash
# Daily local use: production Next.js avoids on-demand development compilation.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
env_dir="${CLOUDSENTINEL_VENV:-$HOME/.venvs/cloudsentinel-ai}"
if [[ -f "$env_dir/bin/activate" ]]; then
  source "$env_dir/bin/activate"
fi
command -v npm >/dev/null || { echo 'Node.js/npm is required.'; exit 1; }
python -c 'import fastapi,uvicorn' || { echo 'Activate the project Python environment first.'; exit 1; }
[[ -d apps/web/node_modules ]] || { echo 'Install frontend dependencies: bash scripts/setup-linux.sh'; exit 1; }

# Fail before launching either service when one of the intended ports is occupied.
python - <<'PY'
import socket
for port in (8000, 3000):
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('127.0.0.1', port))
        except OSError:
            raise SystemExit(f'Port {port} is busy. Stop the previous launcher with Ctrl+C first.')
PY

build_id=apps/web/.next/BUILD_ID
rebuild=false
if [[ ! -f "$build_id" ]]; then
  rebuild=true
elif [[ -n "$(find apps/web/src -type f -newer "$build_id" -print -quit)" ]]; then
  rebuild=true
else
  for config in apps/web/package.json apps/web/package-lock.json apps/web/next.config.ts apps/web/tsconfig.json; do
    if [[ -f "$config" && "$config" -nt "$build_id" ]]; then rebuild=true; fi
  done
fi
if [[ "$rebuild" == true ]]; then
  echo 'Building the production UI once; subsequent starts reuse it until source changes.'
  (cd apps/web && npm run build)
fi
export CLOUDSENTINEL_WRITE_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export UPSTREAM_API_URL='http://127.0.0.1:8000'
python -m uvicorn backend_api.app:app --host 127.0.0.1 --port 8000 &
backend_pid=$!
cleanup() { kill "$backend_pid" 2>/dev/null || true; wait "$backend_pid" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
cd apps/web
npm run start -- --hostname 127.0.0.1
