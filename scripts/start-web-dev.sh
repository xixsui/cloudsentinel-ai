#!/usr/bin/env bash
# Local-only development launcher. Both servers share an ephemeral write token.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
if ! command -v npm >/dev/null; then echo 'Node.js/npm is required (Node >=20.9).'; exit 1; fi
if ! python -c 'import fastapi,uvicorn' 2>/dev/null; then
  echo 'Install backend dependencies: python -m pip install -r requirements-api.txt'; exit 1
fi
if [ ! -d apps/web/node_modules ]; then
  echo 'Install frontend dependencies: cd apps/web && npm install'; exit 1
fi
export CLOUDSENTINEL_WRITE_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export UPSTREAM_API_URL='http://127.0.0.1:8000'
python -m uvicorn backend_api.app:app --host 127.0.0.1 --port 8000 &
backend_pid=$!
cleanup() { kill "$backend_pid" 2>/dev/null || true; wait "$backend_pid" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
cd apps/web
npm run dev -- --hostname 127.0.0.1
