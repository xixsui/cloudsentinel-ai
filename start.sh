#!/usr/bin/env bash
#
# start.sh — launch the AI Cloud Security Console.
#
# Use this every time you want to run the dashboard after the initial setup.sh.
# It activates the virtual environment, does a few sanity checks, and starts
# Streamlit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[start]${NC} $*"; }
warn()  { echo -e "${YELLOW}[start]${NC} $*"; }
error() { echo -e "${RED}[start]${NC} $*"; }

# ---- 1. Ensure venv exists ----
if [ ! -d "venv" ]; then
    error "No venv/ found. Run ./setup.sh first."
    exit 1
fi

# shellcheck disable=SC1091
source venv/bin/activate

# ---- 2. Quick sanity checks (non-fatal warnings) ----
# Offline demo must not make AWS STS or Wazuh reachability requests.
DEMO="${CLOUDSENTINEL_DEMO:-0}"
if [[ "$DEMO" == "1" || "$DEMO" == "true" || "$DEMO" == "yes" ]]; then
    info "Offline demo mode: skipping AWS and Wazuh connectivity checks."
elif command -v aws >/dev/null 2>&1; then
    if aws sts get-caller-identity >/dev/null 2>&1; then
        ACCT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "?")
        info "AWS credentials OK (account $ACCT)"
    else
        warn "AWS CLI present but credentials not working. Prowler/VPC Flow/inventory may fail."
    fi
else
    warn "AWS CLI not found. Cloud inventory and VPC Flow features will be limited."
fi

# Wazuh indexer reachability (optional)
if [[ "$DEMO" != "1" && "$DEMO" != "true" && "$DEMO" != "yes" ]] && command -v curl >/dev/null 2>&1; then
    if curl -sS --max-time 3 "${WAZUH_INDEXER_HOST:-https://localhost:9200}" >/dev/null 2>&1; then
        info "Wazuh indexer reachable on https://localhost:9200"
    else
        warn "Wazuh indexer not reachable (https://localhost:9200). Start it if you need threat data:"
        warn "  cd wazuh-docker/single-node && docker compose up -d"
    fi
fi

# ---- 3. Pick host/port ----
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8501}"

echo ""
info "Launching dashboard at http://${HOST}:${PORT}"
info "(Press Ctrl+C to stop.)"
echo ""

exec streamlit run dashboard/app.py \
    --server.address "$HOST" \
    --server.port "$PORT"
