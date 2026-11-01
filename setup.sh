#!/usr/bin/env bash
#
# setup.sh — first-time setup for the AI Cloud Security Console.
#
# This script only installs the Python side of the project (venv +
# dependencies). Prowler and Wazuh have their own installation steps —
# see README.md for details.
#
# Run this ONCE after cloning the repo. Subsequent launches: ./start.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn()  { echo -e "${YELLOW}[setup]${NC} $*"; }
error() { echo -e "${RED}[setup]${NC} $*"; }

echo "============================================================"
echo "  AI Cloud Security Console — first-time setup"
echo "============================================================"

# ---- Prerequisite check: Prowler ----
echo ""
info "Prerequisite: Prowler (cloud misconfiguration scanner)"
if command -v prowler >/dev/null 2>&1; then
    info "Prowler is installed: $(prowler -v 2>/dev/null | head -1)"
else
    warn "Prowler is not installed."
    echo ""
    read -r -p "Have you installed Prowler and configured it with AWS credentials? [y/N] " ans_prowler
    ans_prowler=${ans_prowler:-N}
    if [[ ! "$ans_prowler" =~ ^[Yy]$ ]]; then
        error "Prowler is required for the misconfiguration data source."
        echo ""
        echo "To install Prowler:"
        echo "  pip install prowler"
        echo ""
        echo "For full setup instructions (AWS credentials, running a scan)"
        echo "see the 'Prowler' section in README.md"
        echo ""
        echo "You can install Prowler now in a separate terminal, then re-run"
        echo "this script. Or continue anyway if you plan to install it later."
        echo ""
        read -r -p "Continue setup without Prowler? [y/N] " continue_ans
        continue_ans=${continue_ans:-N}
        if [[ ! "$continue_ans" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
fi

# ---- Prerequisite check: Wazuh ----
echo ""
info "Prerequisite: Wazuh (SIEM for threat detection)"
WAZUH_OK=0
if command -v docker >/dev/null 2>&1; then
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "wazuh"; then
        info "Wazuh containers detected."
        WAZUH_OK=1
    fi
fi

if [ "$WAZUH_OK" -eq 0 ]; then
    warn "Wazuh containers not detected."
    echo ""
    read -r -p "Have you set up Wazuh (Docker containers + ossec.conf configured)? [y/N] " ans_wazuh
    ans_wazuh=${ans_wazuh:-N}
    if [[ ! "$ans_wazuh" =~ ^[Yy]$ ]]; then
        warn "Wazuh is optional but recommended for CloudTrail threat detection."
        echo ""
        echo "For Wazuh setup (Docker containers + AWS credentials + ossec.conf)"
        echo "see the 'Wazuh' section in README.md"
        echo ""
        echo "You can proceed without Wazuh — the dashboard will still work with"
        echo "just Prowler misconfigurations and VPC Flow Logs."
        echo ""
        read -r -p "Continue setup without Wazuh? [Y/n] " continue_ans
        continue_ans=${continue_ans:-Y}
        if [[ ! "$continue_ans" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
fi

# ---- 1. Check Python version ----
echo ""
if ! command -v python3 >/dev/null 2>&1; then
    error "python3 not found. Install Python 3.10+ and re-run."
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
info "Python $PY_VERSION found"

PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')
if [ "$PY_OK" -ne 1 ]; then
    error "Python 3.10+ required (found $PY_VERSION)."
    exit 1
fi

# ---- 2. Create virtual environment ----
if [ -d "venv" ]; then
    warn "A venv/ already exists. Reusing it."
    warn "(Delete it and re-run for a clean install.)"
else
    info "Creating virtual environment in ./venv ..."
    python3 -m venv venv
fi

# shellcheck disable=SC1091
source venv/bin/activate
info "Virtual environment activated."

# ---- 3. Install Python dependencies ----
info "Upgrading pip ..."
pip install --quiet --upgrade pip

info "Installing Python dependencies (this can take a few minutes) ..."
pip install --quiet -r requirements.txt
info "Dependencies installed."

# ---- 4. Prepare .env ----
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    cp .env.example .env
    info "Created .env from template."
fi

# ---- 5. Initialise the database ----
info "Initialising local database ..."
python3 -c "from ai_module.database import Database; Database(); print('  Database ready')"

# ---- Done ----
echo ""
echo "============================================================"
info "Setup complete!"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Launch the dashboard:   ./start.sh"
echo ""
echo "On first launch, go to the Settings page to:"
echo "  - Add an API key for your AI provider (Gemini has a free tier)"
echo "  - Configure your data sources (Prowler / Wazuh / VPC Flow)"
echo "  - Run the pipeline"
echo ""
