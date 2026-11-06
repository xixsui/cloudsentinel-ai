#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
echo 'Stopping CloudSentinel also interrupts any active scan or installation. Partial scan output will not be imported.'
python3 scripts/service.py stop
