"""
Legacy environment-variable configuration.

Most of the system now uses `config/user_settings.py` (dashboard-editable,
persisted to JSON) instead of these environment variables. This file is
retained only for a few things that still need process-level constants:

- `DB_PATH` — where the SQLite database lives.
- `RATE_LIMIT_SECONDS` — client-side pacing for LLM providers.

For runtime AI backend / API keys, see `config/user_settings.py` — the
dashboard's Settings page reads and writes it.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "findings.db"

RATE_LIMIT_SECONDS = float(os.getenv("RATE_LIMIT_SECONDS", "1.0"))
