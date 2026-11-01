"""
Background scheduler for automatic pipeline runs.

Runs the orchestrator on a fixed interval in a background thread. This is the
"auto sync" toggle in the Settings page. Lives in-process with Streamlit so the
user doesn't have to set up cron / systemd / Docker.

Why a thread, not a subprocess?
- Simpler: one process, shared SQLite DB.
- No need to manage PID files.
- Streamlit reruns scripts on every interaction, so we need a singleton that
  survives reruns — `st.cache_resource` handles that.

The scheduler tolerates errors in any individual run (the orchestrator already
catches per-step exceptions) and keeps going.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from ai_module.database import Database
from orchestrator.pipeline import (
    Orchestrator, PipelineResult, build_config_from_user_settings,
)

logger = logging.getLogger("scheduler")


@dataclass
class SchedulerState:
    enabled: bool = False
    interval_minutes: int = 15
    last_run_at: Optional[datetime] = None
    last_result: Optional[PipelineResult] = None
    next_run_at: Optional[datetime] = None
    runs_total: int = 0
    is_running_now: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


class BackgroundScheduler:
    """A single background thread that wakes every minute and runs the
    pipeline when due."""

    def __init__(self):
        self.state = SchedulerState()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------ #
    # Public API used by the Settings UI
    # ------------------------------------------------------------------ #
    def start(self, interval_minutes: int) -> None:
        """Turn auto-sync on with the given interval."""
        with self.state.lock:
            self.state.interval_minutes = max(1, int(interval_minutes))
            if self.state.enabled and self._thread and self._thread.is_alive():
                # Already running — just update the interval.
                logger.info("Scheduler interval updated to %d minutes",
                            self.state.interval_minutes)
                return

            self.state.enabled = True
            self.state.next_run_at = datetime.utcnow()  # run once now-ish

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="ai-cloud-sec-scheduler")
        self._thread.start()
        logger.info("Background scheduler started (every %d min)",
                    self.state.interval_minutes)

    def stop(self) -> None:
        """Turn auto-sync off."""
        with self.state.lock:
            self.state.enabled = False
            self.state.next_run_at = None
        self._stop_event.set()
        logger.info("Background scheduler stopped")

    def status(self) -> dict:
        """Snapshot of current state for the UI."""
        with self.state.lock:
            return {
                "enabled": self.state.enabled,
                "interval_minutes": self.state.interval_minutes,
                "last_run_at": self.state.last_run_at,
                "next_run_at": self.state.next_run_at,
                "runs_total": self.state.runs_total,
                "is_running_now": self.state.is_running_now,
                "last_steps": (
                    [(s.name, s.ok, s.findings_added, s.message)
                     for s in self.state.last_result.steps]
                    if self.state.last_result else []
                ),
            }

    # ------------------------------------------------------------------ #
    # The thread body
    # ------------------------------------------------------------------ #
    def _loop(self) -> None:
        while not self._stop_event.is_set():
            now = datetime.utcnow()
            with self.state.lock:
                should_run = (
                    self.state.enabled
                    and self.state.next_run_at is not None
                    and now >= self.state.next_run_at
                    and not self.state.is_running_now
                )

            if should_run:
                self._run_once()

            # Sleep for ~10 seconds, but wake early if stop is requested.
            self._stop_event.wait(timeout=10)

        # Reset thread handle
        logger.info("Scheduler thread exiting")

    def _run_once(self) -> None:
        with self.state.lock:
            self.state.is_running_now = True
        try:
            cfg = build_config_from_user_settings()
            orch = Orchestrator(db=Database())
            result = orch.run(cfg)

            with self.state.lock:
                self.state.last_result = result
                self.state.last_run_at = result.finished_at or datetime.utcnow()
                self.state.runs_total += 1
                from datetime import timedelta
                self.state.next_run_at = (
                    datetime.utcnow() +
                    timedelta(minutes=self.state.interval_minutes)
                )
        except Exception:  # noqa: BLE001
            logger.exception("Scheduled pipeline run failed entirely")
        finally:
            with self.state.lock:
                self.state.is_running_now = False
