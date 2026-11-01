"""
Efficiency Benchmark for the AI-Assisted Cloud Cybersecurity System.

Covers the four efficiency metrics that require automated measurement:
    E1 — Pipeline execution time vs dataset size (local overhead)
    E4 — Peak memory footprint during pipeline run
    E5 — Database query time at varying row counts
    E6 — Ingestion time per collection module (Prowler / Wazuh / VPC)

E2 (per-provider AI latency), E3 (token & cost), and E7 (per-task response time)
are collected via the dashboard because their raw values are already recorded
in the ai_analysis table (duration_ms, input_tokens, output_tokens).

Usage (from project root):
    pip install psutil                                        # once
    python benchmark.py e1                                    # ~3-5 min
    python benchmark.py e4                                    # ~3-5 min
    python benchmark.py e5                                    # ~1 min
    python benchmark.py e6                                    # per-module ingestion
    python benchmark.py all                                   # E1 + E4 + E5 (no E6, needs args)

    # E6 uses live infrastructure — run each module explicitly:
    python benchmark.py e6 --prowler-sample path/to/prowler.ocsf.json
    python benchmark.py e6 --wazuh
    python benchmark.py e6 --vpcflow --vpc-bucket my-flowlog-bucket
"""

from __future__ import annotations

import argparse
import csv
import gc
import os
import random
import sqlite3
import statistics
import string
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# --- Project imports ------------------------------------------------------- #
from ai_module.database import Database
from mock_data.generate import build_mock_findings
from orchestrator.pipeline import Orchestrator, PipelineConfig

# --- Constants ------------------------------------------------------------- #
RESULTS_DIR = Path("benchmark_results")
RESULTS_DIR.mkdir(exist_ok=True)

WARMUP_ITERS = 2
MEASURED_ITERS = 10
DATASET_SIZES = [1_000, 5_000, 10_000]
DB_ROW_COUNTS = [1_000, 10_000, 50_000]


# --- Common helpers ------------------------------------------------------- #
def _write_csv(name: str, header: list[str], rows: list[list]) -> Path:
    path = RESULTS_DIR / f"{name}.csv"
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    return path


def _fresh_db(name: str) -> Database:
    """Fresh SQLite so iterations are independent."""
    db_path = RESULTS_DIR / f"{name}.db"
    if db_path.exists():
        db_path.unlink()
    return Database(db_path=db_path)


def _seed_findings(db: Database, count: int) -> int:
    """
    Cycle the 9 mock templates and give each finding a unique ID.
    Uses .model_copy() because Finding is a Pydantic BaseModel.
    """
    template = build_mock_findings()
    if not template:
        raise RuntimeError("build_mock_findings() returned empty list")
    for i in range(count):
        base = template[i % len(template)]
        new_finding = base.model_copy(update={
            "finding_id": f"{base.finding_id}-b{i:05d}"
        })
        db.upsert_finding(new_finding)
    return count


def _local_only_cfg() -> PipelineConfig:
    """Pipeline with all collection modules and AI disabled — measures local overhead."""
    return PipelineConfig(
        prowler_enabled=False,
        wazuh_enabled=False,
        vpcflow_enabled=False,
        ai_enabled=False,
        correlate_enabled=True,
        ai_min_severity="",
    )


def _mean_std(samples: list[float]) -> tuple[float, float]:
    if not samples:
        return 0.0, 0.0
    mean = statistics.mean(samples)
    std = statistics.stdev(samples) if len(samples) > 1 else 0.0
    return mean, std


# ============================================================================
# E1 — Findings-database throughput vs dataset size
# ============================================================================
def run_e1() -> None:
    print("\n[E1] Findings-database throughput vs dataset size")
    print("     Measures the time to write N findings to SQLite and read them back.")
    print("     No LLM / network calls — pure local database throughput.")

    rows = []
    for n in DATASET_SIZES:
        print(f"\n  Dataset size = {n:,}")
        samples: list[float] = []

        # Only 3 iterations for the largest sizes to keep total time reasonable
        measured = MEASURED_ITERS if n <= 5000 else 3
        warmup = 1 if n > 5000 else WARMUP_ITERS

        for it in range(warmup + measured):
            db = _fresh_db(f"e1_{n}")

            t0 = time.perf_counter()
            # 1. Write N findings to the DB
            _seed_findings(db, n)
            # 2. Read them back (simulates dashboard listing)
            findings = db.get_findings()
            elapsed = time.perf_counter() - t0

            tag = "measured" if it >= warmup else "warmup"
            print(f"    iter {it + 1:>2}: {elapsed:.3f}s "
                  f"({len(findings)} rows read) ({tag})")
            if it >= warmup:
                samples.append(elapsed)

        mean, std = _mean_std(samples)
        ms_per_finding = (mean / n) * 1000 if n else 0.0
        rows.append([f"{n:,}", f"{mean:.3f}", f"{std:.3f}", f"{ms_per_finding:.2f}"])
        print(f"    → mean = {mean:.3f}s, std = {std:.3f}s, "
              f"per finding = {ms_per_finding:.2f} ms")

    _write_csv(
        "E1_db_throughput",
        ["Dataset Size (findings)", "Mean Time (s)",
         "Std. Dev. (s)", "Time per Finding (ms)"],
        rows,
    )
    print(f"\n  → wrote {RESULTS_DIR}/E1_db_throughput.csv")


# ============================================================================
# E4 — Peak memory footprint
# ============================================================================
def run_e4() -> None:
    print("\n[E4] Peak memory footprint during pipeline run")

    try:
        import psutil
    except ImportError:
        print("  ! psutil not installed. Run: pip install psutil")
        return

    rows = []
    for n in DATASET_SIZES:
        print(f"\n  Seeding {n:,} findings...")
        db = _fresh_db(f"e4_{n}")
        _seed_findings(db, n)

        proc = psutil.Process(os.getpid())
        peak = [proc.memory_info().rss]
        running = [True]

        def sampler() -> None:
            while running[0]:
                peak[0] = max(peak[0], proc.memory_info().rss)
                time.sleep(0.05)   # sample every 50 ms

        gc.collect()
        t = threading.Thread(target=sampler, daemon=True)
        t.start()

        # Simulate the dashboard listing all findings — this is where peak
        # memory is actually observed (Pydantic hydrates every row).
        _ = db.get_findings()

        running[0] = False
        t.join(timeout=1)

        peak_mb = peak[0] / 1024 / 1024
        note = "Largest run" if n == max(DATASET_SIZES) else ""
        rows.append([n, f"{peak_mb:.1f}", note])
        print(f"  n = {n:>3}  peak RSS = {peak_mb:.1f} MB")

    _write_csv(
        "E4_memory_footprint",
        ["Dataset Size (findings)", "Peak RSS (MB)", "Notes"],
        rows,
    )
    print(f"\n  → wrote {RESULTS_DIR}/E4_memory_footprint.csv")


# ============================================================================
# E5 — Database query time
# ============================================================================
def _random_finding_row(i: int) -> tuple:
    severity = random.choice(["Critical", "High", "Medium", "Low", "Info"])
    source = random.choice(["prowler", "wazuh", "vpcflow"])
    resource = (f"arn:aws:{random.choice(['s3', 'ec2', 'iam'])}::" +
                "".join(random.choices(string.ascii_lowercase, k=8)))
    ts = (datetime.utcnow() - timedelta(minutes=i)).isoformat()
    return (
        f"bench-{i:07d}",
        "misconfig",
        source, severity,
        f"Benchmark finding {i}",
        "Synthetic row for E5.",
        resource, "123456789012", "ap-southeast-1",
        "check.bench.1", "[]", "{}", ts, "new",
    )


def run_e5() -> None:
    print("\n[E5] Database query time")

    QUERIES = {
        "Filter by severity":
            "SELECT * FROM findings WHERE severity = 'High'",
        "Filter by source":
            "SELECT * FROM findings WHERE source = 'prowler'",
        "Search by resource name (substring)":
            "SELECT * FROM findings WHERE resource LIKE '%s3%'",
    }

    rows: dict[str, list[str]] = {q: [] for q in QUERIES}

    for n in DB_ROW_COUNTS:
        print(f"\n  Seeding {n:,} rows...")
        db_path = RESULTS_DIR / f"e5_{n}.db"
        if db_path.exists():
            db_path.unlink()
        Database(db_path=db_path)   # let it create schema
        conn = sqlite3.connect(db_path)
        conn.executemany(
            "INSERT INTO findings (finding_id, finding_type, source, severity, "
            "title, description, resource, account_id, region, check_id, "
            "compliance, raw_evidence, timestamp, status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [_random_finding_row(i) for i in range(n)],
        )
        conn.commit()

        for label, sql in QUERIES.items():
            samples: list[float] = []
            for it in range(WARMUP_ITERS + MEASURED_ITERS):
                t0 = time.perf_counter()
                conn.execute(sql).fetchall()
                elapsed = time.perf_counter() - t0
                if it >= WARMUP_ITERS:
                    samples.append(elapsed)
            mean_ms = statistics.mean(samples) * 1000
            rows[label].append(f"{mean_ms:.2f}")
            print(f"    {label:<40}  n={n:>6,}: {mean_ms:>8.2f} ms")

        conn.close()

    _write_csv(
        "E5_db_query_time",
        ["Query"] + [f"{n:,} rows (ms)" for n in DB_ROW_COUNTS],
        [[label, *vals] for label, vals in rows.items()],
    )
    print(f"\n  → wrote {RESULTS_DIR}/E5_db_query_time.csv")


# ============================================================================
# E6 — Ingestion time per collection module
# ============================================================================
def run_e6(prowler_sample: Optional[str] = None,
           wazuh: bool = False,
           vpcflow: bool = False,
           vpc_bucket: str = "") -> None:
    print("\n[E6] Ingestion time per collection module")

    rows: list[list] = []

    # --- Prowler ---
    if prowler_sample:
        if not Path(prowler_sample).exists():
            print(f"  ! Prowler sample not found: {prowler_sample}")
        else:
            rows.append(_measure_prowler(prowler_sample))
    else:
        print("  (skipping Prowler — pass --prowler-sample path/to/file.json)")

    # --- Wazuh ---
    if wazuh:
        rows.append(_measure_wazuh())
    else:
        print("  (skipping Wazuh — pass --wazuh to run against your live Wazuh)")

    # --- VPC ---
    if vpcflow:
        if not vpc_bucket:
            print("  ! --vpcflow requires --vpc-bucket <bucket-name>")
        else:
            rows.append(_measure_vpcflow(vpc_bucket))
    else:
        print("  (skipping VPC Flow Log — pass --vpcflow --vpc-bucket <name>)")

    if not rows:
        print("\n  No modules measured. Provide --prowler-sample / --wazuh / --vpcflow.")
        return

    _write_csv(
        "E6_ingestion_time",
        ["Module", "Sample Size", "Mean Ingestion Time (s)",
         "Std. Dev. (s)", "Findings Produced"],
        rows,
    )
    print(f"\n  → wrote {RESULTS_DIR}/E6_ingestion_time.csv")


def _measure_prowler(sample_path: str) -> list:
    print(f"\n  Prowler ingestion (sample = {sample_path})")
    from prowler_module.scanner import ProwlerScanner

    file_size_kb = Path(sample_path).stat().st_size / 1024
    samples: list[float] = []
    counts: list[int] = []

    for it in range(WARMUP_ITERS + MEASURED_ITERS):
        db = _fresh_db("e6_prowler")
        scanner = ProwlerScanner(db=db)
        t0 = time.perf_counter()
        try:
            n_findings = scanner.ingest_file(sample_path)
        except Exception as e:  # noqa: BLE001
            print(f"    iter {it + 1}: ERROR {type(e).__name__}: {e}")
            continue
        elapsed = time.perf_counter() - t0
        tag = "measured" if it >= WARMUP_ITERS else "warmup"
        print(f"    iter {it + 1:>2}: {elapsed:.3f}s, {n_findings} findings ({tag})")
        if it >= WARMUP_ITERS:
            samples.append(elapsed)
            counts.append(n_findings)

    mean, std = _mean_std(samples)
    avg_findings = int(statistics.mean(counts)) if counts else 0
    print(f"    → mean = {mean:.3f}s, std = {std:.3f}s, "
          f"avg findings = {avg_findings}")
    return ["Prowler", f"{file_size_kb:.1f} KB OCSF JSON",
            f"{mean:.3f}", f"{std:.3f}", str(avg_findings)]


def _measure_wazuh() -> list:
    """
    Run only the Wazuh step of the pipeline against your live Wazuh server.
    Reads Wazuh credentials from user_settings (whatever Settings page saved).
    """
    print("\n  Wazuh ingestion (live Wazuh server)")
    from orchestrator.pipeline import build_config_from_user_settings

    samples: list[float] = []
    counts: list[int] = []

    # Load full config from settings, then disable everything except Wazuh
    for it in range(WARMUP_ITERS + MEASURED_ITERS):
        base_cfg = build_config_from_user_settings()
        base_cfg.prowler_enabled = False
        base_cfg.vpcflow_enabled = False
        base_cfg.ai_enabled = False
        base_cfg.correlate_enabled = False
        base_cfg.wazuh_enabled = True

        db = _fresh_db("e6_wazuh")
        orch = Orchestrator(db=db)
        t0 = time.perf_counter()
        result = orch.run(base_cfg)
        elapsed = time.perf_counter() - t0

        # Pull Wazuh step duration from the pipeline result (more accurate)
        wazuh_step = next((s for s in result.steps
                           if "wazuh" in s.name.lower()), None)
        step_time = wazuh_step.duration_s if wazuh_step else elapsed
        n_findings = db.stats().get("total", 0)

        tag = "measured" if it >= WARMUP_ITERS else "warmup"
        print(f"    iter {it + 1:>2}: step={step_time:.3f}s, "
              f"{n_findings} findings ({tag})")
        if it >= WARMUP_ITERS:
            samples.append(step_time)
            counts.append(n_findings)

    mean, std = _mean_std(samples)
    avg_findings = int(statistics.mean(counts)) if counts else 0
    print(f"    → mean = {mean:.3f}s, std = {std:.3f}s, "
          f"avg findings = {avg_findings}")
    return ["Wazuh", f"{avg_findings} alerts (from Wazuh API)",
            f"{mean:.3f}", f"{std:.3f}", str(avg_findings)]


def _measure_vpcflow(bucket: str) -> list:
    print(f"\n  VPC Flow Log ingestion (bucket = {bucket})")
    from orchestrator.pipeline import build_config_from_user_settings

    samples: list[float] = []
    counts: list[int] = []

    for it in range(WARMUP_ITERS + MEASURED_ITERS):
        base_cfg = build_config_from_user_settings()
        base_cfg.prowler_enabled = False
        base_cfg.wazuh_enabled = False
        base_cfg.ai_enabled = False
        base_cfg.correlate_enabled = False
        base_cfg.vpcflow_enabled = True
        base_cfg.vpcflow_bucket = bucket
        # Reset state each iteration so it re-reads the same files
        base_cfg.vpcflow_reset_state = True

        db = _fresh_db("e6_vpcflow")
        orch = Orchestrator(db=db)
        t0 = time.perf_counter()
        result = orch.run(base_cfg)
        elapsed = time.perf_counter() - t0

        vpc_step = next((s for s in result.steps
                         if "vpc" in s.name.lower()), None)
        step_time = vpc_step.duration_s if vpc_step else elapsed
        n_findings = db.stats().get("total", 0)

        tag = "measured" if it >= WARMUP_ITERS else "warmup"
        print(f"    iter {it + 1:>2}: step={step_time:.3f}s, "
              f"{n_findings} findings ({tag})")
        if it >= WARMUP_ITERS:
            samples.append(step_time)
            counts.append(n_findings)

    mean, std = _mean_std(samples)
    avg_findings = int(statistics.mean(counts)) if counts else 0
    print(f"    → mean = {mean:.3f}s, std = {std:.3f}s, "
          f"avg findings = {avg_findings}")
    return ["VPC Flow Log Collector",
            f"{avg_findings} findings (from S3)",
            f"{mean:.3f}", f"{std:.3f}", str(avg_findings)]


# ============================================================================
# CLI
# ============================================================================
def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("metric", choices=["all", "e1", "e4", "e5", "e6"],
                        help="Which metric to run.")
    parser.add_argument("--prowler-sample", default=None,
                        help="Path to Prowler OCSF JSON sample (for E6).")
    parser.add_argument("--wazuh", action="store_true",
                        help="Include Wazuh in E6 (uses live Wazuh from settings).")
    parser.add_argument("--vpcflow", action="store_true",
                        help="Include VPC Flow Log in E6.")
    parser.add_argument("--vpc-bucket", default="",
                        help="S3 bucket name for VPC Flow Log ingestion.")
    args = parser.parse_args()

    print("=" * 60)
    print(f"Benchmark run: {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"Results dir  : {RESULTS_DIR.resolve()}")
    print(f"Iterations   : {WARMUP_ITERS} warmup + {MEASURED_ITERS} measured")
    print("=" * 60)

    start = time.time()

    if args.metric in ("all", "e1"):
        run_e1()
    if args.metric in ("all", "e4"):
        run_e4()
    if args.metric in ("all", "e5"):
        run_e5()
    if args.metric in ("e6",):
        run_e6(
            prowler_sample=args.prowler_sample,
            wazuh=args.wazuh,
            vpcflow=args.vpcflow,
            vpc_bucket=args.vpc_bucket,
        )
    elif args.metric == "all":
        print("\n[E6] skipped — run with `python benchmark.py e6 --wazuh --vpcflow "
              "--vpc-bucket X --prowler-sample Y.json`")

    elapsed = time.time() - start
    print("\n" + "=" * 60)
    print(f"Done. Total elapsed: {elapsed:.1f}s")
    print(f"CSVs in: {RESULTS_DIR.resolve()}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
