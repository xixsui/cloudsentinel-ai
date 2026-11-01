"""
CLI entry point for the Prowler integration.

Usage:
    # 1. Parse an existing Prowler JSON-OCSF file into the DB (no AWS needed):
    python -m prowler_module.cli ingest path/to/scan.ocsf.json

    # 2. Run a fresh Prowler scan and ingest its output (needs aws credentials):
    python -m prowler_module.cli scan
    python -m prowler_module.cli scan --output-dir ./prowler-scans/output --prefix scan
"""

from __future__ import annotations

import argparse
import logging
import sys

from prowler_module.scanner import ProwlerScanner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)


def main() -> int:
    p = argparse.ArgumentParser(prog="prowler_module", description="Prowler -> DB pipeline")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_ingest = sub.add_parser("ingest", help="Ingest an existing Prowler OCSF JSON file")
    p_ingest.add_argument("file", help="Path to *.ocsf.json")

    p_scan = sub.add_parser("scan", help="Run prowler then ingest output")
    p_scan.add_argument("--output-dir", default="./prowler-scans/output")
    p_scan.add_argument("--prefix", default="scan")
    p_scan.add_argument("--provider", default="aws")
    p_scan.add_argument("--extra", nargs="*", default=[], help="Extra args passed to prowler")

    args = p.parse_args()
    scanner = ProwlerScanner()

    if args.cmd == "ingest":
        n = scanner.ingest_file(args.file)
        print(f"Ingested {n} FAIL findings.")
        return 0

    if args.cmd == "scan":
        n = scanner.run_and_ingest(
            output_dir=args.output_dir,
            file_prefix=args.prefix,
            provider=args.provider,
            extra_args=args.extra,
        )
        print(f"Scan complete. Ingested {n} FAIL findings.")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
