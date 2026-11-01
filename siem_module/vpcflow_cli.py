"""
CLI for the VPC Flow Logs collector.

Examples:
    # Pull from your bucket
    python -m siem_module.vpcflow_cli pull --bucket fyp-vpcflowlogs-s3

    # Reprocess everything (ignore state file)
    python -m siem_module.vpcflow_cli pull --bucket fyp-vpcflowlogs-s3 --reset

    # Tune detection thresholds (testing with quiet traffic)
    python -m siem_module.vpcflow_cli pull --bucket fyp-vpcflowlogs-s3 \\
        --reject-threshold 5 --sweep-threshold 5 --sensitive-threshold 3
"""

from __future__ import annotations

import argparse
import logging
import sys

from siem_module.vpcflow_collector import RuleConfig, VPCFlowCollector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)


def main() -> int:
    p = argparse.ArgumentParser(prog="siem_module.vpcflow_cli",
                                description="VPC Flow Logs → DB collector")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_pull = sub.add_parser("pull", help="Pull new Flow Log files and detect patterns")
    p_pull.add_argument("--bucket", required=True, help="S3 bucket holding the flow logs")
    p_pull.add_argument("--region", default="ap-southeast-1")
    p_pull.add_argument("--prefix", default=None,
                        help="Optional S3 key prefix to narrow the scan "
                             "(e.g. 'AWSLogs/123456789012/vpcflowlogs/ap-southeast-1/2026/')")
    p_pull.add_argument("--max-files", type=int, default=50,
                        help="Process at most N new files per run (default 50)")
    p_pull.add_argument("--reset", action="store_true",
                        help="Ignore the state file and reprocess everything")
    p_pull.add_argument("--reject-threshold", type=int, default=20)
    p_pull.add_argument("--sweep-threshold", type=int, default=15)
    p_pull.add_argument("--sensitive-threshold", type=int, default=5)

    args = p.parse_args()

    if args.cmd == "pull":
        collector = VPCFlowCollector(
            bucket=args.bucket,
            region=args.region,
            rules=RuleConfig(
                reject_storm_threshold=args.reject_threshold,
                port_sweep_threshold=args.sweep_threshold,
                sensitive_port_attempts=args.sensitive_threshold,
            ),
        )
        n = collector.pull_logs(
            prefix=args.prefix,
            max_files=args.max_files,
            reset_state=args.reset,
        )
        print(f"Wrote {n} finding(s).")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
