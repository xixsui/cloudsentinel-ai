"""
CLI entry point for the Wazuh integration.

Examples:
    # Pull the last hour of Wazuh alerts (rule.level >= 6) into the DB
    python -m siem_module.wazuh_cli pull

    # Last 24 hours, only AWS-sourced alerts, lower threshold
    python -m siem_module.wazuh_cli pull --since 24h --min-level 3 --aws-only

    # Test the connection to the indexer
    python -m siem_module.wazuh_cli test
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from siem_module.wazuh_client import WazuhClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)


def _build_client(args: argparse.Namespace) -> WazuhClient:
    return WazuhClient(
        host=args.host,
        username=args.username,
        password=args.password,
        verify_ssl=args.ca_bundle or True,
    )


def main() -> int:
    p = argparse.ArgumentParser(prog="siem_module.wazuh_cli")
    p.add_argument("--host", default=os.getenv("WAZUH_INDEXER_HOST", "https://localhost:9200"))
    p.add_argument("--username", default=os.getenv("WAZUH_INDEXER_USER", "admin"))
    p.add_argument(
        "--password",
        default=os.getenv("WAZUH_INDEXER_PASSWORD", ""),
        help="Tip: set WAZUH_INDEXER_PASSWORD env var instead of putting it on the CLI.",
    )

    p.add_argument("--ca-bundle", default=os.getenv("WAZUH_CA_BUNDLE") or None,
                   help="Path to trusted CA PEM for a private Wazuh indexer certificate")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("test", help="Test connectivity to the Wazuh indexer")

    p_pull = sub.add_parser("pull", help="Pull alerts and ingest into the DB")
    p_pull.add_argument("--since", default="1h",
                        help="Time window: 15m / 1h / 24h / 7d (default 1h)")
    p_pull.add_argument("--min-level", type=int, default=6,
                        help="Skip Wazuh rule.level below this (default 6)")
    p_pull.add_argument("--max", type=int, default=500,
                        help="Cap on number of alerts pulled (default 500)")
    p_pull.add_argument("--aws-only", action="store_true",
                        help="Only pull alerts from the AWS integration")

    args = p.parse_args()
    client = _build_client(args)

    if args.cmd == "test":
        ok, msg = client.test()
        print(("✅ " if ok else "❌ ") + msg)
        return 0 if ok else 1

    if args.cmd == "pull":
        sources = ["aws"] if args.aws_only else None
        n = client.pull_alerts(
            since=args.since,
            min_rule_level=args.min_level,
            max_results=args.max,
            sources=sources,
        )
        print(f"Ingested {n} findings.")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
