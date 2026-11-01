"""
AWS Inventory — list resources in the connected AWS account so the dashboard
can show what's actually being monitored.

This is read-only (uses the same fyp-scanner credentials Prowler/Wazuh use)
and cached so we don't re-call AWS APIs on every dashboard rerun.

Each resource is annotated with a "findings_count" pulled from the local DB
so the UI can highlight which resources have problems.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ai_module.database import Database

logger = logging.getLogger("aws_inventory")


@dataclass
class Resource:
    service: str          # e.g. "EC2", "S3", "IAM"
    type: str             # e.g. "Instance", "Bucket", "User"
    name: str             # display name or ID
    arn_or_id: str        # canonical identifier
    region: str = ""
    state: str = ""       # e.g. "running", "stopped", "active"
    findings_count: int = 0  # joined from DB
    extra: dict = field(default_factory=dict)


@dataclass
class InventorySnapshot:
    fetched_at: datetime
    region: str
    resources: list[Resource]
    errors: list[str] = field(default_factory=list)  # service-by-service errors

    @property
    def by_service(self) -> dict[str, list[Resource]]:
        out: dict[str, list[Resource]] = {}
        for r in self.resources:
            out.setdefault(r.service, []).append(r)
        return out

    @property
    def total(self) -> int:
        return len(self.resources)

    def stats(self) -> dict[str, int]:
        """Service-level counts for compact display."""
        return {svc: len(rs) for svc, rs in self.by_service.items()}


# ---------------------------------------------------------------------------
# Legacy cache placeholder; callers now cache snapshots in Streamlit session state.
# ---------------------------------------------------------------------------
_CACHE: dict[tuple[str, str], tuple[datetime, InventorySnapshot]] = {}
_CACHE_TTL = timedelta(minutes=10)


class AWSInventory:
    """Collect a snapshot of resources across common AWS services."""

    def __init__(self, region: str = "ap-southeast-1", db: Optional[Database] = None,
                 session=None, account_id: str = ""):
        self.region = region
        self.db = db
        self.account_id = account_id
        # Never pick up implicit credentials from the Streamlit server here.
        # The calling page must pass its explicitly verified session.
        self.session = session
        self.available = session is not None and bool(account_id)
        self.error_msg = "AWS connection not verified in this dashboard session"

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #
    def fetch(self, force_refresh: bool = False) -> InventorySnapshot:
        snapshot = InventorySnapshot(
            fetched_at=datetime.utcnow(),
            region=self.region,
            resources=[],
        )

        if not self.available:
            snapshot.errors.append("AWS is not connected")
            return snapshot

        # Each service in its own try/except so one failure doesn't break others.
        for fn in (self._fetch_ec2, self._fetch_s3, self._fetch_iam_users,
                   self._fetch_iam_roles, self._fetch_vpc, self._fetch_security_groups,
                   self._fetch_rds, self._fetch_lambda, self._fetch_cloudtrail):
            try:
                snapshot.resources.extend(fn())
            except (BotoCoreError, ClientError) as e:
                err = f"{fn.__name__}: {type(e).__name__}: {e}"
                snapshot.errors.append(err)
                logger.warning(err)
            except Exception as e:  # noqa: BLE001
                snapshot.errors.append(f"{fn.__name__}: {e}")
                logger.exception("Inventory step failed: %s", fn.__name__)

        # Join with local DB to get findings_count per resource
        self._annotate_findings(snapshot)

        # Caller owns per-session caching. Never cache cross-account resources
        # in a process-global dict shared by different browser sessions.
        return snapshot

    # ------------------------------------------------------------------ #
    # Per-service collectors
    # ------------------------------------------------------------------ #
    def _fetch_ec2(self) -> list[Resource]:
        ec2 = self.session.client("ec2")
        out: list[Resource] = []
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    name = next((t["Value"] for t in inst.get("Tags", [])
                                 if t["Key"] == "Name"), inst["InstanceId"])
                    out.append(Resource(
                        service="EC2",
                        type="Instance",
                        name=name,
                        arn_or_id=inst["InstanceId"],
                        region=self.region,
                        state=inst.get("State", {}).get("Name", "unknown"),
                        extra={
                            "type": inst.get("InstanceType", ""),
                            "public_ip": inst.get("PublicIpAddress", ""),
                            "private_ip": inst.get("PrivateIpAddress", ""),
                        },
                    ))
        return out

    def _fetch_s3(self) -> list[Resource]:
        # S3 buckets are global but listed here. Region per bucket via location.
        s3 = self.session.client("s3")
        out: list[Resource] = []
        for b in s3.list_buckets().get("Buckets", []):
            try:
                loc = s3.get_bucket_location(Bucket=b["Name"])
                bucket_region = loc.get("LocationConstraint") or "us-east-1"
            except ClientError:
                bucket_region = "?"
            out.append(Resource(
                service="S3",
                type="Bucket",
                name=b["Name"],
                arn_or_id=f"arn:aws:s3:::{b['Name']}",
                region=bucket_region,
                state="active",
                extra={"created": b.get("CreationDate", "").isoformat()
                       if b.get("CreationDate") else ""},
            ))
        return out

    def _fetch_iam_users(self) -> list[Resource]:
        iam = self.session.client("iam")
        out: list[Resource] = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                out.append(Resource(
                    service="IAM",
                    type="User",
                    name=u["UserName"],
                    arn_or_id=u["Arn"],
                    region="global",
                    state="active",
                    extra={"created": u.get("CreateDate", "").isoformat()
                           if u.get("CreateDate") else ""},
                ))
        return out

    def _fetch_iam_roles(self) -> list[Resource]:
        iam = self.session.client("iam")
        out: list[Resource] = []
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page.get("Roles", []):
                # Skip AWS service-linked roles (noisy)
                if r.get("Path", "").startswith("/aws-service-role/"):
                    continue
                out.append(Resource(
                    service="IAM",
                    type="Role",
                    name=r["RoleName"],
                    arn_or_id=r["Arn"],
                    region="global",
                    state="active",
                ))
        return out

    def _fetch_vpc(self) -> list[Resource]:
        ec2 = self.session.client("ec2")
        out: list[Resource] = []
        for v in ec2.describe_vpcs().get("Vpcs", []):
            name = next((t["Value"] for t in v.get("Tags", []) if t["Key"] == "Name"),
                        v["VpcId"])
            out.append(Resource(
                service="VPC",
                type="VPC",
                name=name,
                arn_or_id=v["VpcId"],
                region=self.region,
                state=v.get("State", "unknown"),
                extra={"cidr": v.get("CidrBlock", ""),
                       "default": v.get("IsDefault", False)},
            ))
        return out

    def _fetch_security_groups(self) -> list[Resource]:
        ec2 = self.session.client("ec2")
        out: list[Resource] = []
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            out.append(Resource(
                service="VPC",
                type="SecurityGroup",
                name=sg["GroupName"],
                arn_or_id=sg["GroupId"],
                region=self.region,
                state="active",
                extra={
                    "vpc": sg.get("VpcId", ""),
                    "description": sg.get("Description", ""),
                },
            ))
        return out

    def _fetch_rds(self) -> list[Resource]:
        rds = self.session.client("rds")
        out: list[Resource] = []
        try:
            for db in rds.describe_db_instances().get("DBInstances", []):
                out.append(Resource(
                    service="RDS",
                    type="DBInstance",
                    name=db["DBInstanceIdentifier"],
                    arn_or_id=db["DBInstanceArn"],
                    region=self.region,
                    state=db.get("DBInstanceStatus", "unknown"),
                    extra={"engine": db.get("Engine", ""),
                           "class": db.get("DBInstanceClass", "")},
                ))
        except ClientError:
            pass
        return out

    def _fetch_lambda(self) -> list[Resource]:
        lam = self.session.client("lambda")
        out: list[Resource] = []
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for f in page.get("Functions", []):
                out.append(Resource(
                    service="Lambda",
                    type="Function",
                    name=f["FunctionName"],
                    arn_or_id=f["FunctionArn"],
                    region=self.region,
                    state=f.get("State", "active"),
                    extra={"runtime": f.get("Runtime", "")},
                ))
        return out

    def _fetch_cloudtrail(self) -> list[Resource]:
        ct = self.session.client("cloudtrail")
        out: list[Resource] = []
        for t in ct.describe_trails().get("trailList", []):
            out.append(Resource(
                service="CloudTrail",
                type="Trail",
                name=t["Name"],
                arn_or_id=t.get("TrailARN", t["Name"]),
                region=t.get("HomeRegion", self.region),
                state="active" if t.get("IsMultiRegionTrail") else "single-region",
                extra={"bucket": t.get("S3BucketName", "")},
            ))
        return out

    # ------------------------------------------------------------------ #
    # Annotate with local DB findings
    # ------------------------------------------------------------------ #
    def _annotate_findings(self, snapshot: InventorySnapshot) -> None:
        """Match each resource ARN/ID against findings.resource in the DB."""
        if self.db is None:
            return
        findings = self.db.get_findings()
        # Index by substring of resource for fast lookup
        for r in snapshot.resources:
            needle = r.arn_or_id.lower()
            r.findings_count = sum(
                1 for f in findings
                if needle and (needle in f.resource.lower()
                               or r.name.lower() in f.resource.lower())
            )
