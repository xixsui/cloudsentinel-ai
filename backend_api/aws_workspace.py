"""Explicit, process-local AWS connection and asynchronous read-only inventory."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import RLock
import copy

from botocore.config import Config
from cloud_connection.aws import AWSConnection
from config import ai_preferences
import os
from backend_api.aws_errors import explain

_lock = RLock()
_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="aws-inventory")
_connection = None
_identity = None
_generation = 0
_future = None
_snapshot = None
_loading = False


def status():
    with _lock:
        return {"connected": _connection is not None and not _connection.credentials_expired, "identity": copy.deepcopy(_identity),
                "expires_at": (_connection.expires_at or None) if _connection else None,
                "credentials_expired": _connection.credentials_expired if _connection else False,
                "region": _connection.region if _connection else None,
                "mode": _connection.mode if _connection else None,
                "saved_access_key": bool(ai_preferences.load().get("aws_access_key")),
                "storage_supported": os.name == "posix",
                "loading": _loading, "snapshot": copy.deepcopy(_snapshot)}


def connect(connection: AWSConnection, *, persist=False):
    # Verify before replacing a working connection. Never expose SDK exception text.
    identity = connection.test_identity()
    if persist:
        if connection.mode != "access_key":
            raise ValueError("Only Access Key credentials can be saved")
        with ai_preferences.edit() as state:
            state["aws_access_key"] = {"region": connection.region, "access_key_id": connection.access_key_id, "secret_access_key": connection.secret_access_key}
    global _connection, _identity, _generation, _snapshot, _loading
    with _lock:
        _connection, _identity = connection, identity
        _generation += 1
        _snapshot, _loading = None, False
    return status()


def disconnect():
    global _connection, _identity, _generation, _snapshot, _loading
    with _lock:
        _connection = _identity = _snapshot = None
        _loading = False
        _generation += 1
    return status()


def collect(connection, identity):
    session = connection.session()
    resources, errors, truncated = [], [], []
    config = Config(connect_timeout=3, read_timeout=5, retries={"max_attempts": 1})
    # Regional services use the selected region; IAM and S3 are account-wide.
    specs = [
        ("EC2", "ec2", "describe_instances", "Reservations", "Instances", "InstanceId", "InstanceId"),
        ("S3", "s3", "list_buckets", "Buckets", None, "Name", "Name"),
        ("IAM Users", "iam", "list_users", "Users", None, "UserName", "Arn"),
        ("IAM Roles", "iam", "list_roles", "Roles", None, "RoleName", "Arn"),
        ("VPC", "ec2", "describe_vpcs", "Vpcs", None, "VpcId", "VpcId"),
        ("Security Groups", "ec2", "describe_security_groups", "SecurityGroups", None, "GroupName", "GroupId"),
        ("RDS", "rds", "describe_db_instances", "DBInstances", None, "DBInstanceIdentifier", "DBInstanceArn"),
        ("Lambda", "lambda", "list_functions", "Functions", None, "FunctionName", "FunctionArn"),
        ("CloudTrail", "cloudtrail", "describe_trails", "trailList", None, "Name", "TrailARN"),
    ]
    for label, service, operation, key, nested, name, resource_id in specs:
        try:
            client = session.client(service, config=config)
            pages = client.get_paginator(operation).paginate() if client.can_paginate(operation) else [getattr(client, operation)()]
            count = 0
            for page in pages:
                rows = page.get(key, [])
                if nested:
                    rows = [item for row in rows for item in row.get(nested, [])]
                for row in rows:
                    if count >= 1000:
                        break
                    state = row.get("State", row.get("DBInstanceStatus", ""))
                    if isinstance(state, dict):
                        state = state.get("Name", "")
                    resources.append({"service": label, "name": row.get(name, ""),
                                      "id": row.get(resource_id, row.get(name, "")),
                                      "region": "account-wide" if service in ("s3", "iam") else connection.region,
                                      "state": state})
                    count += 1
                if count >= 1000:
                    truncated.append(label)
                    break
        except Exception as exc:
            errors.append(f"{label} ({service}:{''.join(part.title() for part in operation.split('_'))}): {explain(exc)}")
    return {"account": identity["Account"], "region": connection.region,
            "fetched_at": datetime.now(timezone.utc).isoformat(), "resources": resources,
            "errors": errors, "truncated": truncated}


def refresh():
    global _loading, _future
    with _lock:
        if _connection is None or _connection.credentials_expired:
            raise ValueError("Connect AWS in Settings first")
        if _loading:
            return status()
        if _future is not None and not _future.done():
            raise ValueError("A previous inventory request is finishing. Try again shortly.")
        connection, identity, generation = _connection, _identity, _generation
        _loading = True

        def run():
            global _snapshot, _loading
            try:
                snapshot = collect(connection, identity)
            except Exception:
                snapshot = {"account": identity["Account"], "region": connection.region,
                            "fetched_at": datetime.now(timezone.utc).isoformat(), "resources": [],
                            "errors": ["AWS inventory unavailable. Reconnect in Settings and try again."], "truncated": []}
            with _lock:
                if generation == _generation:
                    _snapshot, _loading = snapshot, False
        _future = _pool.submit(run)
        return status()


def connect_saved():
    saved = ai_preferences.load().get("aws_access_key")
    if not saved:
        raise ValueError("No saved AWS Access Key")
    return connect(AWSConnection(mode="access_key", **saved))


def remove_saved():
    with ai_preferences.edit() as state:
        state.pop("aws_access_key", None)
    return disconnect()


def scan_connection():
    with _lock:
        if _connection is None or _identity is None or _connection.credentials_expired:
            raise ValueError("Connect AWS in Settings first")
        return _connection, _identity["Account"]
