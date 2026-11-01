"""Unverified browser views must never silently read server-side AWS credentials."""

from dashboard.aws_inventory import AWSInventory


def test_inventory_requires_explicit_verified_connection(monkeypatch, tmp_path):
    import boto3

    def forbidden_implicit_session(*args, **kwargs):
        raise AssertionError("AWSInventory must not construct an implicit AWS session")

    monkeypatch.setattr(boto3, "Session", forbidden_implicit_session)
    inv = AWSInventory(region="ap-southeast-5")
    assert inv.available is False
    snap = inv.fetch()
    assert not snap.resources
    assert snap.errors == ["AWS is not connected"]
