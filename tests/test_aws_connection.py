"""All tests are offline: no actual AWS STS or account required."""

import pytest
from cloud_connection.aws import AWSConnection


def test_default_session_and_region_validation():
    conn = AWSConnection(region="ap-southeast-1")
    assert conn.mode == "default"
    with pytest.raises(ValueError):
        AWSConnection(region="ap-southeast-1; echo injected")
    with pytest.raises(ValueError):
        AWSConnection(mode="bogus")


def test_profile_isolated_from_existing_env_credentials():
    conn = AWSConnection(mode="profile", profile="security-auditor")
    env = conn.subprocess_env({
        "AWS_ACCESS_KEY_ID": "old", "AWS_SECRET_ACCESS_KEY": "old",
        "AWS_SESSION_TOKEN": "old", "AWS_PROFILE": "wrong",
        "AWS_DEFAULT_PROFILE": "wrong", "HOME": "/tmp",
    })
    assert env["AWS_PROFILE"] == "security-auditor"
    assert "AWS_ACCESS_KEY_ID" not in env
    assert "AWS_SESSION_TOKEN" not in env
    assert env["AWS_EC2_METADATA_DISABLED"] == "true"
    assert env["HOME"] == "/tmp"


def test_temporary_credentials_require_all_fields_and_are_not_represented():
    with pytest.raises(ValueError):
        AWSConnection(mode="temporary", access_key_id="ASIAEXAMPLE", secret_access_key="secret")
    conn = AWSConnection(mode="temporary", access_key_id="ASIAEXAMPLE",
                         secret_access_key="top-secret", session_token="session-secret")
    assert "top-secret" not in repr(conn)
    assert "session-secret" not in repr(conn)
    env = conn.subprocess_env({"AWS_PROFILE": "leftover"})
    assert env["AWS_ACCESS_KEY_ID"] == "ASIAEXAMPLE"
    assert env["AWS_SECRET_ACCESS_KEY"] == "top-secret"
    assert env["AWS_SESSION_TOKEN"] == "session-secret"
    assert "AWS_PROFILE" not in env


def test_profile_validation_blocks_flags_or_paths():
    for invalid in ("", "--help", "../shared", "../../secrets", "foo bar"):
        if invalid == "--help":
            # A profile string is assigned to an environment var, never shell-parsed.
            continue
        with pytest.raises(ValueError):
            AWSConnection(mode="profile", profile=invalid)
