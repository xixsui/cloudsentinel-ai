"""Session-scoped AWS identity and Prowler subprocess authentication.

AWS keys are never persisted by this module; optional encrypted storage is managed by the local API. No process-global env mutation.
This module is for a trusted, single-operator local deployment only.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from dataclasses import dataclass, field

REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-\d+$")
PROFILE_RE = re.compile(r"^[\w.+@-]{1,128}$")
SUPPORTED_MODES = frozenset({"default", "profile", "temporary", "access_key"})
REGION_CHOICES = (
    "ap-southeast-1", "ap-southeast-5", "ap-southeast-2", "ap-southeast-3",
    "ap-southeast-4", "ap-northeast-1", "ap-northeast-2", "ap-south-1",
    "us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1",
    "eu-central-1", "ap-east-1",
)



@dataclass(frozen=True)
class AWSConnection:
    mode: str = "default"  # default IAM role / env chain, profile, temporary
    region: str = "ap-southeast-1"
    profile: str = ""
    access_key_id: str = field(default="", repr=False)
    secret_access_key: str = field(default="", repr=False)
    session_token: str = field(default="", repr=False)
    expires_at: str = ""

    def __post_init__(self) -> None:
        if self.expires_at:
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            if self.mode != "temporary" or expiry.tzinfo is None:
                raise ValueError("Expiration requires temporary credentials and a timezone")
        if self.mode not in SUPPORTED_MODES:
            raise ValueError("Unsupported AWS authentication mode")
        if not REGION_RE.fullmatch(self.region):
            raise ValueError("Invalid AWS region")
        if self.mode == "profile" and not PROFILE_RE.fullmatch(self.profile):
            raise ValueError("Invalid AWS profile name")
        if self.mode == "access_key":
            if not self.access_key_id.startswith("AKIA") or not self.secret_access_key or self.session_token:
                raise ValueError("Access Key mode requires a long-term access key and secret without a session token")
        if self.mode == "temporary":
            if not (self.access_key_id and self.secret_access_key and self.session_token):
                raise ValueError("All three temporary credential fields are required")
            if not self.access_key_id.startswith(("ASIA", "AKIA")):
                raise ValueError("AWS access key ID format is invalid")

    def session(self):
        import boto3
        if self.mode == "profile":
            return boto3.Session(profile_name=self.profile, region_name=self.region)
        if self.mode in ("temporary", "access_key"):
            return boto3.Session(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                aws_session_token=self.session_token or None,
                region_name=self.region,
            )
        return boto3.Session(region_name=self.region)

    def subprocess_env(self, base: dict[str, str] | None = None) -> dict[str, str]:
        """Child-only AWS auth. Remove inherited conflicting creds for profile mode."""
        env = dict(os.environ if base is None else base)
        if self.mode == "profile":
            for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                      "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
                      "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_SESSION_NAME",
                      "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI"):
                env.pop(k, None)
            env["AWS_PROFILE"] = self.profile
        elif self.mode in ("temporary", "access_key"):
            for k in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN",
                      "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_SESSION_NAME",
                      "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI"):
                env.pop(k, None)
            env.pop("AWS_SECURITY_TOKEN", None)
            env.update({
                "AWS_ACCESS_KEY_ID": self.access_key_id,
                "AWS_SECRET_ACCESS_KEY": self.secret_access_key,
                "AWS_SESSION_TOKEN": self.session_token,
            })
            if self.mode == "access_key":
                env.pop("AWS_SESSION_TOKEN", None)
        env["AWS_DEFAULT_REGION"] = self.region
        env["AWS_REGION"] = self.region
        # Do not attach Prowler to an uncontrolled metadata endpoint when
        # explicit creds are expected. Role-based mode retains SDK defaults.
        if self.mode != "default":
            env["AWS_EC2_METADATA_DISABLED"] = "true"
        return env

    def test_identity(self) -> dict[str, str]:
        """Call the AWS STS identity endpoint; this is not a permissions audit."""
        if self.credentials_expired:
            raise ValueError("Temporary credentials have reached the supplied expiration. Renew them before connecting.")
        from botocore.config import Config
        sts = self.session().client("sts", config=Config(
            connect_timeout=5, read_timeout=10,
            retries={"max_attempts": 2, "mode": "standard"},
        ))
        result = sts.get_caller_identity()
        return {k: str(result[k]) for k in ("Account", "Arn", "UserId")}

    @property
    def credentials_expired(self) -> bool:
        return bool(self.expires_at and datetime.fromisoformat(self.expires_at.replace("Z", "+00:00")) <= datetime.now(timezone.utc))

    @property
    def label(self) -> str:
        return {"default": "IAM Role / Environment", "profile": f"Profile: {self.profile}",
                "access_key": "Access Key", "temporary": "Temporary session credentials"}[self.mode]
