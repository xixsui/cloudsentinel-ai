"""Local-only AWS onboarding. Secrets are held in this Streamlit session only."""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cloud_connection.aws import AWSConnection, REGION_CHOICES
from dashboard.theme import apply_theme, page_title, render_sidebar

st.set_page_config(page_title="Cloud Connections · CloudSentinel", layout="wide", page_icon="🔐")
apply_theme()
DEMO = os.getenv("CLOUDSENTINEL_DEMO", "").lower() in {"1", "true", "yes"}
render_sidebar()
page_title("Cloud Connections", subtitle="Connect safely, verify your AWS identity and configure scanning.", icon="ti-cloud-lock")

st.markdown('<div class="cs-eyebrow">INTEGRATION WORKSPACE <span class="cs-eyebrow-dot"></span> AWS CLOUD</div>', unsafe_allow_html=True)

col_a, col_b, col_c = st.columns(3)
with col_a:
    st.metric("Connection", "Demo only" if DEMO else ("Verified" if st.session_state.get("aws_identity") else "Not connected"))
with col_b:
    st.metric("Credential storage", "Session memory")
with col_c:
    st.metric("Operations", "Read-only scan")

if DEMO:
    st.info("**Offline demo is enabled.** AWS credential checks and live scanning are disabled. You can run a synthetic scan in **Scan Center** without an AWS account.")
    st.page_link("pages/5_Scan_Center.py", label="Open Scan Center →", icon="🛡️")
else:
    connected = st.session_state.get("aws_connection")
    identity = st.session_state.get("aws_identity")
    if connected is not None and identity:
        with st.container(border=True):
            st.markdown("#### Connected AWS identity")
            st.success(f"Verified with AWS STS at {st.session_state.get('aws_verified_at', 'this session')}. A successful STS request does **not** establish permission to run Prowler checks.")
            a,b = st.columns(2)
            a.metric("AWS account", identity["Account"])
            b.metric("Region", connected.region)
            st.caption("IAM principal ARN")
            st.code(identity["Arn"], language=None)
            st.caption(f"Authentication: {connected.label}. Credentials have not been written to a project config file or SQLite.")
            b1,b2 = st.columns(2)
            with b1:
                st.page_link("pages/5_Scan_Center.py", label="Configure a scan →", icon="🛡️")
            with b2:
                if st.button("Disconnect this session", use_container_width=True):
                    for k in ("aws_connection", "aws_identity", "aws_verified_at"):
                        st.session_state.pop(k, None)
                    st.rerun()

    st.markdown("#### Add or replace an AWS connection")
    st.caption("For production accounts, prefer an AWS IAM Role or SSO-backed profile with limited read permissions. Do not use root credentials or create access keys just for this dashboard.")

    auth_options = {
        "AWS profile / IAM Identity Center (recommended)": "profile",
        "IAM role / default environment credentials": "default",
        "Temporary STS credentials (session-only)": "temporary",
    }
    selected = st.radio("Authentication method", options=list(auth_options), horizontal=False)
    mode = auth_options[selected]

    with st.form("aws_connect", clear_on_submit=True):
        region = st.selectbox(
            "Default scan region", list(REGION_CHOICES),
            help="Choose the region containing your resources. Malaysia is ap-southeast-5 (opt-in). You can change it per scan.",
        )
        profile = access = secret = token = ""
        if mode == "profile":
            profiles = []
            try:
                import boto3
                profiles = boto3.Session().available_profiles
            except Exception:
                pass
            if profiles:
                st.caption("Detected profiles: " + ", ".join(profiles[:12]))
            profile = st.text_input("AWS profile name", placeholder="my-security-audit-profile", help="Profiles are configured with AWS CLI or IAM Identity Center before launching Streamlit.")
        elif mode == "temporary":
            st.warning("Use temporary STS credentials only. All three fields are required. They are retained in server session memory until disconnect or session expiry; never deploy this page publicly.")
            access = st.text_input("Access key ID", type="password", placeholder="ASIA…")
            secret = st.text_input("Secret access key", type="password")
            token = st.text_input("Session token", type="password")
        else:
            st.info("Uses the boto3 default credential chain (for example an EC2 instance role, task role or environment credentials). Set these up outside the app.")
        submitted = st.form_submit_button("Test AWS connection", type="primary", use_container_width=True)

    if submitted:
        # Invalidate old verified connection before attempting a new one.
        for k in ("aws_connection", "aws_identity", "aws_verified_at"):
            st.session_state.pop(k, None)
        try:
            conn = AWSConnection(mode=mode, region=region, profile=profile.strip(),
                                 access_key_id=access.strip(), secret_access_key=secret,
                                 session_token=token)
        except ValueError as exc:
            st.error(f"Check your connection inputs: {exc}")
        else:
            with st.spinner("Calling AWS STS GetCallerIdentity…"):
                try:
                    result = conn.test_identity()
                except Exception as exc:
                    # Do not print full SDK exception content, HTTP details or request data.
                    from botocore.exceptions import (ClientError, NoCredentialsError,
                                                     PartialCredentialsError, ProfileNotFound,
                                                     EndpointConnectionError)
                    if isinstance(exc, (NoCredentialsError, PartialCredentialsError, ProfileNotFound)):
                        message = "No usable credentials found. Check the AWS profile, role or environment."
                    elif isinstance(exc, EndpointConnectionError):
                        message = "Could not reach AWS STS. Check your network or region."
                    elif isinstance(exc, ClientError):
                        code = exc.response.get("Error", {}).get("Code", "ClientError")
                        message = f"AWS rejected the request ({code}). Check credentials, expiry or access policy."
                    else:
                        message = "Connection test failed. Check AWS SDK installation and local configuration."
                    st.error(message)
                else:
                    st.session_state["aws_connection"] = conn
                    st.session_state["aws_identity"] = result
                    st.session_state["aws_verified_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                    st.success("AWS identity verified. You can proceed to Scan Center.")
                    st.page_link("pages/5_Scan_Center.py", label="Open Scan Center →", icon="🛡️")

st.divider()
with st.expander("Security and permissions — important before connecting", expanded=False):
    st.markdown("""
- **Local, trusted operator only:** This prototype has no login, team RBAC, multi-tenant isolation or cross-user secret controls. Run on `127.0.0.1`; do not publish the Streamlit port to the internet.
- **Least privilege:** Use a dedicated, read-only identity with the permissions required by the enabled Prowler checks. STS identity validation is not a Prowler permission check.
- **Storage boundary:** This page does not write AWS credentials to disk. They remain in the Streamlit server's session state while connected and could remain in RAM during a background scan.
- **Secrets:** Do not upload `.aws/credentials`, IAM keys, or production scan output to a public GitHub repository.
- **Availability:** Sign in with your AWS CLI/SSO profile first; after SSO expires, re-authenticate and reconnect.
""")
