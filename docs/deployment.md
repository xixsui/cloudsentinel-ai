# Deployment guide (trusted local lab)

## Offline demo

Follow [README Quick Start](../README.md#quick-start--offline-demo-no-aws-credentials-or-llm-key). Run `python -m mock_data.generate` before Streamlit. Set `CLOUDSENTINEL_DEMO=1` to prevent the homepage from querying AWS inventory. No cloud access is required to inspect stored synthetic findings.

## AWS / Prowler

Use an AWS role or read-only identity scoped to the services being assessed. Grant only necessary permissions to list/read CloudTrail and VPC Flow Log S3 buckets; a wide admin role is unnecessary and dangerous. Prowler executable must already be installed and on PATH for fresh scans. You can ingest an exported `.ocsf.json` without AWS by configuring the Settings page to import an existing report. Fresh scans write to unique ignored `prowler-scans/output/run-...` folders.

## Wazuh HTTPS

Install the indexer certificate's private CA and point the app to its PEM file if the Wazuh server uses a self-signed or private CA certificate. Never disable TLS verification. Wazuh manager API and indexer are separate interfaces: this implementation queries the **indexer** on its OpenSearch endpoint.

```bash
export WAZUH_INDEXER_PASSWORD='your-password'
export WAZUH_CA_BUNDLE='/private/path/to/wazuh-ca.pem'
python -m siem_module.wazuh_cli --ca-bundle "$WAZUH_CA_BUNDLE" test
```

The Settings page stores the host, username and CA bundle path in config, but stores **no plaintext password**. Add the password in your OS Keyring, or export `WAZUH_INDEXER_PASSWORD`. Certificate validation is enabled by default.

## AI providers and third-party data

Set `GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` or `GROQ_API_KEY` in the environment (or save via the desktop Settings page to an OS Keyring). Only choose approved providers for data allowed to leave your environment. External model calls are opt-in through pipeline configuration and may generate cost.

## Windows vs Linux

PowerShell: `py -3 -m venv venv`, `.\\venv\\Scripts\\Activate.ps1`, `pip install -r requirements.txt`, `streamlit run dashboard/app.py`. On Linux/macOS, existing `setup.sh` / `start.sh` handle installation and startup. Use `HOST=127.0.0.1` unless secure network controls and authentication are added.

## Migrating from the FYP version

The original `~/.fyp-ai-cloud-sec/config.json` may contain obfuscated API keys and a plaintext Wazuh password. When settings load in this version, the legacy secret fields are scrubbed and the legacy keys become unavailable by design. **Back up any necessary non-secret configuration first; re-enter credentials in OS Keyring or env**. Rotate any secrets that have ever been committed to a repository. Delete the old `.salt` file after updating credentials.
