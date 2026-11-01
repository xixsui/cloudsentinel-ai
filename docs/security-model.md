# Security model and data handling

**Intended deployment:** trusted local workstation or private lab, single analyst. The current dashboard has **no login/authentication or per-user authorization**, so keep it bound to `127.0.0.1`, behind a trusted tunnel if remote access is truly needed. Never put it directly on the public Internet.

**Secrets:** `config.json` is non-secret; API keys and the Wazuh password use environment variables or an OS Keyring. The legacy XOR/Base64 encoding was insecure and is no longer accepted. Re-enter your old keys and rotate any previously exposed secrets. Local `.env` is ignored by Git. On Linux headless servers, use protected environment injection rather than assuming a desktop keyring exists.

**Transport:** Wazuh indexer access requires HTTPS and validates the system trust store or a user-specified CA PEM. Old lab configurations using an untrusted self-signed certificate must install/trust their private CA. AWS connections are handled by AWS SDK credentials with TLS.

**Sensitive evidence:** Stored event bodies can contain AWS account IDs, ARN values, private/public IPs, log fragments and IAM metadata. They are **not anonymous**. LLM prompts may transmit pieces of this evidence to third-party services; only enable AI integration after checking your organization's data policies and redacting sensitive values. Avoid screenshots of production data in public repositories.

**Log injection:** CloudTrail/Wazuh event titles and raw evidence can contain attacker-controlled text. Model instructions mark them as untrusted, but prompt-injection risk cannot be fully eliminated. Do not automatically execute remediation suggestions.

**Permissions:** Use AWS IAM roles with scoped read-only policies, least-privilege S3 object access and no long-lived AWS keys if available. The Prowler process should run under a dedicated low-privilege user.

**Retention:** Data lives in local SQLite and Prowler's per-run scan directories. There is no automatic sensitive-data retention/deletion workflow yet; periodically review and delete generated files. Avoid adding database/log outputs to Git.

**Safe open-source publishing:** Review full Git history for previously committed credentials, real cloud artifacts and identifiers. Removing a file from the current ZIP does not remove it from an already published repository's history. Rotate exposed credentials before publishing.
