# Security Policy

This is an **educational prototype**, not a production-hardened cloud SIEM.

## Reporting vulnerabilities

Please report suspected vulnerabilities **privately** using GitHub's `Security` → `Report a vulnerability` option (after enabling private vulnerability reporting on your repository). Avoid submitting secrets, sensitive AWS logs or unredacted proof-of-concept data in public issues.

## Out of scope / existing risks

- No dashboard authentication/RBAC; use only on a trusted loopback/private lab.
- AI-generated interpretations may be incorrect or susceptible to prompt injection.
- Security event data contains potentially sensitive cloud identifiers.
- Integrated AWS/Wazuh/Prowler runtime behavior has not been audited for production use.

Do not expose Streamlit on public interfaces or grant the cloud integrations write/administrator IAM permissions.
