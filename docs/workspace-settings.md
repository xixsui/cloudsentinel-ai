# AWS resources and local data management

Settings now includes AWS connection, AI providers and local data management.
AI keys continue to use the encrypted store described in [AI settings](ai-settings.md).

## AWS

Choose a region and explicitly connect with the backend server's IAM role/environment
chain, a profile configured on that server (WSL when using the launcher), or all three
temporary credential fields. Access Key mode accepts a long-term Access Key ID and Secret Access Key without a Session Token. Connect verifies STS identity. No AWS requests run on page
load. By default credentials and connection state are process-local memory only, never localStorage,
source files, database or API responses. Access Key mode optionally saves credentials encrypted
in the same owner-only store as AI settings, outside the repository. The master key protects
against other OS users, not the same user or administrator. Saving happens only after identity
verification. After restart, explicitly click Connect saved credentials to reverify. Remove saved
AWS credentials deletes the local saved copy and disconnects; it does not revoke the AWS key.
Disconnect alone retains the saved copy. Temporary credentials cannot be persisted. Restarting requires reconnection. Temporary
credentials are not automatically renewed by this application.

Home shows a connect-to-Settings prompt until connected. Refresh AWS resources starts a
background read-only inventory; navigating does not restart it. Results are cached in
memory until explicitly refreshed or disconnected. Replacing/disconnecting the identity
invalidates pending results. Refresh is single-flight and limited to 1,000 resources per
category. A connection check is not a permissions audit. Expired credentials, inaccessible
services and incomplete listings are visible, not interpreted as empty services.

Coverage: EC2 instances, VPCs, security groups, RDS instances, Lambda functions and
CloudTrail trails in the selected region; S3 buckets and IAM users/roles account-wide.
This is not a complete account inventory or a Prowler security scan. Imported findings
remain historical and independent of the currently connected account.

## Deleting local records

Settings > Data management supports search, pagination, selection (up to 100) and typed
confirmation. Selected deletion requires `DELETE`: removes findings, AI runs/feedback,
legacy analyses and remediation records; updates linked incidents and clears the legacy
AI cache. Immutable imported scans remain available; reimporting can restore findings.

`CLEAR ALL` removes all local findings (including non-misconfiguration findings), AI
analyses/feedback/cache, remediation records, incidents, scan runs and observations.
Provider settings and AWS resources are unaffected. No automatic demo seeding occurs.
Source JSON files and external backups are not deleted. This is application deletion,
not a secure disk-erasure feature. The app provides no undo.

Deletions are transactional, token-protected and same-origin through Next.js. In the
supported single-worker local API, deletion is rejected while an import, analysis or
other data write is running. Do not run separate legacy writers against the same database
while clearing records. Tests use isolated databases and mocked AWS calls.

No live cloud credentials or resource access are required to upload an existing Prowler
OCSF report from Scan History into an empty workspace.
