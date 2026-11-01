# Correlation methodology

Current candidate selection is implemented by `build_candidates()` in `ai_module/correlation.py`:

1. Ignore resolved/false-positive findings and missing/placeholder resources.
2. Partition by **(account_id, region, exact resource string)**. Never group solely by shared account.
3. Sort by occurrence time; split into windows no longer than 24 hours and at most 20 findings.
4. Require at least 2 distinct finding IDs, two source names, and >=1 threat finding.
5. Cap at the 25 most recent candidate groups per invocation to bound external AI cost.
6. LLM receives a truncated evidence summary and may mark `is_incident` true or false. It cannot certify an incident; analyst review remains necessary.
7. Incident IDs are derived from entity + evidence IDs, avoiding overwrite between unrelated windows on one resource.

**Limitations:** Exact string matching is conservative. If Wazuh identifies an IAM ARN but Prowler identifies a bucket ARN, the system may fail to correlate a truly related scenario. Account/region strings must match exactly, and overlapping windows are not chained; analysts should not interpret missing incidents as absence of attack. LLM conclusions can be incorrect, and prompt injection via attacker-controlled log content is possible despite instructions to treat logs as untrusted. No ground-truth accuracy/false-positive rate is claimed.

**Planned:** typed identities (principal ARN, bucket ARN, instance ID, IP), normalized event times, explicit entity relationships and deterministic ATT&CK mapping rules with evidence traces before allowing wider correlations.
