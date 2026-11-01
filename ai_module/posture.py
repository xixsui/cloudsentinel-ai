"""Conservative, evidence-scoped CSPM classification and human-reviewed guidance.

ATT&CK is a possible attacker *technique*, not an observation or a probability.
CWE is a possible weakness *class*, not a CVE or an exploited vulnerability.
Unknown checks deliberately remain unmapped.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from ai_module.models import Finding


@dataclass(frozen=True)
class PostureAssessment:
    category: str
    weakness_id: str | None
    weakness_name: str | None
    technique_id: str | None
    technique_name: str | None
    technique_tactic: str | None
    conditions: str
    remediation: tuple[str, ...]
    verification: str
    mapping_basis: str

    @property
    def cwe_url(self) -> str | None:
        return f"https://cwe.mitre.org/data/definitions/{self.weakness_id[4:]}.html" if self.weakness_id else None

    @property
    def attack_url(self) -> str | None:
        return ("https://attack.mitre.org/techniques/" + self.technique_id.replace(".", "/") + "/") if self.technique_id else None


DEFAULT = PostureAssessment(
    category="Configuration hygiene / other",
    weakness_id=None, weakness_name=None,
    technique_id=None, technique_name=None, technique_tactic=None,
    conditions="This check alone does not establish an exploitable weakness or a specific attacker technique. Review the original evidence and intended configuration.",
    remediation=("Read the Prowler status detail and linked remediation references.",
                 "Confirm the resource's intended security requirements before making a change.",
                 "Apply a least-privilege configuration change through your approved process."),
    verification="Rerun the same Prowler check for the same resource and review the new PASS/FAIL evidence.",
    mapping_basis="Unmapped: no approved rule for this Prowler check ID.",
)

# Match exact Prowler check IDs only, not titles or untrusted LLM text.
RULES: dict[str, PostureAssessment] = {
    "s3_bucket_public_access": PostureAssessment(
        "Public cloud storage exposure", "CWE-732", "Incorrect Permission Assignment for Critical Resource",
        "T1530", "Data from Cloud Storage", "Collection",
        "If public access is effective for objects, an external actor could retrieve accessible data. Bucket settings alone do not prove that data was accessed.",
        ("Confirm whether the bucket or any objects are intentionally public; inspect bucket policy, ACLs and effective Block Public Access settings.",
         "Remove unintended public permissions; enable appropriate S3 Block Public Access controls after checking application impact.",
         "Validate effective permissions with an authorized access review; do not test against production data anonymously without approval."),
        "Rescan s3_bucket_public_access for the same bucket and verify access policies and affected objects.",
        "Exact Prowler s3_bucket_public_access failure; CWE candidate requires analyst review.",
    ),
    "s3_bucket_level_public_access_block": PostureAssessment(
        "Missing S3 public-access guardrail", None, None, None, None, None,
        "Absence of bucket-level Block Public Access does not alone prove the bucket is publicly readable.",
        ("Review bucket-level and account-level Block Public Access settings and legitimate public-serving requirements.",
         "Enable suitable S3 Block Public Access controls if the bucket does not require public access."),
        "Rerun the bucket-level public-access-block check and inspect the resulting configuration.",
        "Control failure only; no attack-technique mapping without evidence of actual access.",
    ),
    "s3_account_level_public_access_blocks": PostureAssessment(
        "Missing account-level public-access guardrail", None, None, None, None, None,
        "This is an account-level preventative control gap, not evidence of public object access.",
        ("Inventory workloads that intentionally expose S3 objects.",
         "Review and configure S3 account-level Block Public Access according to the access policy."),
        "Rerun s3_account_level_public_access_blocks for the same account.",
        "Control failure only; do not infer T1530 from missing guardrails.",
    ),
    "ec2_instance_port_ssh_exposed_to_internet": PostureAssessment(
        "Internet-exposed remote administration", None, None,
        "T1021.004", "Remote Services: SSH", "Lateral Movement",
        "An Internet-reachable SSH service may be a target for unauthorized remote access attempts. An open port alone does not show SSH use, credential compromise, or lateral movement.",
        ("Confirm which EC2 instance and security-group rules permit TCP/22 from the Internet.",
         "Restrict SSH ingress to approved administrative networks, or use AWS Systems Manager Session Manager where appropriate.",
         "Check authorized access paths and avoid locking out administrators."),
        "Rerun the instance SSH exposure check and confirm approved ingress rules.",
        "Possible SSH-related technique only; not evidence of a lateral-movement event.",
    ),
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": PostureAssessment(
        "Overly broad SSH ingress", None, None, "T1021.004", "Remote Services: SSH", "Lateral Movement",
        "TCP/22 ingress from the Internet widens the attack surface, but doesn't prove attacker use.",
        ("Inspect ingress rules for 0.0.0.0/0 or ::/0 on TCP/22 and document authorized sources.",
         "Limit ingress to approved CIDRs, VPN/bastion routes, or Session Manager as appropriate."),
        "Rescan the relevant security group and inspect inbound rules.",
        "Exposure-based potential mapping; no behavioural telemetry.",
    ),
    "ec2_instance_port_rdp_exposed_to_internet": PostureAssessment(
        "Internet-exposed remote administration", None, None,
        "T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement",
        "An Internet-reachable RDP service can be targeted, but exposure does not establish an RDP session or attack.",
        ("Review EC2 security-group rules for TCP/3389 and confirm business need.",
         "Restrict to approved network access paths and strengthen authentication."),
        "Rescan the instance RDP exposure check and review actual ingress controls.",
        "Potential technique from exposed RDP port, not observed attacker behaviour.",
    ),
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389": PostureAssessment(
        "Overly broad RDP ingress", None, None,
        "T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement",
        "Internet-wide RDP ingress is a potential remote-service attack surface, not a recorded intrusion.",
        ("Review permitted sources for TCP/3389 in the security group.",
         "Replace Internet-wide ingress with approved controlled access."),
        "Rescan the affected security group and verify inbound rules.",
        "Potential technique from overbroad access rule only.",
    ),
    "cloudtrail_log_file_validation_enabled": PostureAssessment(
        "Audit log integrity control", None, None, None, None, None,
        "Disabled log file validation can weaken the ability to validate log integrity; it does not mean logs were tampered with.",
        ("Review CloudTrail trail settings, operational requirements and validation implications.",
         "Enable log file validation on the intended trail where appropriate."),
        "Rescan CloudTrail log-file validation and verify the trail settings.",
        "Monitoring/control gap; no ATT&CK behaviour inferred.",
    ),
}


# Additional exact-check classifications: deliberately no ATT&CK/CWE where a
# failed guardrail does not establish an exploitable actor path.
RULES.update({
    "s3_bucket_secure_transport_policy": PostureAssessment(
        "Transport protection policy", None, None, None, None, None,
        "The bucket policy may not require secure transport. This check does not prove that plaintext transfer occurred.",
        ("Inspect effective bucket policy and application TLS requirements.",
         "If appropriate, explicitly deny requests with aws:SecureTransport set to false after reviewing workload impact."),
        "Rerun the exact S3 secure-transport-policy check.", "Policy-control gap; no observed plaintext traffic."),
    "s3_bucket_kms_encryption": PostureAssessment(
        "Storage encryption policy", None, None, None, None, None,
        "Lack of configured KMS encryption does not imply the bucket is wholly unencrypted: S3 default SSE-S3 may still apply.",
        ("Review current bucket default encryption and key management requirements.",
         "If required, configure SSE-KMS with least-privilege key policy and check associated workloads."),
        "Rerun the bucket KMS-encryption check and review the effective default encryption.",
        "Encryption governance gap; avoid assuming unencrypted storage."),
    "ec2_securitygroup_allow_ingress_from_internet_to_any_port": PostureAssessment(
        "Broad network ingress", None, None, None, None, None,
        "Internet-wide ingress to all ports can increase attack surface, but does not prove service reachability or intrusion.",
        ("Review the security-group inbound CIDRs, ports, attached interfaces and business requirements.",
         "Remove unnecessary Internet-wide rules and limit ingress to approved sources and service ports."),
        "Rerun the specific security-group rule check and validate reachability from approved networks.",
        "Broad attack surface; no specific technique without a confirmed reachable service."),
    "ec2_instance_account_imdsv2_enabled": PostureAssessment(
        "EC2 instance metadata hardening", None, None, None, None, None,
        "IMDSv1 may be enabled; this is a hardening gap, not evidence of SSRF or credential theft.",
        ("Inspect instance metadata options and application compatibility.",
         "After testing consumers, require IMDSv2 tokens where supported."),
        "Rerun the IMDSv2 check and verify HttpTokens=required on the affected instance.",
        "No CWE or ATT&CK claim from metadata-version setting alone."),
    "ec2_ebs_volume_encryption": PostureAssessment(
        "EBS encryption at rest", None, None, None, None, None,
        "Unencrypted EBS data could raise confidentiality/compliance concerns depending on use and controls.",
        ("Review volume sensitivity, encryption policy, snapshots and migration plan.",
         "Plan an approved encrypted replacement / snapshot workflow; validate backups and instance downtime risks."),
        "Rerun the EBS volume-encryption check against the expected replacement volume.",
        "Storage protection gap; no CVE/ATT&CK inferred."),
    "config_recorder_all_regions_enabled": PostureAssessment(
        "Cloud configuration inventory coverage", None, None, None, None, None,
        "Configuration recording gaps limit visibility; they do not prove a hidden attack.",
        ("Review where AWS Config recording is required, and associated service costs.",
         "Enable/configure recording in intended Regions with appropriate IAM role and delivery channel."),
        "Rerun the all-regions AWS Config recorder check.",
        "Coverage gap rather than attack evidence."),
    "iam_user_hardware_mfa_enabled": PostureAssessment(
        "IAM hardware MFA assurance", None, None, None, None, None,
        "Failure of a hardware-MFA requirement does not alone mean the user has no MFA at all.",
        ("Confirm IAM user's actual MFA configuration and organization policy.",
         "Enroll a required hardware authenticator through an approved user process if mandated."),
        "Rerun the user hardware-MFA check and inspect permitted factors.",
        "Authentication assurance gap; distinguish hardware MFA requirement from all-MFA absence."),
    "iam_password_policy_minimum_length_14": PostureAssessment(
        "IAM password policy strength", None, None, None, None, None,
        "A weak policy increases password guessing risk but does not show credential theft or login attempts.",
        ("Review IAM account password policy and existing user-impact requirements.",
         "Set the organizationally approved minimum password length and validate enforcement."),
        "Rerun the password-policy check and verify policy settings.",
        "Password policy issue; no observed attack technique."),
    "s3_bucket_object_versioning": PostureAssessment(
        "S3 recovery resilience", None, None, None, None, None,
        "Absent bucket versioning may weaken recovery from accidental or malicious object modification or deletion.",
        ("Review recovery, cost, and data-retention requirements.",
         "Enable S3 Versioning where appropriate and update lifecycle/recovery policy."),
        "Rerun the bucket-versioning check and test recovery plans in a safe environment.",
        "Recovery control gap; no observed destructive activity."),
    "iam_policy_attached_only_to_group_or_roles": PostureAssessment(
        "IAM policy attachment governance", None, None, None, None, None,
        "Directly attached user policies can complicate governance; failure does not itself prove AdministratorAccess or privilege abuse.",
        ("Review effective permissions and direct user-policy attachments.",
         "Move permissions to approved IAM groups/roles after assessing least privilege and operational effects."),
        "Rerun the policy-attachment check and inspect effective access.",
        "Policy hygiene only; check result does not prove excess permissions."),
})

# Backward compatibility for a legacy *synthetic* demo rule ID in v0.4.
RULES["ec2_securitygroup_allow_ingress_from_internet_to_port_22"] = RULES[
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"]


def assess_finding(finding: Finding) -> PostureAssessment:
    check = finding.check_id.strip().lower()
    if check in RULES:
        return RULES[check]
    service = check.split("_", 1)[0] if "_" in check else ""
    categories = {
        "iam": "IAM identity / access governance review",
        "s3": "S3 data protection / resilience review",
        "ec2": "EC2 instance / network hardening review",
        "config": "AWS Config coverage review",
        "cloudtrail": "CloudTrail auditability review",
        "cloudwatch": "CloudWatch monitoring review",
        "bedrock": "Bedrock AI governance — applicability review",
        "sagemaker": "SageMaker AI governance — applicability review",
        "organizations": "AWS Organizations governance review",
    }
    category = categories.get(service, DEFAULT.category)
    condition = DEFAULT.conditions
    if service in {"bedrock", "sagemaker"}:
        condition += " First confirm that the service and use case are in scope; an unused optional service is not necessarily an exploitable vulnerability."
    return replace(DEFAULT, category=category, conditions=condition)

