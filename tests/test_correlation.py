from datetime import datetime, timedelta

from ai_module.correlation import build_candidates
from ai_module.models import Finding, FindingType, Severity, Status

BASE = datetime(2026, 7, 1, 12, 0)


def finding(fid, source, *, resource="arn:aws:s3:::demo", account="123", hour=0,
            kind=FindingType.THREAT, status=Status.NEW):
    return Finding(
        finding_id=fid, finding_type=kind, source=source,
        severity=Severity.HIGH, title=f"Event {fid}", description="demo",
        resource=resource, account_id=account, region="ap-southeast-1",
        timestamp=BASE + timedelta(hours=hour), status=status,
    )


def test_correlates_only_explicit_cross_source_threat():
    items = [finding("a", "prowler", kind=FindingType.MISCONFIG),
             finding("b", "wazuh")]
    result = build_candidates(items)
    assert len(result) == 1
    assert {f.finding_id for f in result[0].findings} == {"a", "b"}


def test_no_account_only_or_unknown_resource_correlation():
    assert not build_candidates([finding("a", "prowler", resource=""),
                                 finding("b", "wazuh", resource="")])
    assert not build_candidates([finding("a", "prowler", resource="a"),
                                 finding("b", "wazuh", resource="b")])
    assert not build_candidates([finding("a", "prowler", resource="aws"),
                                 finding("b", "wazuh", resource="aws")])


def test_different_accounts_never_merge():
    assert not build_candidates([finding("a", "prowler", account="123"),
                                 finding("b", "wazuh", account="999")])


def test_time_window_and_same_source_requirements():
    assert not build_candidates([finding("a", "prowler"),
                                 finding("b", "wazuh", hour=25)])
    assert not build_candidates([finding("a", "wazuh"), finding("b", "wazuh")])
    assert not build_candidates([finding("a", "prowler", kind=FindingType.MISCONFIG),
                                 finding("b", "scanner", kind=FindingType.MISCONFIG)])


def test_resolved_and_false_positive_are_excluded():
    assert not build_candidates([
        finding("a", "prowler", kind=FindingType.MISCONFIG),
        finding("b", "wazuh", status=Status.FALSE_POSITIVE),
    ])
    assert not build_candidates([
        finding("a", "prowler", kind=FindingType.MISCONFIG),
        finding("b", "wazuh", status=Status.RESOLVED),
    ])


def test_max_limit_validation():
    import pytest
    with pytest.raises(ValueError):
        build_candidates([], max_findings=1)
