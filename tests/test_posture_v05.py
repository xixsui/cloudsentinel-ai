"""CSPM tests: no AWS, no API key, no real account data required."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ai_module.models import Finding, FindingType, Severity
from ai_module.database import Database
from ai_module.posture import assess_finding
from ai_module.remediation_tracker import RemediationTracker
from prowler_module.scanner import ProwlerScanner


def finding(check: str, finding_id: str = 'find-1') -> Finding:
    return Finding(finding_id=finding_id, finding_type=FindingType.MISCONFIG,
                   source='prowler', title=check, description='example finding',
                   resource='arn:aws:s3:::demo-safe-bucket', check_id=check,
                   severity=Severity.HIGH)


def event(scan_id: str, scan_time: datetime, status: str):
    return {'status_code': status, 'severity': 'High',
            'time_dt': scan_time.isoformat(),
            'status_detail': f'{status} finding for demo-safe-bucket',
            'unmapped': {'scan_id': scan_id},
            'cloud': {'account': {'uid': '000000000000'}},
            'finding_info': {'analytic': {'uid':'s3_bucket_public_access'},
                'uid':'prowler-aws-s3_bucket_public_access-000000000000-us-east-1-demo-safe-bucket',
                'title':'S3 Bucket Public Access'},
            'resources':[{'uid':'arn:aws:s3:::demo-safe-bucket','region':'us-east-1'}]}


def test_cwe_candidate_only_for_specific_s3_exposure():
    a=assess_finding(finding('s3_bucket_public_access'))
    assert a.weakness_id == 'CWE-732'
    assert a.technique_id == 'T1530'
    assert a.attack_url == 'https://attack.mitre.org/techniques/T1530/'
    assert 'potential' not in a.mapping_basis.lower() or a.technique_id == 'T1530'


def test_guardrail_does_not_imply_attack_or_cve():
    a=assess_finding(finding('s3_bucket_level_public_access_block'))
    assert a.technique_id is None
    assert a.weakness_id is None


def test_unmapped_check_defaults_no_attack_mapping():
    a=assess_finding(finding('bedrock_prompt_management_exists'))
    assert a.technique_id is None
    assert a.weakness_id is None
    assert 'Unmapped' in a.mapping_basis


def test_ssh_is_potential_remote_service_not_observed_attack():
    a=assess_finding(finding('ec2_instance_port_ssh_exposed_to_internet'))
    assert a.technique_id == 'T1021.004'
    assert a.attack_url == 'https://attack.mitre.org/techniques/T1021/004/'
    assert a.weakness_id is None
    assert 'not' in a.conditions.lower()


def test_invalid_transitions_and_no_manual_verification(tmp_path):
    db=Database(tmp_path / 'db.sqlite')
    f=finding('s3_bucket_public_access');db.upsert_finding(f)
    t=RemediationTracker(db.db_path)
    with pytest.raises(ValueError, match='Verified'):
        t.update(f.finding_id,state='Verified',assignee='',actor='tester')
    with pytest.raises(ValueError, match='In Progress'):
        t.update(f.finding_id,state='Pending Verification',assignee='',actor='tester')
    t.update(f.finding_id,state='In Progress',assignee='Engineer',actor='tester',note='Review bucket controls')
    t.update(f.finding_id,state='Pending Verification',assignee='Engineer',actor='tester',note='Applied approved control')
    assert t.get(f.finding_id)['state']=='Pending Verification'
    assert len(t.activity(f.finding_id))==2


def test_old_scan_reimport_and_unmatched_pass_never_verifies(tmp_path):
    db=Database(tmp_path / 'db.sqlite'); s=ProwlerScanner(db); t=RemediationTracker(db.db_path)
    past=datetime.now(timezone.utc)-timedelta(days=2)
    s.ingest_events([event('baseline',past,'FAIL')])
    fid=db.get_findings()[0].finding_id
    t.update(fid,state='In Progress',assignee='E',actor='tester')
    t.update(fid,state='Pending Verification',assignee='E',actor='tester')
    s.ingest_events([event('baseline',past,'FAIL')])
    s.ingest_events([event('other',past+timedelta(hours=1),'PASS')])
    assert t.get(fid)['state']=='Pending Verification'
    assert len(db.get_findings())==1


def test_new_independent_pass_verifies_exact_finding(tmp_path):
    db=Database(tmp_path / 'db.sqlite'); s=ProwlerScanner(db); t=RemediationTracker(db.db_path)
    past=datetime.now(timezone.utc)-timedelta(days=2)
    s.ingest_events([event('original',past,'FAIL')])
    fid=db.get_findings()[0].finding_id
    t.update(fid,state='In Progress',assignee='E',actor='tester',note='Investigating')
    t.update(fid,state='Pending Verification',assignee='E',actor='tester',note='Configuration fixed')
    assert t.record_observations([{'scan_id':'fresh-1','finding_id':fid,'status':'PASS',
                                   'scanned_at':(datetime.now(timezone.utc)+timedelta(seconds=30)).isoformat()}])==1
    case=t.get(fid)
    assert case['state']=='Verified'
    assert case['verified_scan_id']=='fresh-1'
    assert t.activity(fid)[0]['action']=='scan_verified'
    assert t.record_observations([{'scan_id':'fresh-1','finding_id':fid,'status':'PASS',
                                   'scanned_at':(datetime.now(timezone.utc)+timedelta(seconds=30)).isoformat()}])==0


def test_different_finding_cannot_verify(tmp_path):
    db=Database(tmp_path / 'd.db'); f=finding('s3_bucket_public_access');db.upsert_finding(f)
    t=RemediationTracker(db.db_path)
    t.update(f.finding_id,state='In Progress',assignee='',actor='engineer')
    t.update(f.finding_id,state='Pending Verification',assignee='',actor='engineer')
    t.record_observations([{'scan_id':'recent', 'finding_id':'different-id','status':'PASS',
                             'scanned_at':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()}])
    assert t.get(f.finding_id)['state']=='Pending Verification'


def test_accept_risk_requires_reason(tmp_path):
    db=Database(tmp_path/'d.db'); f=finding('unknown'); db.upsert_finding(f)
    t=RemediationTracker(db.db_path)
    with pytest.raises(ValueError,match='reason'):
        t.update(f.finding_id,state='Accepted Risk',assignee='',actor='engineer')
    t.update(f.finding_id,state='Accepted Risk',assignee='',actor='engineer',note='Approved exception with expiry')
    assert t.get(f.finding_id)['state']=='Accepted Risk'


def test_existing_database_preserved_on_tracker_creation(tmp_path):
    db=Database(tmp_path/'data.sqlite');db.upsert_finding(finding('unknown'))
    RemediationTracker(db.db_path)
    assert len(db.get_findings())==1
