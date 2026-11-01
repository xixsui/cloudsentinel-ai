import sqlite3
import threading
import time

import pytest
from fastapi.testclient import TestClient
from backend_api.app import app
from backend_api import aws_workspace
from ai_module.database import Database
from ai_module.models import Finding, FindingType
from ai_module.remediation_tracker import RemediationTracker
from ai_module.scan_history import ScanHistory
from ai_module.advisor_v07 import _init_history, _init_feedback
from cloud_connection.aws import AWSConnection

TOKEN = {"X-Local-Token": "settings-test"}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    path = tmp_path / "data.db"
    monkeypatch.setenv("CLOUDSENTINEL_DB_PATH", str(path))
    monkeypatch.setenv("CLOUDSENTINEL_WRITE_TOKEN", "settings-test")
    db = Database(path)
    for fid in ("one", "two"):
        db.upsert_finding(Finding(finding_id=fid, finding_type=FindingType.MISCONFIG, source="prowler", title=fid, description="test"))
    RemediationTracker(path)
    ScanHistory(path)
    _init_history(db)
    _init_feedback(db)
    with sqlite3.connect(path) as con:
        con.execute("INSERT INTO scan_runs VALUES ('scan', 'now', 'then', 'prowler', 0, 1, '{}')")
        con.execute("INSERT INTO scan_observations VALUES ('scan','one','FAIL','then')")
        con.execute("INSERT INTO advisor_runs_v07 (finding_id,fingerprint,provider,model,payload,created_at) VALUES ('one','x','demo','demo','{}','now')")
        con.execute("INSERT INTO advisor_feedback_v09 VALUES (1,'one','helpful','','now')")
        con.execute("INSERT INTO remediation_cases (finding_id,updated_at) VALUES ('one','now')")
        con.execute("INSERT INTO incidents (incident_id,finding_ids,ai_narrative) VALUES ('incident','[\"one\",\"two\"]','old narrative')")
    aws_workspace.disconnect()
    yield TestClient(app), path
    aws_workspace.disconnect()


def test_deletion_confirmation_auth_atomicity(setup):
    client, path = setup
    payload = {"scope":"selected","finding_ids":["one"],"confirmation":"DELETE"}
    assert client.post('/api/v1/settings/data/delete',json=payload).status_code == 403
    assert client.post('/api/v1/settings/data/delete',headers=TOKEN,json={**payload,"confirmation":""}).status_code == 422
    assert client.post('/api/v1/settings/data/delete',headers=TOKEN,json={**payload,"finding_ids":["one","missing"]}).status_code == 409
    assert client.get('/api/v1/findings').json()['total'] == 2
    result = client.post('/api/v1/settings/data/delete',headers=TOKEN,json=payload)
    assert result.json()['deleted'] == 1
    with sqlite3.connect(path) as con:
        for table in ('advisor_runs_v07','advisor_feedback_v09','remediation_cases'):
            assert con.execute(f'SELECT count(*) FROM {table}').fetchone()[0] == 0
        assert con.execute('SELECT count(*) FROM scan_runs').fetchone()[0] == 1
        assert con.execute('SELECT count(*) FROM scan_observations').fetchone()[0] == 1
        assert con.execute('SELECT finding_ids, ai_narrative FROM incidents').fetchone() == ('["two"]', '')


def test_clear_leaves_working_empty_workspace(setup):
    client, path = setup
    assert client.post('/api/v1/settings/data/delete',headers=TOKEN,json={'scope':'all','confirmation':'DELETE'}).status_code == 422
    assert client.post('/api/v1/settings/data/delete',headers=TOKEN,json={'scope':'all','confirmation':'CLEAR ALL'}).json()['deleted'] == 2
    with sqlite3.connect(path) as con:
        for table in ('findings','scan_runs','scan_observations','incidents','advisor_runs_v07','advisor_feedback_v09'):
            assert con.execute(f'SELECT count(*) FROM {table}').fetchone()[0] == 0
    assert client.get('/api/v1/posture/summary').json()['total'] == 0
    assert client.get('/api/v1/scans').json()['items'] == []
    assert client.get('/api/v1/findings/one').status_code == 404


def test_no_implicit_aws_calls_and_safe_errors(setup, monkeypatch):
    client, _ = setup
    def forbidden(*a, **k):
        raise AssertionError('SECRET SHOULD NOT LEAK')
    monkeypatch.setattr(AWSConnection,'test_identity',forbidden)
    assert client.get('/api/v1/aws/inventory').json()['connected'] is False
    assert client.post('/api/v1/aws/inventory/refresh',headers=TOKEN,json={}).status_code == 409
    body={'mode':'default','region':'us-east-1'}
    assert client.post('/api/v1/settings/aws/connect',json=body).status_code == 403
    failed=client.post('/api/v1/settings/aws/connect',headers=TOKEN,json=body)
    assert failed.status_code==409 and 'SECRET' not in failed.text
    failed=client.post('/api/v1/settings/aws/connect',headers=TOKEN,json={**body,'secret_access_key':{'secret':'SENSITIVE'}})
    assert failed.status_code==422 and 'SENSITIVE' not in failed.text


def test_disconnect_discards_inflight_snapshot(setup, monkeypatch):
    client, _ = setup
    monkeypatch.setattr(AWSConnection,'test_identity',lambda self:{'Account':'123','Arn':'test'})
    started, release = threading.Event(), threading.Event()
    def slow(*args):
        started.set(); release.wait(5)
        return {'resources':[{'id':'old-account-resource'}]}
    monkeypatch.setattr(aws_workspace,'collect',slow)
    response=client.post('/api/v1/settings/aws/connect',headers=TOKEN,json={'mode':'temporary','region':'us-east-1','access_key_id':'ASIATEST','secret_access_key':'private-test-secret','session_token':'private-test-token'})
    assert response.status_code==200
    assert 'private-test' not in response.text
    assert client.post('/api/v1/aws/inventory/refresh',headers=TOKEN,json={}).json()['loading']
    assert started.wait(2)
    client.post('/api/v1/settings/aws/disconnect',headers=TOKEN,json={})
    release.set()
    aws_workspace._future.result(timeout=5)
    status=client.get('/api/v1/aws/inventory').json()
    assert not status['connected'] and status['snapshot'] is None


def test_inventory_partial_failure_is_visible(monkeypatch):
    class Client:
        def can_paginate(self, operation): return False
        def describe_instances(self): return {'Reservations':[{'Instances':[{'InstanceId':'i-test','State':{'Name':'running'}}]}]}
        def __getattr__(self, attr):
            def fail(): raise RuntimeError('credential-secret-must-not-leak')
            return fail
    class Session:
        def client(self, *a, **kw): return Client()
    monkeypatch.setattr(AWSConnection,'session',lambda self:Session())
    result=aws_workspace.collect(AWSConnection(region='us-east-1'),{'Account':'123'})
    assert len(result['resources'])==1
    assert len(result['errors'])==8
    assert 'credential-secret' not in str(result)


def test_delete_waits_for_active_writes_and_releases_after_failure(setup):
    from backend_api.app import protect_data_write, protect_data_delete
    client, _ = setup
    write = protect_data_write()
    next(write)
    try:
        response = client.post('/api/v1/settings/data/delete',headers=TOKEN,json={'scope':'all','confirmation':'CLEAR ALL'})
        assert response.status_code == 409
    finally:
        write.close()
    deletion = protect_data_delete()
    next(deletion)
    try:
        response = client.post('/api/v1/findings/one/ai/analyze',headers=TOKEN,json={'consent_to_external_processing':True})
        assert response.status_code == 409
    finally:
        deletion.close()
    assert client.post('/api/v1/settings/data/delete',headers=TOKEN,json={'scope':'all','confirmation':'CLEAR ALL'}).status_code == 200


@pytest.mark.skipif(__import__('os').name != 'posix', reason='Encrypted saving requires POSIX')
def test_access_key_encrypted_reconnect_remove(setup, monkeypatch):
    from config import ai_preferences
    client, _ = setup
    seen = []
    def verify(self):
        seen.append((self.mode, self.access_key_id, self.secret_access_key, self.session_token))
        return {'Account':'123','Arn':'test'}
    monkeypatch.setattr(AWSConnection, 'test_identity', verify)
    secret = 'fake-aws-secret-for-test'
    body = {'mode':'access_key','region':'us-east-1','access_key_id':'AKIATEST','secret_access_key':secret,'save_credentials':True}
    response = client.post('/api/v1/settings/aws/connect',headers=TOKEN,json=body)
    assert response.status_code == 200, response.text
    assert response.json()['saved_access_key']
    assert secret not in response.text and 'AKIATEST' not in response.text
    assert secret.encode() not in (ai_preferences.directory()/'settings.enc').read_bytes()
    aws_workspace.disconnect()
    assert not client.get('/api/v1/settings/aws').json()['connected']
    assert len(seen) == 1
    assert client.post('/api/v1/settings/aws/connect-saved',headers=TOKEN,json={}).status_code == 200
    assert seen[-1] == ('access_key','AKIATEST',secret,'')
    with ai_preferences.edit() as state:
        state['credentials'] = {'groq':'fake-ai-key'}
    assert client.post('/api/v1/settings/aws/remove-saved',json={}).status_code == 403
    result = client.post('/api/v1/settings/aws/remove-saved',headers=TOKEN,json={}).json()
    assert not result['connected'] and not result['saved_access_key']
    assert ai_preferences.credential('groq') == 'fake-ai-key'


def test_access_key_memory_only_and_failed_verification(setup, monkeypatch):
    from config import ai_preferences
    client, _ = setup
    body={'mode':'access_key','region':'us-east-1','access_key_id':'AKIATEST','secret_access_key':'fake-secret'}
    monkeypatch.setattr(AWSConnection,'test_identity',lambda self:{'Account':'123','Arn':'test'})
    result=client.post('/api/v1/settings/aws/connect',headers=TOKEN,json=body)
    assert result.status_code==200 and not result.json()['saved_access_key']
    assert not ai_preferences.directory().exists()
    assert client.post('/api/v1/settings/aws/connect',headers=TOKEN,json={**body,'session_token':'unexpected'}).status_code==422
    def fail(self): raise RuntimeError('fake-secret')
    monkeypatch.setattr(AWSConnection,'test_identity',fail)
    result=client.post('/api/v1/settings/aws/connect',headers=TOKEN,json={**body,'save_credentials':True})
    assert result.status_code==409 and 'fake-secret' not in result.text
    assert not ai_preferences.directory().exists()


def test_access_key_sdk_and_subprocess_do_not_inherit_session_token(monkeypatch):
    import boto3
    captured={}
    monkeypatch.setattr(boto3,'Session',lambda **kw:captured.update(kw))
    conn=AWSConnection(mode='access_key',region='us-east-1',access_key_id='AKIATEST',secret_access_key='fake-secret')
    conn.session()
    assert captured['aws_session_token'] is None
    assert captured['aws_secret_access_key']=='fake-secret'
    env=conn.subprocess_env({'AWS_SESSION_TOKEN':'stale','AWS_SECURITY_TOKEN':'stale','AWS_PROFILE':'wrong'})
    assert 'AWS_SESSION_TOKEN' not in env and 'AWS_SECURITY_TOKEN' not in env and 'AWS_PROFILE' not in env
