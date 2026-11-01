import json
import os
import sqlite3
import sys
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from botocore.exceptions import ClientError
from backend_api import web_scans, aws_workspace
from backend_api.aws_errors import explain
from backend_api.app import app
from cloud_connection.aws import AWSConnection
from ai_module.database import Database
from ai_module.scan_history import ScanHistory
from prowler_module.report_import import import_report
from prowler_module.scan_jobs import ScanOptions
from tests.test_report_import import event


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    path=tmp_path/'test.db'
    Database(path)
    monkeypatch.setenv('CLOUDSENTINEL_DB_PATH',str(path))
    monkeypatch.setenv('CLOUDSENTINEL_WRITE_TOKEN','test')
    monkeypatch.setattr(AWSConnection,'test_identity',lambda self:{'Account':'000000000000','Arn':'fake'})
    manager=web_scans.WebScans()
    import importlib
    api_module=importlib.import_module('backend_api.app')
    monkeypatch.setattr(api_module,'web_scans',manager)
    aws_workspace.disconnect()
    yield path, manager, TestClient(app), {'X-Local-Token':'test'}
    if manager.current: manager.cancel(manager.current)
    manager.pool.shutdown(wait=True)
    aws_workspace.disconnect()


def fake_cli(tmp_path, monkeypatch, *, delay=0, code=3, account='000000000000'):
    report=event();report['cloud']['account']['uid']=account
    file=tmp_path/'fake-prowler'
    file.write_text(f'#!{sys.executable}\nimport sys,time,pathlib,json\ntime.sleep({delay})\nassert "--services" in sys.argv\npathlib.Path(sys.argv[sys.argv.index("-o")+1],"scan.ocsf.json").write_text({json.dumps(json.dumps([report]))})\nsys.exit({code})\n')
    file.chmod(0o700)
    monkeypatch.setenv('CLOUDSENTINEL_PROWLER_BIN',str(file))


def wait(manager,path):
    deadline=time.monotonic()+10
    while manager.active() and time.monotonic()<deadline:time.sleep(.05)
    assert not manager.active()
    return manager.jobs(path)[0]


@pytest.mark.skipif(os.name!='posix', reason='Local process integration requires WSL')
def test_scan_completion_import_scope_and_restart(fixture,tmp_path,monkeypatch):
    path,manager,client,headers=fixture
    fake_cli(tmp_path,monkeypatch)
    conn=AWSConnection(mode='access_key',access_key_id='AKIATEST',secret_access_key='fake-secret')
    job=manager.submit(path,conn,'000000000000',ScanOptions())
    result=wait(manager,path)
    assert result['status']=='completed',result
    assert result['findings_imported']==1
    assert 'fake-secret' not in str(result)
    scan=ScanHistory(path).get(result['scan_id'])
    assert scan['source']=='Prowler web scan'
    rows,total=Database(path).get_findings_filtered(account_id='000000000000',scan_id=result['scan_id'])
    assert total==1 and not rows[0].raw_evidence['historical_import']
    assert Database(path).get_findings_filtered(account_id='111111111111',scan_id=result['scan_id'])[1]==0
    with sqlite3.connect(path) as con:
        con.execute('UPDATE web_scan_jobs SET payload=? WHERE id=?',(json.dumps({**result,'status':'running'}),job['id']))
    restarted=web_scans.WebScans()
    assert restarted.jobs(path)[0]['status']=='interrupted'
    restarted.pool.shutdown()


@pytest.mark.skipif(os.name!='posix', reason='Local process integration requires WSL')
def test_cancel_and_delete_guard(fixture,tmp_path,monkeypatch):
    path,manager,client,headers=fixture
    fake_cli(tmp_path,monkeypatch,delay=5)
    job=manager.submit(path,AWSConnection(),'000000000000',ScanOptions())
    with pytest.raises(ValueError):manager.submit(path,AWSConnection(),'000000000000',ScanOptions())
    response=client.post('/api/v1/settings/data/delete',headers=headers,json={'scope':'all','confirmation':'CLEAR ALL'})
    assert response.status_code==409
    manager.cancel(job['id'])
    assert wait(manager,path)['status']=='cancelled'
    assert Database(path).get_findings()==[]
    assert client.post('/api/v1/settings/data/delete',headers=headers,json={'scope':'all','confirmation':'CLEAR ALL'}).status_code==200
    assert manager.jobs(path)==[]


@pytest.mark.skipif(os.name!='posix', reason='Local process integration requires WSL')
@pytest.mark.parametrize('code,account',[(2,'000000000000'),(0,'111111111111')])
def test_failed_or_wrong_account_report_never_imports(fixture,tmp_path,monkeypatch,code,account):
    path,manager,_,_=fixture
    fake_cli(tmp_path,monkeypatch,code=code,account=account)
    manager.submit(path,AWSConnection(),'000000000000',ScanOptions())
    assert wait(manager,path)['status']=='failed'
    assert Database(path).get_findings()==[]
    assert ScanHistory(path).list_runs()==[]


def test_api_scan_requires_token_consent_matching_account_and_allowed_scope(fixture,monkeypatch):
    path,manager,client,headers=fixture
    aws_workspace.connect(AWSConnection())
    body={'region':'us-east-1','services':['s3'],'account_id':'000000000000','consent':True}
    assert client.post('/api/v1/scans/start',json=body).status_code==403
    assert client.post('/api/v1/scans/start',headers=headers,json={**body,'consent':False}).status_code==422
    assert client.post('/api/v1/scans/start',headers=headers,json={**body,'account_id':'111111111111'}).status_code==409
    assert client.post('/api/v1/scans/start',headers=headers,json={**body,'services':['s3;bad']} ).status_code==409
    assert client.post('/api/v1/scans/start',headers=headers,json={**body,'region':'--bad'}).status_code==409


def test_account_and_scan_filters_and_empty_onboarding(fixture):
    path,_,client,_=fixture
    assert client.get('/api/v1/workspace/status').json()['finding_count']==0
    first=event();second=event();second['cloud']={'account':{'uid':'111111111111'}};second['finding_info']={**second['finding_info'],'uid':'different'}
    a=import_report(ScanHistory(path),[first]);b=import_report(ScanHistory(path),[second])
    response=client.get('/api/v1/findings',params={'account_id':'111111111111','scan_id':a['id']})
    assert response.json()['total']==0
    response=client.get('/api/v1/posture/summary',params={'account_id':'111111111111','scan_id':b['id']})
    assert response.json()['total']==1 and response.json()['accounts']==['111111111111']
    assert client.get('/api/v1/workspace/status').json()['accounts']==['000000000000','111111111111']
    assert len(client.get('/api/v1/scans',params={'account_id':'000000000000'}).json()['items'])==1


@pytest.mark.parametrize('code,word',[('ExpiredToken','expired'),('InvalidClientTokenId','rejected'),('AccessDenied','denied'),('Throttling','limit')])
def test_aws_diagnostics_redact_sdk_details(code,word):
    message=explain(ClientError({'Error':{'Code':code,'Message':'SECRET-KEY-MUST-NOT-LEAK'}},'test'))
    assert word in message and 'SECRET' not in message


@pytest.mark.skipif(os.name!='posix', reason='Local process integration requires WSL')
def test_timeout_does_not_import_partial_report(fixture,tmp_path,monkeypatch):
    path,manager,_,_=fixture
    fake_cli(tmp_path,monkeypatch,delay=5)
    options=ScanOptions()
    # Exercise the timeout branch quickly; the public API still enforces >=60s.
    object.__setattr__(options,'timeout_seconds',0)
    manager.submit(path,AWSConnection(),'000000000000',options)
    assert wait(manager,path)['status']=='timed_out'
    assert Database(path).get_findings()==[]


@pytest.mark.skipif(os.name!='posix', reason='Local process integration requires WSL')
def test_scanner_does_not_receive_application_secrets(fixture,tmp_path,monkeypatch):
    path,manager,_,_=fixture
    fake_cli(tmp_path,monkeypatch)
    file=tmp_path/'fake-prowler'
    script=file.read_text().replace('import sys,time,pathlib,json', 'import sys,time,pathlib,json,os\nassert "OPENAI_API_KEY" not in os.environ\nassert "CLOUDSENTINEL_WRITE_TOKEN" not in os.environ\nassert "PROWLER_CLOUD_API_KEY" not in os.environ')
    file.write_text(script)
    monkeypatch.setenv('OPENAI_API_KEY','fake-app-secret')
    monkeypatch.setenv('PROWLER_CLOUD_API_KEY','fake-cloud-secret')
    manager.submit(path,AWSConnection(),'000000000000',ScanOptions())
    assert wait(manager,path)['status']=='completed'
