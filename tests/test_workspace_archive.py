import copy
import json
import sqlite3
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from backend_api.app import app
from backend_api.workspace_archive import export_data, validate, restore
from ai_module.database import Database
from ai_module.scan_history import ScanHistory
from ai_module.remediation_tracker import RemediationTracker
from prowler_module.report_import import import_report


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path / 'private-home'))
    path = tmp_path / 'workspace.db'
    Database(path)
    events = json.loads((Path(__file__).parents[1] / 'mock_data/scan_history/before.json').read_text())
    imported = import_report(ScanHistory(path), events, synthetic=True)
    monkeypatch.setenv('CLOUDSENTINEL_DB_PATH', str(path))
    monkeypatch.setenv('CLOUDSENTINEL_WRITE_TOKEN', 'archive-test')
    return path, imported


def test_roundtrip_with_snapshots_and_private_recovery(workspace):
    path, imported = workspace
    original = export_data(path)
    check = validate(original)
    assert check['counts']['findings'] == 3
    with sqlite3.connect(path) as con:
        con.execute("UPDATE findings SET title='changed'")
    result = restore(path, original, check['sha256'])
    recovery = Path(result['recovery_file'])
    assert json.loads(recovery.read_text())['tables']['findings'][0]['title'] == 'changed'
    assert export_data(path)['tables'] == original['tables']
    assert 'credentials' not in original['tables']
    assert result['restored'] == 3


@pytest.mark.parametrize('mutation', ['table', 'columns', 'duplicate', 'version', 'json'])
def test_bad_archive_does_not_modify_current_data(workspace, mutation):
    path, _ = workspace
    original = export_data(path)
    broken = copy.deepcopy(original)
    if mutation == 'table': broken['tables']['credentials'] = []
    if mutation == 'columns': broken['tables']['findings'][0]['unexpected'] = 'bad'
    if mutation == 'duplicate': broken['tables']['findings'].append(broken['tables']['findings'][0])
    if mutation == 'version': broken['version'] = 999
    if mutation == 'json': broken['tables']['findings'][0]['raw_evidence'] = '{'
    with pytest.raises((ValueError, sqlite3.Error)):
        restore(path, broken, 'bad')
    assert export_data(path)['tables'] == original['tables']


def test_preview_auth_confirmation_and_changed_archive(workspace):
    path, _ = workspace
    client = TestClient(app)
    headers = {'X-Local-Token': 'archive-test'}
    assert client.post('/api/v1/settings/data/backup', json={}).status_code == 403
    data = client.post('/api/v1/settings/data/backup', headers=headers, json={}).json()
    preview = client.post('/api/v1/settings/data/preview', headers=headers, json=data)
    assert preview.status_code == 200
    body = {'archive': data, 'sha256': preview.json()['sha256'], 'confirmation': 'wrong'}
    assert client.post('/api/v1/settings/data/restore', headers=headers, json=body).status_code == 422
    body['confirmation'] = 'RESTORE'
    body['archive']['tables']['findings'][0]['title'] = 'changed after preview'
    assert client.post('/api/v1/settings/data/restore', headers=headers, json=body).status_code == 422
    assert Database(path).get_findings()[0].title != 'changed after preview'


def test_restore_blocks_when_scan_active(workspace, monkeypatch):
    from backend_api.app import web_scans
    path, _ = workspace
    data = export_data(path)
    monkeypatch.setattr(web_scans, 'active', lambda: True)
    response = TestClient(app).post('/api/v1/settings/data/restore', headers={'X-Local-Token':'archive-test'},
        json={'archive':data,'sha256':validate(data)['sha256'],'confirmation':'RESTORE'})
    assert response.status_code == 409
