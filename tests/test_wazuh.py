import pytest
from siem_module.wazuh_client import WazuhClient, _wazuh_level_to_severity
from ai_module.models import Severity


def test_tls_validation_enabled_by_default(tmp_path):
    from ai_module.database import Database
    client = WazuhClient(db=Database(tmp_path / "db.sqlite"))
    assert client.verify_ssl is True
    assert client.auth.password == ""


def test_non_https_indexer_is_rejected(tmp_path):
    from ai_module.database import Database
    with pytest.raises(ValueError, match="HTTPS"):
        WazuhClient(host="http://localhost:9200", db=Database(tmp_path / "db.sqlite"))


def test_severity_mapping():
    assert _wazuh_level_to_severity(14) == Severity.CRITICAL
    assert _wazuh_level_to_severity(9) == Severity.HIGH
    assert _wazuh_level_to_severity(1) == Severity.INFO
