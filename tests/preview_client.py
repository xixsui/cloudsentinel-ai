"""Existing analysis tests follow the new UI preview-before-send contract."""
from fastapi.testclient import TestClient


class PreviewClient(TestClient):
    def post(self, url, **kwargs):
        body = kwargs.get("json")
        if str(url).endswith("/ai/analyze") and isinstance(body, dict) and body.get("consent_to_external_processing") is True:
            params = {k: body[k] for k in ("provider_id", "model", "privacy") if body.get(k)}
            result = self.get(str(url).removesuffix("analyze") + "preview", params=params)
            kwargs["json"] = {**body, "preview_hash": result.json().get("hash", "0" * 64)}
        return super().post(url, **kwargs)
