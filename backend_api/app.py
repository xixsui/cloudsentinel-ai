"""CloudSentinel v0.6 local-only FastAPI API.

This service intentionally reuses the v0.5 SQLite and classification engine.
It has no account authentication, so never expose it on a public interface.
All mutations require a session-specific token shared only with the Next.js BFF.
"""
from __future__ import annotations

import hmac
import os
from threading import Lock
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, SecretStr, ConfigDict

from ai_module.database import Database, DEFAULT_DB_PATH
from ai_module.models import Finding, FindingType
from ai_module.posture import assess_finding
from ai_module.remediation_tracker import RemediationTracker
from ai_module.scan_history import ScanHistory
from prowler_module.report_import import import_report
from config import ai_preferences
from ai_module.providers.base import PROVIDERS
from ai_module.advisor_v07 import _provider_settings
from ai_module.advisor_v07 import advisor_status, history as advisor_history, generate as generate_advice, save_feedback, AdvisorConfigurationError, AdvisorProviderError
from backend_api import aws_workspace
from backend_api.data_management import delete_data
from cloud_connection.aws import AWSConnection
from backend_api.web_scans import manager as web_scans, executable as prowler_executable
from prowler_module.scan_jobs import ScanOptions, SAFE_SERVICES
from backend_api.aws_errors import explain as explain_aws_error
from backend_api.scanner_setup import manager as scanner_setup

app = FastAPI(
    title="CloudSentinel AI Local API",
    description="v0.7 development API: local operator only, not an authenticated SaaS platform.",
    version="0.9.0",
    docs_url="/docs",
    redoc_url=None,
)


@app.exception_handler(LookupError)
async def missing_evidence(request: Request, exc: LookupError):
    return JSONResponse(status_code=404, content={"detail": str(exc)})


def db_path() -> Path:
    # Explicit override is useful for tests and migrating an existing v0.5 database.
    return Path(os.getenv("CLOUDSENTINEL_DB_PATH", str(DEFAULT_DB_PATH))).expanduser().resolve()


def get_db() -> Database:
    return Database(db_path())


def get_tracker() -> RemediationTracker:
    return RemediationTracker(db_path())


def require_write_token(x_local_token: Annotated[str | None, Header()] = None) -> None:
    expected = os.getenv("CLOUDSENTINEL_WRITE_TOKEN", "")
    if not expected or not x_local_token or not hmac.compare_digest(expected, x_local_token):
        raise HTTPException(403, "Write operations require a valid local development token")


_data_guard = Lock()
_active_data_writes = 0
_deleting_data = False


def protect_data_write():
    """Prevent a pending AI response from restoring records during deletion."""
    global _active_data_writes
    with _data_guard:
        if _deleting_data:
            raise HTTPException(409, "Local data is being deleted. Retry after it completes.")
        _active_data_writes += 1
    try:
        yield
    finally:
        with _data_guard:
            _active_data_writes -= 1


def protect_data_delete():
    global _deleting_data
    with _data_guard:
        if _active_data_writes or _deleting_data or web_scans.active():
            raise HTTPException(409, "An analysis, import or data update is still running. Wait for it to finish before deleting.")
        _deleting_data = True
    try:
        yield
    finally:
        with _data_guard:
            _deleting_data = False


@app.exception_handler(ai_preferences.AISettingsError)
async def settings_storage_error(request: Request, exc: ai_preferences.AISettingsError):
    return JSONResponse(status_code=503, content={"detail": str(exc)})


@app.exception_handler(RequestValidationError)
async def safe_validation_error(request: Request, exc: RequestValidationError):
    # Pydantic errors normally include the submitted input, which may contain a key.
    if request.url.path.startswith("/api/v1/settings/"):
        return JSONResponse(status_code=422, content={"detail": "Invalid settings request. Check the required fields and their format."})
    return await request_validation_exception_handler(request, exc)


@app.get("/api/v1/settings/ai")
def ai_settings() -> dict:
    status = advisor_status()
    available = {p["id"]: p for p in status["providers"]}
    saved = ai_preferences.load()
    providers = []
    for provider_id, cls in PROVIDERS.items():
        configured = provider_id in available
        providers.append({
            "id": provider_id, "name": cls.info.display_name,
            "configured": configured,
            "models": available[provider_id]["models"] if configured else [],
            "credential_source": "environment" if ai_preferences.environment_key(provider_id) else
                "encrypted-local" if saved.get("credentials", {}).get(provider_id) else "none",
            "destination": "operator-configured" if provider_id == "private" else "external",
        })
    return {"status": status, "providers": providers, "saved_default": saved.get("default"), "storage_supported": os.name == "posix",
            "notice": "Keys are encrypted in private local storage outside the project. Saving does not contact the provider or verify the key. Environment credentials take precedence."}


class AIDefaultUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str = Field(min_length=1, max_length=40)
    model: str = Field(min_length=1, max_length=100)


@app.put("/api/v1/settings/ai/default", dependencies=[Depends(require_write_token)])
def update_ai_default(body: AIDefaultUpdate) -> dict:
    try:
        provider, model, _ = _provider_settings(body.provider, body.model)
        ai_preferences.save_default(provider, model)
    except (AdvisorConfigurationError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return ai_settings()


class AICredentialUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["groq", "openai", "gemini", "anthropic", "private"]
    action: Literal["save", "remove"]
    api_key: SecretStr | None = Field(default=None, max_length=4096)


@app.put("/api/v1/settings/ai/credential", dependencies=[Depends(require_write_token)])
def update_ai_credential(body: AICredentialUpdate) -> dict:
    if body.action == "save" and body.api_key is None:
        raise HTTPException(422, "Enter an API key to save")
    if body.provider == "private" and body.action == "save" and not any(p["id"] == "private" for p in advisor_status()["providers"]):
        raise HTTPException(409, "Configure the private endpoint and approved model on the server first")
    try:
        ai_preferences.save_credential(body.provider, body.api_key.get_secret_value() if body.action == "save" else None)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return ai_settings()


class AWSConnect(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["default", "profile", "temporary", "access_key"]
    save_credentials: bool = False
    region: str = Field(pattern=r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-\d+$", max_length=40)
    profile: str = Field(default="", max_length=128)
    access_key_id: SecretStr = Field(default=SecretStr(""), max_length=128)
    secret_access_key: SecretStr = Field(default=SecretStr(""), max_length=512)
    session_token: SecretStr = Field(default=SecretStr(""), max_length=16384)


@app.get("/api/v1/settings/aws")
@app.get("/api/v1/aws/inventory")
def aws_status() -> dict:
    return aws_workspace.status()


@app.post("/api/v1/settings/aws/connect", dependencies=[Depends(require_write_token)])
def aws_connect(body: AWSConnect) -> dict:
    try:
        connection = AWSConnection(mode=body.mode, region=body.region, profile=body.profile,
                                   access_key_id=body.access_key_id.get_secret_value(),
                                   secret_access_key=body.secret_access_key.get_secret_value(),
                                   session_token=body.session_token.get_secret_value())
        if body.save_credentials and body.mode != "access_key":
            raise ValueError("Only Access Key credentials can be saved")
        return aws_workspace.connect(connection, persist=body.save_credentials)
    except ai_preferences.AISettingsError:
        raise
    except ValueError as exc:
        raise HTTPException(422, "Invalid AWS connection fields") from exc
    except Exception as exc:
        raise HTTPException(409, explain_aws_error(exc)) from exc


@app.post("/api/v1/settings/aws/connect-saved", dependencies=[Depends(require_write_token)])
def aws_connect_saved() -> dict:
    try:
        return aws_workspace.connect_saved()
    except ai_preferences.AISettingsError:
        raise
    except Exception as exc:
        raise HTTPException(409, explain_aws_error(exc)) from exc


@app.post("/api/v1/settings/aws/remove-saved", dependencies=[Depends(require_write_token)])
def aws_remove_saved() -> dict:
    return aws_workspace.remove_saved()


@app.post("/api/v1/settings/aws/disconnect", dependencies=[Depends(require_write_token)])
def aws_disconnect() -> dict:
    return aws_workspace.disconnect()


@app.post("/api/v1/aws/inventory/refresh", dependencies=[Depends(require_write_token)])
def aws_refresh() -> dict:
    try:
        return aws_workspace.refresh()
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


class DataDelete(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: Literal["selected", "all"]
    finding_ids: list[str] = Field(default_factory=list, max_length=100)
    confirmation: str = Field(max_length=40)


@app.post("/api/v1/settings/data/delete", dependencies=[Depends(require_write_token), Depends(protect_data_delete)])
def remove_local_data(body: DataDelete, db: Annotated[Database, Depends(get_db)]) -> dict:
    if body.scope == "all":
        if body.confirmation != "CLEAR ALL" or body.finding_ids:
            raise HTTPException(422, "Type CLEAR ALL to confirm clearing all local findings and history")
        ids = None
    else:
        if body.confirmation != "DELETE" or not body.finding_ids or any(not fid or len(fid) > 200 for fid in body.finding_ids):
            raise HTTPException(422, "Select findings and type DELETE to confirm")
        ids = body.finding_ids
    try:
        return {"deleted": delete_data(db.db_path, ids), "scope": body.scope}
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


def get_scan_history() -> ScanHistory:
    get_db()  # Initialize the existing database without replacing any tables.
    return ScanHistory(db_path())


class ScanImport(BaseModel):
    events: list[dict] = Field(min_length=1, max_length=20000)
    synthetic: bool = False


@app.get("/api/v1/scans")
def scan_runs(history: Annotated[ScanHistory, Depends(get_scan_history)], account_id: str | None = None) -> dict:
    return {"items": [s for s in history.list_runs() if not account_id or account_id in s["scope"]["accounts"]]}


@app.post("/api/v1/scans/import", dependencies=[Depends(require_write_token), Depends(protect_data_write)])
def import_scan(body: ScanImport, history: Annotated[ScanHistory, Depends(get_scan_history)]) -> dict:
    try:
        return import_report(history, body.events, synthetic=body.synthetic)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.get("/api/v1/scans/compare")
def compare_scans(before: Annotated[str, Query(pattern=r"^[a-f0-9]{64}$")],
                  after: Annotated[str, Query(pattern=r"^[a-f0-9]{64}$")],
                  history: Annotated[ScanHistory, Depends(get_scan_history)]) -> dict:
    try:
        return history.compare(before, after)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc



def serialize_finding(f: Finding, *, detail: bool = False) -> dict:
    result = {
        "finding_id": f.finding_id,
        "source": f.source,
        "severity": f.severity.value,
        "title": f.title,
        "description": f.description if detail else f.description[:280],
        "resource": f.resource,
        "account_id": f.account_id,
        "region": f.region,
        "check_id": f.check_id,
        "timestamp": f.timestamp.isoformat(),
        "status": f.status.value,
        "synthetic": bool(f.raw_evidence.get("synthetic_demo")),
    }
    if detail:
        result["compliance"] = f.compliance
        # Raw OCSF can contain sensitive configuration / account metadata;
        # not forwarded wholesale into the browser.
    return result


def find_or_404(db: Database, finding_id: str) -> Finding:
    f = db.get_finding(finding_id)
    if f is None or f.finding_type != FindingType.MISCONFIG:
        raise HTTPException(404, "Misconfiguration finding not found")
    return f


@app.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok", "version": "0.9.0", "mode": "local-development"}


@app.get("/api/v1/posture/summary")
def posture_summary(db: Annotated[Database, Depends(get_db)],
                    tracker: Annotated[RemediationTracker, Depends(get_tracker)],
                    account_id: str | None = None, scan_id: str | None = None) -> dict:
    findings, _ = db.get_findings_filtered(finding_type=FindingType.MISCONFIG, account_id=account_id, scan_id=scan_id)
    severity = {name: 0 for name in ("Critical", "High", "Medium", "Low", "Informational")}
    sources: dict[str, int] = {}
    for f in findings:
        severity[f.severity.value] += 1
        sources[f.source] = sources.get(f.source, 0) + 1
    ids = {f.finding_id for f in findings}
    cases = [c for c in tracker.list_cases() if c["finding_id"] in ids]
    workflow: dict[str, int] = {}
    for case in cases:
        workflow[case["state"]] = workflow.get(case["state"], 0) + 1
    return {
        "accounts": sorted({f.account_id for f in findings if f.account_id}),
        "latest_evidence_at": max((f.timestamp.isoformat() for f in findings), default=None),
        "total": len(findings),
        "severity": severity,
        "sources": sources,
        "tracked": len(cases),
        "workflow": workflow,
        "synthetic_count": sum(bool(f.raw_evidence.get("synthetic_demo")) for f in findings),
        "data_scope": "Stored misconfiguration FAIL findings, not a live AWS posture score",
    }


@app.get("/api/v1/findings")
def list_findings(
    db: Annotated[Database, Depends(get_db)],
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"] | None = None,
    source: Annotated[str | None, Query(max_length=80)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    account_id: Annotated[str | None, Query(max_length=128)] = None,
    scan_id: Annotated[str | None, Query(pattern=r"^[a-f0-9]{64}$")] = None,
) -> dict:
    results, total = db.get_findings_filtered(
        finding_type=FindingType.MISCONFIG,
        severities=[severity] if severity else None,
        sources=[source] if source else None,
        search=search, account_id=account_id, scan_id=scan_id,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return {
        "items": [serialize_finding(f) for f in results],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@app.get("/api/v1/findings/{finding_id}")
def finding_detail(finding_id: str, db: Annotated[Database, Depends(get_db)],
                   tracker: Annotated[RemediationTracker, Depends(get_tracker)],
                   scan_id: Annotated[str | None, Query(pattern=r"^[a-f0-9]{64}$")] = None) -> dict:
    if scan_id:
        from ai_module.scan_snapshots import read
        f = next((f for f in read(db.db_path, scan_id) if f.finding_id == finding_id), None)
        if f is None:
            raise HTTPException(404, "Finding not present in this scan snapshot")
    else:
        f = find_or_404(db, finding_id)
    posture = assess_finding(f)
    cached_ai = None if scan_id else db.get_analysis(finding_id)
    return {
        "finding": serialize_finding(f, detail=True),
        "assessment": asdict(posture) | {"cwe_url": posture.cwe_url, "attack_url": posture.attack_url},
        "remediation": tracker.get(finding_id),
        "ai_analysis": {
            "explanation": cached_ai.explanation,
            "mitigation_steps": cached_ai.mitigation_steps,
            "model_used": cached_ai.model_used,
            "analyzed_at": cached_ai.analyzed_at.isoformat(),
        } if cached_ai else None,
        "snapshot_scan_id": scan_id,
        "evidence_notice": "Read-only scan snapshot. Workflow status is current, not historical." if scan_id else "Historical check output; no attacker activity is confirmed without telemetry.",
    }


@app.get("/api/v1/remediations")
def remediations(tracker: Annotated[RemediationTracker, Depends(get_tracker)]) -> dict:
    return {"items": tracker.list_cases()}


@app.get("/api/v1/remediations/{finding_id}/activity")
def remediation_activity(finding_id: str,
                         db: Annotated[Database, Depends(get_db)],
                         tracker: Annotated[RemediationTracker, Depends(get_tracker)]) -> dict:
    find_or_404(db, finding_id)
    return {"items": tracker.activity(finding_id)}


class RemediationUpdate(BaseModel):
    state: Literal["Open", "In Progress", "Pending Verification", "Accepted Risk", "False Positive"]
    assignee: str = Field(default="", max_length=80)
    actor: str = Field(min_length=1, max_length=80)
    note: str = Field(default="", max_length=2000)


@app.patch("/api/v1/remediations/{finding_id}", dependencies=[Depends(require_write_token), Depends(protect_data_write)])
def update_remediation(finding_id: str, body: RemediationUpdate,
                       db: Annotated[Database, Depends(get_db)],
                       tracker: Annotated[RemediationTracker, Depends(get_tracker)]) -> dict:
    find_or_404(db, finding_id)
    try:
        tracker.update(finding_id, state=body.state, assignee=body.assignee, actor=body.actor, note=body.note)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return tracker.get(finding_id)


class AIAnalyzeRequest(BaseModel):
    # Human consent required for every request; nothing is called on page load.
    consent_to_external_processing: Literal[True]
    force_refresh: bool = False
    provider_id: str | None = Field(default=None, min_length=2, max_length=40)
    model: str | None = Field(default=None, min_length=1, max_length=100)
    privacy: Literal["standard", "minimal"] = "standard"
    preview_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


@app.get("/api/v1/findings/{finding_id}/ai/preview")
def ai_preview(finding_id: str, db: Annotated[Database, Depends(get_db)],
               privacy: Literal["standard", "minimal"] = "standard", provider_id: str | None = None, model: str | None = None) -> dict:
    from ai_module.advisor_v07 import preview
    try:
        return preview(find_or_404(db, finding_id), provider_id, model, privacy)
    except AdvisorConfigurationError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/v1/ai/status")
def ai_status() -> dict:
    return advisor_status()


@app.get("/api/v1/findings/{finding_id}/ai/history")
def ai_history(finding_id: str, db: Annotated[Database, Depends(get_db)]) -> dict:
    find_or_404(db, finding_id)
    return {"items": advisor_history(db, finding_id)}


@app.post("/api/v1/findings/{finding_id}/ai/analyze", dependencies=[Depends(require_write_token), Depends(protect_data_write)])
def analyze_finding(finding_id: str, body: AIAnalyzeRequest,
                    db: Annotated[Database, Depends(get_db)]) -> dict:
    f = find_or_404(db, finding_id)
    try:
        return generate_advice(db, f, force=body.force_refresh,
                               provider_id=body.provider_id, model_id=body.model,
                               privacy=body.privacy, expected_preview=body.preview_hash)
    except AdvisorConfigurationError as exc:
        raise HTTPException(409, str(exc)) from exc
    except AdvisorProviderError as exc:
        raise HTTPException(502, str(exc)) from exc


class AIFeedbackRequest(BaseModel):
    rating: Literal["helpful", "needs_correction"]
    note: str = Field(default="", max_length=500)


@app.put("/api/v1/findings/{finding_id}/ai/runs/{run_id}/feedback",
         dependencies=[Depends(require_write_token), Depends(protect_data_write)])
def update_advisor_feedback(finding_id: str, run_id: int, body: AIFeedbackRequest,
                            db: Annotated[Database, Depends(get_db)]) -> dict:
    find_or_404(db, finding_id)
    try:
        return save_feedback(db, finding_id, run_id, body.rating, body.note)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.get("/api/v1/workspace/status")
def workspace_status(db: Annotated[Database, Depends(get_db)]) -> dict:
    scans = get_scan_history().list_runs()
    ai = advisor_status()
    return {"accounts": sorted(set(db.distinct_values("account_id")) | {a for s in scans for a in s["scope"]["accounts"]}),
            "scans": scans, "finding_count": db.get_findings_filtered(finding_type=FindingType.MISCONFIG)[1],
            "aws_connected": aws_workspace.status()["connected"], "ai_configured": ai["configured"],
            "prowler_installed": bool(prowler_executable())}


@app.get("/api/v1/scans/jobs")
def list_scan_jobs(db: Annotated[Database, Depends(get_db)]) -> dict:
    return {"items": web_scans.jobs(db.db_path), "installed": bool(prowler_executable()), "services": sorted(SAFE_SERVICES)}


@app.get("/api/v1/settings/scanner")
def scanner_status() -> dict:
    return scanner_setup.status()


class InstallScanner(BaseModel):
    model_config = ConfigDict(extra="forbid")
    consent: Literal[True]


@app.post("/api/v1/findings/{finding_id}/recheck", dependencies=[Depends(require_write_token), Depends(protect_data_write)])
def recheck_finding(finding_id: str, body: InstallScanner, db: Annotated[Database, Depends(get_db)]) -> dict:
    from backend_api.recheck import prepare
    finding = find_or_404(db, finding_id)
    try:
        connection, account = aws_workspace.scan_connection()
        if account != finding.account_id:
            raise ValueError("Connect the finding's AWS account before rechecking.")
        options, target = prepare(db.db_path, finding)
        return web_scans.submit(db.db_path, connection, account, options, recheck=target)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/v1/settings/scanner/install", dependencies=[Depends(require_write_token)])
def install_scanner(body: InstallScanner) -> dict:
    try:
        return scanner_setup.start()
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except OSError as exc:
        raise HTTPException(409, "Cannot prepare the installer. Check backend home-directory permissions and free disk space.") from exc


class StartScan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    region: str = Field(max_length=40)
    services: list[str] = Field(min_length=1, max_length=10)
    account_id: str = Field(pattern=r"^\d{12}$")
    timeout_seconds: int = Field(default=1800, ge=60, le=3600)
    consent: Literal[True]


@app.post("/api/v1/scans/start", dependencies=[Depends(require_write_token), Depends(protect_data_write)])
def start_scan(body: StartScan, db: Annotated[Database, Depends(get_db)]) -> dict:
    try:
        connection, account = aws_workspace.scan_connection()
        if account != body.account_id:
            raise ValueError("Connected account changed. Refresh before starting a scan.")
        options = ScanOptions(region=body.region, services=tuple(body.services), timeout_seconds=body.timeout_seconds)
        return web_scans.submit(db.db_path, connection, account, options)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/v1/scans/jobs/{job_id}/cancel", dependencies=[Depends(require_write_token)])
def cancel_scan(job_id: str) -> dict:
    try:
        web_scans.cancel(job_id)
        return {"message": "Cancellation requested. Wait for terminal job status."}
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
