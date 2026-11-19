"""Evidence-scoped summaries and explicit, local-only report exports."""
import csv
from datetime import datetime, timezone
import html
import io
import json
import re

from ai_module.scan_snapshots import read as read_snapshot
from ai_module.remediation_tracker import RemediationTracker, STATES
from prowler_module.scan_jobs import SAFE_SERVICES

NOTICE = "Only evidence present in this report is counted. Missing services, checks, regions and accounts have unknown coverage. A scanner PASS is not proof of complete security."


def summary(history, scan_id):
    run = history.get(scan_id)
    observations = run.pop("observations")
    services = {}
    for item in observations:
        explicit = item.get("service", "")
        prefix = item["check"].split("_", 1)[0]
        service = explicit or (prefix if prefix in SAFE_SERVICES else "Unknown")
        basis = "Reported" if explicit else "Inferred from check ID" if service != "Unknown" else "Not recorded"
        group = services.setdefault((service, basis), {"service": service, "basis": basis, "observations": 0, "checks": set()})
        group["observations"] += 1
        group["checks"].add(item["check"])
    recorded = all("reported_status" in item for item in observations)
    run.update(services=[{**s, "checks": sorted(s["checks"])} for s in services.values()],
               checks=sorted({o["check"] for o in observations}),
               incomplete_observations=sum(not o["comparable"] for o in observations),
               reported_errors=sum(bool(set(o.get("reported_statuses", [o.get("reported_status")])) & {"ERROR", "ERRORS"}) for o in observations) if recorded else None,
               reported_skipped=sum(bool(set(o.get("reported_statuses", [o.get("reported_status")])) & {"SKIP", "SKIPPED"}) for o in observations) if recorded else None,
               coverage_notice=NOTICE,
               outcome_notice="Counts use unique check/resource observations. Reported errors/skips may also be counted as UNKNOWN or CONFLICT; they are not extra findings. Duplicate events may be collapsed; scanner execution errors outside the imported report are not known.")
    return run


def csv_cell(value):
    text = str(value if value is not None else "")
    # Guard spreadsheet formula execution, including leading control/space chars.
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def export_report(history, scan_id, *, format="html", include_identifiers=False, include_notes=False, include_ai=False):
    if format not in {"html", "csv"}:
        raise ValueError("Choose HTML or CSV")
    if (include_notes or include_ai) and not include_identifiers:
        raise ValueError("Notes and AI text may contain identifiers. Enable sensitive fields explicitly before including them.")
    info = summary(history, scan_id)
    # Never substitute mutable current findings when a historical snapshot is absent.
    findings = read_snapshot(history.db_path, scan_id)
    tracker = RemediationTracker(history.db_path)
    generated = datetime.now(timezone.utc).isoformat()
    secrets = {f.account_id for f in findings} | {f.resource for f in findings} | set(info["scope"]["accounts"])
    observations = history.get(scan_id)["observations"]
    secrets |= {o["resource"] for o in observations} | {o["account"] for o in observations}
    def public(value):
        text = str(value or "")
        if include_identifiers:
            return text
        for value in sorted((x for x in secrets if len(x) >= 3), key=len, reverse=True):
            text = text.replace(value, "[hidden]")
        text = re.sub(r"arn:[^\s<>\"']+|\b\d{12}\b", "[hidden]", text)
        return text
    records = []
    states = {r["finding_id"]:r for r in tracker.list_cases()}
    with history.connect() as con:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for index, finding in enumerate(findings, 1):
            workflow = states.get(finding.finding_id, {"state":"Open"})
            record = {"record": index, "check": public(finding.check_id), "severity": finding.severity.value,
                      "account": finding.account_id if include_identifiers else "[hidden]",
                      "resource": finding.resource if include_identifiers else "[hidden]",
                      "region": public(finding.region), "evidence_time": finding.timestamp.isoformat() if not finding.raw_evidence.get("scan_time_missing") else "Unknown",
                      "title": finding.title if include_identifiers else "Omitted in private export",
                      "description": finding.description if include_identifiers else "Omitted in private export",
                      "workflow_state_at_export": workflow["state"] if workflow["state"] in STATES else "Unknown"}
            if include_notes:
                record["notes_at_export"] = "\n".join(f'{a["occurred_at"]}: {a["note"]}' for a in tracker.activity(finding.finding_id) if a["note"])
            if include_ai:
                ai = con.execute("SELECT payload,created_at FROM advisor_runs_v07 WHERE finding_id=? ORDER BY id DESC LIMIT 1", (finding.finding_id,)).fetchone() if "advisor_runs_v07" in tables else None
                record["latest_saved_ai_at_export"] = f'{ai["created_at"]}: {ai["payload"]}' if ai else "No saved Web Advisor analysis"
            records.append(record)
    privacy = "Identifiers and free-text finding details included; inspect before sharing." if include_identifiers else "Account/resource fields hidden; titles and descriptions omitted. Check IDs and regions retained with best-effort identifier removal; inspect before sharing."
    context = {"scan_time": info["scanned_at"] or "Unknown", "generated_at": generated,
               "evidence_label": "Synthetic demo" if info["synthetic"] else "Historical scanner evidence",
               "accounts": ", ".join(info["scope"]["accounts"]) if include_identifiers else "[hidden]",
               "regions": public(", ".join(info["scope"]["regions"])) or "Unknown",
               "outcomes": json.dumps(info["counts"]), "reported_errors": info["reported_errors"] if info["reported_errors"] is not None else "Not recorded",
               "reported_skipped": info["reported_skipped"] if info["reported_skipped"] is not None else "Not recorded",
               "services": public("; ".join(f'{s["service"]} ({s["basis"]})' for s in info["services"])),
               "coverage": NOTICE, "counting": info["outcome_notice"], "privacy": privacy,
               "workflow": "Workflow states, notes and AI are current at export, not historical scan evidence. Saved AI may concern newer evidence; it is not fresh analysis or validated remediation."}
    if format == "csv":
        output = io.StringIO(newline="")
        columns = list(context) + ["record", "check", "severity", "account", "resource", "region", "evidence_time", "title", "description", "workflow_state_at_export"]
        columns += (["notes_at_export"] if include_notes else []) + (["latest_saved_ai_at_export"] if include_ai else [])
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        # A PASS-only report still carries its summary in one metadata row.
        for record in records or [{}]:
            writer.writerow({k: csv_cell(v) for k, v in {**context, **record}.items()})
        content, mime = "\ufeff" + output.getvalue(), "text/csv;charset=utf-8"
    else:
        esc = lambda value: html.escape(str(value), quote=True)
        rows = "".join(f'<tr><th>{esc(k.replace("_", " "))}</th><td>{esc(v)}</td></tr>' for k, v in context.items())
        cards = "".join('<section><h2>Finding '+str(i+1)+'</h2><dl>'+"".join(f'<dt>{esc(k.replace("_", " "))}</dt><dd>{esc(v)}</dd>' for k, v in r.items())+'</dl></section>' for i, r in enumerate(records))
        checks = "".join('<li>'+esc(public(c))+'</li>' for c in info["checks"])
        content = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>CloudSentinel scan report</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;color:#182336}table{border-collapse:collapse;width:100%}th,td{padding:10px;border:1px solid #ccd4df;text-align:left;vertical-align:top}section{margin:24px 0;padding:20px;border:1px solid #ccd4df;break-inside:avoid}dt{font-weight:bold;margin-top:12px}dd{margin:4px 0;white-space:pre-wrap;overflow-wrap:anywhere}td,li{overflow-wrap:anywhere}@media print{body{margin:0}}</style><h1>CloudSentinel scan report</h1><table>'+rows+'</table><h2>Checks represented in this report</h2><ul>'+checks+'</ul>'+ (cards or '<p>No FAIL findings in this snapshot. This does not prove complete account security.</p>')+'</html>'
        mime = "text/html;charset=utf-8"
    if len(content.encode("utf-8")) > 20 * 1024 * 1024:
        raise ValueError("Export exceeds 20 MB. Exclude notes/AI text or choose a smaller report.")
    return {"filename": f"cloudsentinel-report-{scan_id[:12]}.{format}", "mime": mime, "content": content}
