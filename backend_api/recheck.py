"""Conservative verification of an explicit live recheck against captured baseline."""
from ai_module.scan_history import ScanHistory
from ai_module.remediation_tracker import RemediationTracker, parse_dt, utc_now
from prowler_module.scan_jobs import SAFE_SERVICES, ScanOptions


def prepare(path, finding):
    case = RemediationTracker(path).get(finding.finding_id)
    if case["state"] != "Pending Verification":
        raise ValueError("Set the case to In Progress, then Pending Verification before rechecking.")
    if finding.raw_evidence.get("synthetic_demo"):
        raise ValueError("Synthetic findings cannot be verified with live AWS scans.")
    baseline_id = finding.raw_evidence.get("scan_history_id")
    if not baseline_id:
        raise ValueError("Reimport the original report to establish baseline evidence first.")
    run = ScanHistory(path).get(baseline_id)
    matches = [o for o in run["observations"] if o["account"] == finding.account_id and o["resource"] == finding.resource
               and o["region"] == finding.region and o["check"] == finding.check_id and o["provider"] == "aws"]
    if len(matches) != 1 or matches[0]["status"] != "FAIL" or not matches[0]["comparable"] or matches[0]["version"] == "unknown":
        raise ValueError("Baseline identity, version or timestamp is incomplete or conflicting; verification is unavailable.")
    service = finding.check_id.split("_")[0]
    if service not in SAFE_SERVICES:
        raise ValueError("This check's service is not supported for web rechecks.")
    options = ScanOptions(region=finding.region, services=(service,))
    return options, {"finding_id": finding.finding_id, "baseline_id": baseline_id,
                     "baseline": matches[0], "pending_at": case["pending_at"]}


def finish(path, target, scan_id, started_at):
    run = ScanHistory(path).get(scan_id)
    baseline = target["baseline"]
    matches = [o for o in run["observations"] if o["key"] == baseline["key"]]
    outcome = "Unable to confirm"
    if not run["synthetic"] and scan_id != target["baseline_id"] and len(matches) == 1:
        current = matches[0]
        fresh = current["comparable"] and current["scanned_at"] and all(
            parse_dt(current["scanned_at"]) > parse_dt(t) for t in (baseline["scanned_at"], target["pending_at"], started_at))
        if baseline.get("source_scan_id") and current.get("source_scan_id") == baseline["source_scan_id"]:
            fresh = False
        from ai_module.database import Database
        latest = Database(path).get_finding(target["finding_id"])
        if latest is None or (current["scanned_at"] and parse_dt(latest.timestamp.isoformat()) > parse_dt(current["scanned_at"])):
            fresh = False
        if fresh and current["status"] in ("PASS", "FAIL"):
            outcome = "Verified" if current["status"] == "PASS" else "Still failing"
    tracker = RemediationTracker(path)
    with tracker._conn() as con:
        case = con.execute("SELECT * FROM remediation_cases WHERE finding_id=?", (target["finding_id"],)).fetchone()
        if not case or case["state"] != "Pending Verification" or case["pending_at"] != target["pending_at"]:
            return "Unable to confirm: workflow changed during the scan"
        now = utc_now()
        if outcome == "Verified":
            con.execute("UPDATE remediation_cases SET state='Verified',verified_at=?,verified_scan_id=?,verification_evidence=?,updated_at=? WHERE finding_id=?",
                        (now, scan_id, "Matching live Prowler PASS after requested verification", now, target["finding_id"]))
        con.execute("INSERT INTO remediation_activity(finding_id,actor,action,previous_state,new_state,note,occurred_at) VALUES(?,?,?,?,?,?,?)",
                    (target["finding_id"], "prowler-recheck", "live_recheck", case["state"], "Verified" if outcome == "Verified" else case["state"], f"{outcome}; scan {scan_id}", now))
    return outcome
