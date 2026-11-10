"""Validate through the real importer in private, disposable storage."""
from pathlib import Path
from tempfile import TemporaryDirectory

from ai_module.database import Database
from ai_module.scan_history import ScanHistory
from prowler_module.report_import import import_report


def preview_report(history, events, *, synthetic=False):
    with TemporaryDirectory(prefix="cloudsentinel-preview-") as folder:
        db = Database(Path(folder) / "preview.db")
        scratch = ScanHistory(db.db_path)
        result = import_report(scratch, events, synthetic=synthetic)
        observations = scratch.get(result["id"])["observations"]
    with history.connect() as con:
        duplicate = con.execute("SELECT 1 FROM scan_runs WHERE id=?", (result["id"],)).fetchone() is not None
    warnings = []
    if not result["scanned_at"]:
        warnings.append("Some event times are missing or invalid. This report cannot be compared chronologically.")
    if not result["scope"]["accounts"]:
        warnings.append("Account identity is missing; the report cannot establish which AWS account was scanned.")
    if result["counts"]["UNKNOWN"] or result["counts"]["CONFLICT"]:
        warnings.append("Unknown or conflicting outcomes are not PASS results.")
    if not result["findings_imported"]:
        warnings.append("No FAIL findings will appear in Overview. The report will still be saved in Scan History.")
    if duplicate:
        warnings.append("This exact report and evidence label are already stored. Reimport refreshes derived evidence without creating another scan.")
    return {**result, "duplicate": duplicate,
            "repeated_observations": len(events) - len(observations), "warnings": warnings}
