"""Read OCSF milliseconds and legacy Prowler epoch seconds without guessing timezones."""
from datetime import datetime, timezone
import math


def event_time(event: dict) -> datetime | None:
    candidates = []
    raw = event.get("time")
    if isinstance(raw, (int, float)) and not isinstance(raw, bool) and math.isfinite(raw):
        # Prowler exports seen in this project use seconds despite OCSF's ms convention.
        seconds = raw / 1000 if raw >= 100_000_000_000 else raw
        try:
            value = datetime.fromtimestamp(seconds, timezone.utc)
            if value.year >= 2000:
                candidates.append(value)
        except (ValueError, OverflowError, OSError):
            pass
    try:
        value = datetime.fromisoformat(str(event.get("time_dt", "")).replace("Z", "+00:00"))
        if value.tzinfo is not None:
            candidates.append(value.astimezone(timezone.utc))
    except ValueError:
        pass
    if not candidates or any(t > datetime.now(timezone.utc) for t in candidates):
        return None
    if len(candidates) > 1 and abs((candidates[0] - candidates[1]).total_seconds()) > 1:
        return None
    return candidates[0]
