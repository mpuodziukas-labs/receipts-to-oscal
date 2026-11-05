"""RFC 3339 date-time parsing without third-party code (fromisoformat differs across versions)."""
import re
from datetime import datetime, timedelta, timezone

_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})")


def parse(text):
    """Return an aware UTC datetime, or None when text is not a valid RFC 3339 date-time."""
    if not isinstance(text, str):
        return None
    m = _RE.fullmatch(text)
    if not m:
        return None
    try:
        when = datetime(*(int(m.group(i)) for i in range(1, 7)), tzinfo=timezone.utc)
    except ValueError:
        return None
    zone = m.group(8)
    if zone != "Z":
        hours, minutes = int(zone[1:3]), int(zone[4:6])
        if hours > 23 or minutes > 59:
            return None
        offset = timedelta(hours=hours, minutes=minutes)
        when = when - offset if zone[0] == "+" else when + offset
    return when


def fmt(when):
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
