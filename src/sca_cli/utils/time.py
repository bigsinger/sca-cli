from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")


def make_scan_id(prefix: str = "") -> str:
    stamp = utc_now().strftime("%Y%m%d-%H%M%S")
    suffix = uuid4().hex[:8]
    if prefix:
        return f"{prefix}-{stamp}-{suffix}"
    return f"{stamp}-{suffix}"
