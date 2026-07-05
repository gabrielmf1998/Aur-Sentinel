from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo


LOCAL_ZONE = ZoneInfo("America/Sao_Paulo")


def now_local_string() -> str:
    return datetime.now(LOCAL_ZONE).strftime("%Y-%m-%d %H:%M:%S %Z")


def timestamp_for_path() -> str:
    return datetime.now(LOCAL_ZONE).strftime("%Y%m%d-%H%M%S")


def format_unix_timestamp(value: int | float | str | None) -> str:
    if not value:
        return ""
    try:
        timestamp = float(value)
    except (TypeError, ValueError):
        return str(value)
    return datetime.fromtimestamp(timestamp, LOCAL_ZONE).strftime("%Y-%m-%d %H:%M:%S %Z")
