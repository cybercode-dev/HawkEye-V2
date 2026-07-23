"""
HawkEye Utilities
Shared helpers: timestamp parsing, IP validation, severity/risk helpers,
and small formatting utilities used across the SIEM modules.
"""

import ipaddress
import re
from datetime import datetime

# --- Timestamp parsing -----------------------------------------------------

SYSLOG_TS_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
ISO_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")

ISO_FORMATS = ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")


def parse_timestamp(line, fallback_year=None):
    """
    Best-effort timestamp parser supporting syslog style ("Jan 15 03:22:11")
    and ISO-8601 style ("2026-01-15T03:22:11" / "2026-01-15 03:22:11").
    Returns a datetime or None.
    """
    m = ISO_TS_RE.match(line)
    if m:
        ts = m.group("ts")
        for fmt in ISO_FORMATS:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue

    m = SYSLOG_TS_RE.match(line)
    if m:
        ts = m.group("ts")
        try:
            month_str, day, time_str = ts.split(None, 2)
            year = fallback_year or datetime.now().year
            return datetime.strptime(
                f"{year} {month_str} {int(day):02d} {time_str}", "%Y %b %d %H:%M:%S"
            )
        except Exception:
            return None

    return None


# --- IP helpers --------------------------------------------------------------

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ip(text):
    m = IP_PATTERN.search(text)
    return m.group(0) if m else None


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def is_private_ip(value):
    try:
        addr = ipaddress.ip_address(value)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except (ValueError, TypeError):
        return True


# --- Severity / risk helpers -------------------------------------------------

SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SEVERITY_CLASS = {"Low": "low", "Medium": "medium", "High": "high", "Critical": "critical"}


def severity_rank(severity):
    return SEVERITY_ORDER.get(severity, 0)


def severity_class(severity):
    return SEVERITY_CLASS.get(severity, "low")


def clamp(value, low=0, high=100):
    return max(low, min(high, value))


def risk_level_from_score(score):
    """Shared 0-100 threat score -> (label, css_class) mapping."""
    if score >= 80:
        return "Critical", "critical"
    if score >= 60:
        return "High", "high"
    if score >= 30:
        return "Medium", "medium"
    return "Low", "low"


def safe_get(d, key, default=None):
    return d.get(key, default) if isinstance(d, dict) else default
