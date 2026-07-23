"""
HawkEye Smart Log Processing Engine (Module 1)
Streaming, memory-efficient parser supporting .log, .txt, .csv, .json
(JSON Lines or JSON array), Apache/Nginx access logs, and gzip-compressed
variants of any of the above (.gz). Auto-detects format from extension
and, if that fails, by sniffing the first non-empty line.

Design goal: never load the whole file into memory. Everything here is
a generator that yields one normalized event dict at a time.
"""

import csv
import gzip
import io
import json
import re
from datetime import datetime

from utils import parse_timestamp, extract_ip

# --- Normalized event schema -------------------------------------------------
# {
#   "timestamp": datetime | None,
#   "hostname": str | None,
#   "process": str | None,
#   "pid": str | None,
#   "username": str | None,
#   "source_ip": str | None,
#   "event_type": str,      # auth_failure | invalid_user | auth_success |
#                            # sudo_command | session_opened | session_closed | other
#   "auth_result": "failed" | "success" | None,
#   "raw_line": str,
# }

SYSLOG_LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-.\/]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

FAILED_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")
ACCEPTED_RE = re.compile(r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)")
SUDO_RE = re.compile(r"sudo:\s*(?P<user>\S+)\s*:.*COMMAND=(?P<command>.*)")
SUDO_MSG_RE = re.compile(r"^\s*(?P<user>\S+)\s*:.*COMMAND=(?P<command>.*)")
SESSION_OPENED_RE = re.compile(r"session opened for user (?P<user>\S+)")
SESSION_CLOSED_RE = re.compile(r"session closed for user (?P<user>\S+)")

# --- Apache / Nginx access log support --------------------------------------
# Matches the Common Log Format and Combined Log Format, with an optional
# trailing referrer + user-agent pair (Combined format only).
APACHE_LINE_RE = re.compile(
    r'^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

APACHE_TIME_FORMATS = ("%d/%b/%Y:%H:%M:%S", "%d/%b/%Y:%H:%M:%S %z")

WEB_SQLI_RE = re.compile(
    r"(union\s+select|or\s+1=1|information_schema|sleep\(|benchmark\(|"
    r"select\s+.*from|%27|--\s|;--|drop\s+table)",
    re.IGNORECASE,
)
WEB_XSS_RE = re.compile(
    r"(<script|javascript:|onerror=|onload=|alert\(|%3cscript)",
    re.IGNORECASE,
)
WEB_DIR_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow)", re.IGNORECASE)
WEB_LOGIN_PATH_RE = re.compile(r"(login|signin|wp-login|admin|auth)", re.IGNORECASE)
WEB_SUSPICIOUS_AGENT_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|acunetix|nessus|w3af|havij|hydra)",
    re.IGNORECASE,
)


def _parse_apache_time(raw_time):
    """Parse Apache's '23/Jul/2026:10:00:01 +0530' style timestamp."""
    if not raw_time:
        return None
    for fmt in APACHE_TIME_FORMATS:
        try:
            dt = datetime.strptime(raw_time, fmt)
            return dt.replace(tzinfo=None)
        except ValueError:
            continue
    return None


def _classify_web_path(path):
    """Return a list of attack-pattern flags found in a request path."""
    import urllib.parse
    try:
        decoded = urllib.parse.unquote(path)
    except Exception:
        decoded = path
    combined = f"{path} {decoded}"
    flags = []
    if WEB_SQLI_RE.search(combined):
        flags.append("sqli")
    if WEB_XSS_RE.search(combined):
        flags.append("xss")
    if WEB_DIR_TRAVERSAL_RE.search(combined):
        flags.append("dir_traversal")
    return flags


def _parse_apache_line(line):
    """Parse one Apache/Nginx access-log line into a normalized event, or None."""
    line = line.rstrip("\n\r")
    if not line.strip():
        return None

    m = APACHE_LINE_RE.match(line)
    if not m:
        return None

    status = int(m.group("status"))
    path = m.group("path")
    method = m.group("method")
    agent = m.group("agent") or ""
    attack_flags = _classify_web_path(path)
    if WEB_SUSPICIOUS_AGENT_RE.search(agent):
        attack_flags.append("suspicious_agent")

    is_login_path = bool(WEB_LOGIN_PATH_RE.search(path))

    return {
        "timestamp": _parse_apache_time(m.group("time")),
        "hostname": None,
        "process": "apache",
        "pid": None,
        "username": None,
        "source_ip": m.group("ip"),
        "event_type": "http_request",
        "auth_result": None,
        "raw_line": line,
        "extra": {
            "method": method,
            "path": path,
            "status": status,
            "size": m.group("size"),
            "referrer": m.group("referrer"),
            "user_agent": agent,
            "attack_flags": attack_flags,
            "is_login_path": is_login_path,
        },
    }


class LogParsingError(Exception):
    """Raised when a file can't be parsed as any supported log format."""


def _classify_message(msg):
    """
    Given the free-text portion of a log line/message, return
    (event_type, username, source_ip, auth_result, extra).
    """
    m = FAILED_RE.search(msg)
    if m:
        return "auth_failure", m.group("user"), m.group("ip"), "failed", {}

    m = INVALID_USER_RE.search(msg)
    if m:
        return "invalid_user", m.group("user"), m.group("ip"), "failed", {}

    m = ACCEPTED_RE.search(msg)
    if m:
        return "auth_success", m.group("user"), m.group("ip"), "success", {}

    m = SUDO_RE.search(msg)
    if m:
        return "sudo_command", m.group("user"), extract_ip(msg), None, {"command": m.group("command").strip()}

    m = SESSION_OPENED_RE.search(msg)
    if m:
        return "session_opened", m.group("user"), extract_ip(msg), None, {}

    m = SESSION_CLOSED_RE.search(msg)
    if m:
        return "session_closed", m.group("user"), extract_ip(msg), None, {}

    return "other", None, extract_ip(msg), None, {}


def _parse_syslog_line(line):
    """Parse one raw syslog-style line into a normalized event, or None."""
    line = line.rstrip("\n\r")
    if not line.strip():
        return None

    m = SYSLOG_LINE_RE.match(line)
    if m:
        ts = parse_timestamp(line)
        proc = m.group("proc")
        msg = m.group("msg")

        if proc == "sudo":
            sm = SUDO_MSG_RE.search(msg)
            if sm:
                event_type, user, ip = "sudo_command", sm.group("user"), extract_ip(msg)
                result, extra = None, {"command": sm.group("command").strip()}
            else:
                event_type, user, ip, result, extra = _classify_message(msg)
        else:
            event_type, user, ip, result, extra = _classify_message(msg)

        return {
            "timestamp": ts,
            "hostname": m.group("host"),
            "process": proc,
            "pid": m.group("pid"),
            "username": user,
            "source_ip": ip,
            "event_type": event_type,
            "auth_result": result,
            "raw_line": line,
            "extra": extra,
        }

    # Line didn't match the full syslog header (e.g. non-standard format) —
    # still try to classify the free text so we don't silently drop data.
    ts = parse_timestamp(line)
    event_type, user, ip, result, extra = _classify_message(line)
    if event_type == "other" and not ip and not user:
        return None
    return {
        "timestamp": ts,
        "hostname": None,
        "process": None,
        "pid": None,
        "username": user,
        "source_ip": ip,
        "event_type": event_type,
        "auth_result": result,
        "raw_line": line,
        "extra": extra,
    }


# --- Field-name aliases for structured (CSV/JSON) sources -------------------

FIELD_ALIASES = {
    "timestamp": ["timestamp", "time", "date", "datetime", "@timestamp"],
    "username": ["username", "user", "account", "login"],
    "source_ip": ["source_ip", "src_ip", "ip", "client_ip", "remote_ip", "srcip"],
    "hostname": ["hostname", "host", "server"],
    "process": ["process", "proc", "service", "program"],
    "event_type": ["event_type", "event", "type", "action"],
    "auth_result": ["auth_result", "result", "status", "outcome"],
    "message": ["message", "msg", "description", "detail", "raw"],
}


def _pick_field(row, keys):
    lower_map = {str(k).lower(): v for k, v in row.items()}
    for name in keys:
        if name in lower_map and lower_map[name] not in (None, ""):
            return lower_map[name]
    return None


def _normalize_structured_row(row):
    """Map a CSV/JSON row (arbitrary column names) onto the normalized schema."""
    raw_ts = _pick_field(row, FIELD_ALIASES["timestamp"])
    username = _pick_field(row, FIELD_ALIASES["username"])
    source_ip = _pick_field(row, FIELD_ALIASES["source_ip"])
    hostname = _pick_field(row, FIELD_ALIASES["hostname"])
    process = _pick_field(row, FIELD_ALIASES["process"])
    event_type = _pick_field(row, FIELD_ALIASES["event_type"])
    auth_result = _pick_field(row, FIELD_ALIASES["auth_result"])
    message = _pick_field(row, FIELD_ALIASES["message"]) or ""

    ts = None
    if raw_ts:
        ts = parse_timestamp(str(raw_ts)) or _try_iso(str(raw_ts))

    # If the row doesn't explicitly say what happened, infer from any
    # free-text message field using the same classifier as raw logs.
    extra = {}
    if not event_type and message:
        inferred_type, inferred_user, inferred_ip, inferred_result, extra = _classify_message(str(message))
        event_type = inferred_type
        auth_result = auth_result or inferred_result
        username = username or inferred_user
        source_ip = source_ip or inferred_ip

    if isinstance(auth_result, str):
        auth_result = auth_result.strip().lower()
        if auth_result in ("fail", "failed", "failure", "denied", "false", "0"):
            auth_result = "failed"
        elif auth_result in ("success", "succeeded", "accepted", "ok", "true", "1"):
            auth_result = "success"

    if not event_type or event_type == "other":
        if auth_result == "failed":
            event_type = "auth_failure"
        elif auth_result == "success":
            event_type = "auth_success"
        elif not event_type:
            event_type = "other"

    return {
        "timestamp": ts,
        "hostname": hostname,
        "process": process,
        "pid": None,
        "username": username,
        "source_ip": source_ip,
        "event_type": event_type,
        "auth_result": auth_result,
        "raw_line": json.dumps(row, default=str) if not message else str(message),
        "extra": extra,
    }


def _try_iso(value):
    from datetime import datetime
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(value[:19], fmt)
        except (ValueError, TypeError):
            continue
    return None


# --- Format detection ---------------------------------------------------------

def _detect_format(filename, sniff_line):
    name = filename.lower()
    if name.endswith(".gz"):
        name = name[:-3]

    if name.endswith(".csv"):
        return "csv"
    if name.endswith(".json"):
        return "json"

    stripped = (sniff_line or "").strip()

    # Sniff Apache/Nginx access log format regardless of extension (.log,
    # .txt, or ambiguous), since that's how web servers actually name them.
    if APACHE_LINE_RE.match(stripped):
        return "apache"

    if name.endswith((".log", ".txt")):
        return "text"

    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    if stripped.count(",") >= 2 and "\t" not in stripped:
        return "csv"
    return "text"


def _text_stream_from_upload(file_obj, filename):
    """
    Wrap the uploaded file object in a text stream, transparently
    decompressing .gz, without ever reading the whole payload at once.
    """
    if filename.lower().endswith(".gz"):
        binary_stream = gzip.GzipFile(fileobj=file_obj)
    else:
        binary_stream = file_obj
    return io.TextIOWrapper(binary_stream, encoding="utf-8", errors="ignore")


def parse_events(file_obj, filename):
    """
    Stream-parse an uploaded log file of any supported format and yield
    normalized event dicts one at a time. `file_obj` must be a
    binary file-like object positioned at the start of the file.
    """
    try:
        text_stream = _text_stream_from_upload(file_obj, filename)
    except OSError as e:
        raise LogParsingError(f"Could not read '{filename}': the file may not be valid gzip.") from e

    # Peek at the first non-empty line to sniff format if the extension
    # is ambiguous, without consuming it for the real parse pass.
    first_line = ""
    try:
        pos_marker = []
        for line in text_stream:
            if line.strip():
                first_line = line
                pos_marker.append(line)
            break
    except Exception:
        first_line = ""

    fmt = _detect_format(filename, first_line)

    def _chain_first_line():
        if first_line:
            yield first_line
        for line in text_stream:
            yield line

    line_iter = _chain_first_line()

    if fmt == "csv":
        yield from _parse_csv_stream(line_iter)
    elif fmt == "json":
        yield from _parse_json_stream(line_iter)
    elif fmt == "apache":
        yield from _parse_apache_stream(line_iter)
    else:
        yield from _parse_text_stream(line_iter)


def _parse_text_stream(line_iter):
    any_line = False
    for line in line_iter:
        any_line = True
        event = _parse_syslog_line(line)
        if event:
            yield event
    if not any_line:
        raise LogParsingError("The uploaded file is empty.")


def _parse_apache_stream(line_iter):
    any_line = False
    for line in line_iter:
        any_line = True
        event = _parse_apache_line(line)
        if event:
            yield event
    if not any_line:
        raise LogParsingError("The uploaded file is empty.")


def _parse_csv_stream(line_iter):
    reader = csv.DictReader(line_iter)
    if not reader.fieldnames:
        raise LogParsingError("CSV file has no header row / no recognizable columns.")
    any_row = False
    for row in reader:
        any_row = True
        clean_row = {(k or "").strip(): v for k, v in row.items() if k}
        yield _normalize_structured_row(clean_row)
    if not any_row:
        raise LogParsingError("The uploaded CSV file has no data rows.")


def _parse_json_stream(line_iter):
    """
    Supports two JSON shapes:
      1. JSON Lines — one JSON object per line (true streaming).
      2. A single JSON array of objects — read fully (JSON arrays can't
         be split across lines reliably without a streaming JSON parser),
         but still processed as a generator downstream.
    """
    lines = []
    is_jsonl = True
    first_content_line = None

    for line in line_iter:
        stripped = line.strip()
        if not stripped:
            continue
        if first_content_line is None:
            first_content_line = stripped
            if stripped.startswith("["):
                is_jsonl = False
        lines.append(line)

    if first_content_line is None:
        raise LogParsingError("The uploaded JSON file is empty.")

    if is_jsonl:
        any_row = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                any_row = True
                yield _normalize_structured_row(obj)
        if not any_row:
            raise LogParsingError("No valid JSON objects were found (expected JSON Lines or a JSON array).")
    else:
        try:
            data = json.loads("".join(lines))
        except json.JSONDecodeError as e:
            raise LogParsingError(f"Invalid JSON file: {e}") from e
        if isinstance(data, dict):
            data = data.get("events") or data.get("logs") or data.get("data") or [data]
        if not isinstance(data, list) or not data:
            raise LogParsingError("JSON file did not contain a recognizable list of events.")
        for obj in data:
            if isinstance(obj, dict):
                yield _normalize_structured_row(obj)
