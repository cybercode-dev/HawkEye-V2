"""
HawkEye Scan History
Persists a lightweight record of every analysis run to a local SQLite
database so users can review past scans, trends, and risk levels over
time — independent of the in-memory REPORT_STORE used for one-click
PDF/CSV downloads.
"""

import json
import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hawkeye_history.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    analysis_time TEXT NOT NULL,
    failed INTEGER NOT NULL,
    success INTEGER NOT NULL,
    total INTEGER NOT NULL,
    top_ip TEXT,
    attempts INTEGER,
    unique_ips INTEGER,
    unique_users INTEGER,
    brute_force TEXT,
    threat_score INTEGER,
    risk TEXT,
    risk_class TEXT,
    top_ips_json TEXT,
    top_users_json TEXT,
    siem_threat_score INTEGER,
    siem_risk TEXT,
    alert_count INTEGER,
    incident_count INTEGER,
    severity_counts_json TEXT,
    alerts_json TEXT,
    incidents_json TEXT,
    mitre_distribution_json TEXT,
    ioc_json TEXT,
    pdf_report_path TEXT,
    html_report_path TEXT
);
"""

# Columns added after the original v1 schema — applied via ALTER TABLE for
# anyone upgrading an existing hawkeye_history.db without losing data.
UPGRADE_COLUMNS = [
    ("siem_threat_score", "INTEGER"),
    ("siem_risk", "TEXT"),
    ("alert_count", "INTEGER"),
    ("incident_count", "INTEGER"),
    ("severity_counts_json", "TEXT"),
    ("alerts_json", "TEXT"),
    ("incidents_json", "TEXT"),
    ("mitre_distribution_json", "TEXT"),
    ("ioc_json", "TEXT"),
    ("pdf_report_path", "TEXT"),
    ("html_report_path", "TEXT"),
]


def _json_default(value):
    """Make datetimes (and anything else json can't handle) serializable."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _dumps(value):
    return json.dumps(value, default=_json_default)


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with _connect() as conn:
        conn.execute(SCHEMA)
        for col_name, col_type in UPGRADE_COLUMNS:
            try:
                conn.execute(f"ALTER TABLE scan_history ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass  # column already exists — fine, this is an idempotent upgrade


def save_scan(report_id, result, pdf_report_path=None, html_report_path=None):
    """Persist one analysis result to history, including full SIEM data
    (alerts, incidents, MITRE distribution, IOCs) so archived reports
    can show more than just the summary numbers."""
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO scan_history (
                report_id, filename, analysis_time, failed, success, total,
                top_ip, attempts, unique_ips, unique_users, brute_force,
                threat_score, risk, risk_class, top_ips_json, top_users_json,
                siem_threat_score, siem_risk, alert_count, incident_count,
                severity_counts_json, alerts_json, incidents_json,
                mitre_distribution_json, ioc_json, pdf_report_path, html_report_path
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                report_id,
                result.get("filename", "unknown"),
                result.get("analysis_time", ""),
                result.get("failed", 0),
                result.get("success", 0),
                result.get("total", 0),
                result.get("top_ip", ""),
                result.get("attempts", 0),
                result.get("unique_ips", 0),
                result.get("unique_users", 0),
                result.get("brute_force", "No"),
                result.get("threat_score", 0),
                result.get("risk", ""),
                result.get("risk_class", ""),
                _dumps(result.get("top_ips", [])),
                _dumps(result.get("top_users", [])),
                result.get("siem_threat_score"),
                result.get("siem_risk"),
                result.get("alert_count", 0),
                result.get("incident_count", 0),
                _dumps(result.get("severity_counts", {})),
                _dumps(result.get("alerts", [])),
                _dumps(result.get("incidents", [])),
                _dumps(result.get("mitre_distribution", {})),
                _dumps(result.get("ioc_flat", [])),
                pdf_report_path,
                html_report_path,
            ),
        )


def update_report_paths(report_id, pdf_report_path=None, html_report_path=None):
    """Record where a generated PDF/HTML report was saved for this scan."""
    with _connect() as conn:
        if pdf_report_path:
            conn.execute(
                "UPDATE scan_history SET pdf_report_path = ? WHERE report_id = ?",
                (pdf_report_path, report_id),
            )
        if html_report_path:
            conn.execute(
                "UPDATE scan_history SET html_report_path = ? WHERE report_id = ?",
                (html_report_path, report_id),
            )


def get_history(limit=50):
    """Return the most recent scans, newest first."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def get_scan(report_id):
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scan_history WHERE report_id = ?", (report_id,)
        ).fetchone()
        return dict(row) if row else None


def delete_history():
    """Clear all scan history (used by the 'Clear History' action)."""
    with _connect() as conn:
        conn.execute("DELETE FROM scan_history")
