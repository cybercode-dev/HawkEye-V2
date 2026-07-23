"""
HawkEye — Intelligent Security Log Analysis System
Flask application: handles secure upload, log analysis, dashboard
rendering, and PDF/CSV report export.
"""

import io
import json
import os
import uuid
import datetime
import logging
from zoneinfo import ZoneInfo
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_file, abort, session, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

from analyzer import analyze_log, LogAnalysisError
from parser import LogParsingError
from engine import run_siem_analysis
from reports import build_pdf_report, build_csv_report
from report_generator import build_html_report
from ai_assistant import ask_assistant
from mitre import ATTACK_MAP
from geolocation import enrich_ips_with_geo
import history as history_db

# --- App configuration -------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("HAWKEYE_SECRET_KEY", "dev-key-change-in-production")
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1 GB max upload
ALLOWED_EXTENSIONS = {"log", "txt", "csv", "json", "gz"}
TEXT_EXTENSIONS = {"log", "txt"}  # formats analyzer.py's syslog regex path understands directly
GZIP_MAGIC = b"\x1f\x8b"

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
history_db.init_db()


@app.template_filter("format_dt")
def format_dt(value, fmt="%Y-%m-%d %H:%M"):
    """Format a timestamp for display whether it's a live datetime object
    or an ISO string reloaded from the history database."""
    if not value:
        return "—"
    if hasattr(value, "strftime"):
        return value.strftime(fmt)
    try:
        return datetime.datetime.fromisoformat(str(value)).strftime(fmt)
    except (ValueError, TypeError):
        return str(value)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hawkeye")

# In-memory store for the most recent analysis results, keyed by report id.
# (For a production deployment this would live in a database / cache
# instead of process memory.)
REPORT_STORE = {}


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def is_probably_text(raw_bytes):
    """Reject binary uploads disguised with a .log/.txt/.csv/.json extension."""
    if b"\x00" in raw_bytes:
        return False
    try:
        raw_bytes.decode("utf-8", errors="strict")
        return True
    except UnicodeDecodeError:
        # allow latin-1 style logs too
        try:
            raw_bytes.decode("latin-1")
            return True
        except Exception:
            return False


def is_probably_gzip(raw_bytes):
    return raw_bytes[:2] == GZIP_MAGIC


# --- Routes --------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("logfile")

    if not file or file.filename.strip() == "":
        flash("Please choose a log file before uploading.", "error")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)

    if not allowed_file(filename):
        flash("Invalid file type. Supported formats: .log, .txt, .csv, .json, .gz", "error")
        return redirect(url_for("index"))

    raw = file.read()

    if not raw:
        flash("The uploaded file is empty.", "error")
        return redirect(url_for("index"))

    ext = filename.rsplit(".", 1)[1].lower()

    if ext == "gz":
        if not is_probably_gzip(raw):
            flash("This .gz file doesn't look like valid gzip data.", "error")
            return redirect(url_for("index"))
    elif not is_probably_text(raw):
        flash("The uploaded file does not look like a valid text log file.", "error")
        return redirect(url_for("index"))

    # --- Primary parse: the Module 1-5 SIEM pipeline understands every
    # supported format (.log/.txt/.csv/.json/.gz) via parser.py. ---
    try:
        result = run_siem_analysis(raw, filename)
    except LogParsingError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))
    except Exception:
        logger.exception("Unexpected error running SIEM analysis")
        flash("An unexpected error occurred while analyzing the file. Please try again.", "error")
        return redirect(url_for("index"))

    # --- For plain .log/.txt uploads, prefer analyzer.py's dedicated
    # syslog-regex summary numbers (the original, well-tested path) for
    # backward compatibility. Every other field (alerts, incidents,
    # IOCs, MITRE mapping) still comes from the new SIEM engine above. ---
    if ext in TEXT_EXTENSIONS:
        try:
            text = raw.decode("utf-8", errors="ignore")
            legacy_summary = analyze_log(text)
            # analyzer.py's "timeline" is a different shape (a chronological
            # per-event log, not the hourly failed-attempt buckets the charts
            # and PDF/CSV export expect) -- keep the SIEM engine's version.
            legacy_summary.pop("timeline", None)
            result.update(legacy_summary)
        except LogAnalysisError:
            pass  # fall back to the SIEM engine's own summary_from_events()
        except Exception:
            logger.exception("Legacy analyzer failed; continuing with SIEM engine summary")

    result["filename"] = filename
    result["analysis_time"] = datetime.datetime.now(
    ZoneInfo("Asia/Kolkata")
).strftime("%Y-%m-%d %H:%M:%S IST")

    # Enrich the top suspicious IPs with country/city/ISP info. Never let a
    # geolocation hiccup break the report — enrich_ips_with_geo always
    # degrades gracefully.
    try:
        result["top_ips"] = enrich_ips_with_geo(result["top_ips"])
    except Exception:
        logger.exception("Geolocation enrichment failed; continuing without it")

    report_id = uuid.uuid4().hex
    REPORT_STORE[report_id] = result
    session["last_report_id"] = report_id

    try:
        history_db.save_scan(report_id, result)
    except Exception:
        logger.exception("Failed to write scan to history database")

    return render_template("result.html", report_id=report_id, **result)


@app.route("/history")
def view_history():
    scans = history_db.get_history(limit=50)
    return render_template("history.html", scans=scans)


@app.route("/history/clear", methods=["POST"])
def clear_history():
    history_db.delete_history()
    flash("Scan history cleared.", "success")
    return redirect(url_for("view_history"))


@app.route("/history/report/<report_id>")
def view_past_report(report_id):
    """
    Re-render a past report. If it's still in the in-memory REPORT_STORE
    (same app session) the full dashboard is shown; otherwise fall back
    to the summary stored in the history database.
    """
    result = REPORT_STORE.get(report_id)
    if result:
        return render_template("result.html", report_id=report_id, **result)

    scan = history_db.get_scan(report_id)
    if not scan:
        abort(404, description="This report is no longer available.")

    scan["top_ips"] = json.loads(scan.get("top_ips_json") or "[]")
    scan["top_users"] = json.loads(scan.get("top_users_json") or "[]")
    scan["timeline"] = []
    scan["alerts"] = json.loads(scan.get("alerts_json") or "[]")
    scan["incidents"] = json.loads(scan.get("incidents_json") or "[]")
    scan["severity_counts"] = json.loads(scan.get("severity_counts_json") or "{}")
    scan["ioc_flat"] = json.loads(scan.get("ioc_json") or "[]")
    scan["unique_playbooks"] = []  # playbooks are derived at analysis time; not re-derived for archives
    scan["recommended_controls"] = []
    scan["insight"] = (
        "This is an archived summary. Re-upload the original log file for "
        "the full dashboard, live charts, and PDF/CSV export."
    )
    scan.pop("report_id", None)  # avoid clashing with the explicit kwarg below
    scan.pop("id", None)
    return render_template("result.html", report_id=report_id, archived=True, **scan)


@app.route("/live/<report_id>")
def live_replay(report_id):
    """
    Live Log Replay — plays back the already-parsed events for a report in
    a terminal-style UI, color-coded by severity, with running counters.
    Only available for the current in-memory session's reports (same as
    PDF/CSV export), since archived history rows don't retain full events.
    """
    result = REPORT_STORE.get(report_id)
    if not result:
        abort(404, description="This report is no longer available for live replay. "
                                "Please re-run the analysis.")

    events = result.get("events") or []

    # Build a lightweight, JSON-safe timeline capped at a sane size so the
    # browser never has to animate an unreasonable number of DOM updates.
    MAX_REPLAY_EVENTS = 1500
    alert_ips = set()
    alert_users = set()
    for a in result.get("alerts", []):
        alert_ips.update(a.get("source_ips") or [])
        alert_users.update(a.get("usernames") or [])

    replay_events = []
    for e in events[:MAX_REPLAY_EVENTS]:
        ts = e.get("timestamp")
        is_flagged = (e.get("source_ip") in alert_ips) or (e.get("username") in alert_users)
        severity = "flagged" if is_flagged else "info"
        if e.get("event_type") in ("auth_failure", "invalid_user"):
            severity = "high"
        elif e.get("event_type") == "auth_success":
            severity = "success" if not is_flagged else "flagged"
        elif e.get("event_type") == "http_request":
            status = (e.get("extra") or {}).get("status", 200)
            if (e.get("extra") or {}).get("attack_flags"):
                severity = "critical"
            elif status >= 500:
                severity = "high"
            elif status >= 400:
                severity = "medium"
            else:
                severity = "success"

        replay_events.append({
            "time": ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "--",
            "type": e.get("event_type"),
            "ip": e.get("source_ip") or "-",
            "user": e.get("username") or "-",
            "line": (e.get("raw_line") or "")[:220],
            "severity": severity,
        })

    return render_template(
        "live.html",
        report_id=report_id,
        filename=result.get("filename"),
        log_type=result.get("log_type", "auth"),
        threat_score=result.get("threat_score", 0),
        risk=result.get("risk", "Low"),
        risk_class=result.get("risk_class", "low"),
        alert_count=result.get("alert_count", 0),
        total_events=len(events),
        replay_events=replay_events,
        truncated=len(events) > MAX_REPLAY_EVENTS,
    )


@app.route("/assistant")
def assistant_page():
    report_id = request.args.get("report_id") or session.get("last_report_id")
    result = REPORT_STORE.get(report_id) if report_id else None
    recent_scans = history_db.get_history(limit=15)
    return render_template("assistant.html", result=result, report_id=report_id, recent_scans=recent_scans)


@app.route("/assistant/ask", methods=["POST"])
def assistant_ask():
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    report_id = data.get("report_id") or session.get("last_report_id")

    if not question:
        return jsonify({"answer": "Please type a question."}), 400

    result = REPORT_STORE.get(report_id) if report_id else None
    try:
        answer = ask_assistant(question, result)
    except Exception:
        logger.exception("AI assistant failed to answer")
        answer = "Sorry, I ran into an error answering that. Please try rephrasing your question."

    return jsonify({"answer": answer, "report_id": report_id})


@app.route("/mitre")
def mitre_explorer():
    techniques = [{"rule_key": k, **v} for k, v in ATTACK_MAP.items()]
    techniques.sort(key=lambda t: t["technique_id"])
    return render_template("mitre.html", techniques=techniques)


@app.route("/settings")
def settings_page():
    info = {
        "allowed_extensions": sorted(ALLOWED_EXTENSIONS),
        "max_upload_mb": app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024),
        "ai_assistant_llm_enabled": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "history_db_path": history_db.DB_PATH,
        "total_scans": len(history_db.get_history(limit=10_000)),
        "debug_mode": os.environ.get("HAWKEYE_DEBUG", "false"),
    }
    return render_template("settings.html", info=info)


@app.route("/download/pdf/<report_id>")
def download_pdf(report_id):
    result = REPORT_STORE.get(report_id)
    if not result:
        abort(404, description="Report not found or has expired. Please re-run the analysis.")

    logo_path = os.path.join(BASE_DIR, "static", "images", "logo.png")
    pdf_buf = build_pdf_report(result, logo_path=logo_path if os.path.exists(logo_path) else None)

    out_name = f"HawkEye_Report_{result.get('filename', 'log')}.pdf".replace(" ", "_")
    return send_file(
        pdf_buf, mimetype="application/pdf",
        as_attachment=True, download_name=out_name,
    )


@app.route("/download/csv/<report_id>")
def download_csv(report_id):
    result = REPORT_STORE.get(report_id)
    if not result:
        abort(404, description="Report not found or has expired. Please re-run the analysis.")

    csv_buf = build_csv_report(result)
    out_name = f"HawkEye_Report_{result.get('filename', 'log')}.csv".replace(" ", "_")
    return send_file(
        csv_buf, mimetype="text/csv",
        as_attachment=True, download_name=out_name,
    )


@app.route("/download/html/<report_id>")
def download_html(report_id):
    result = REPORT_STORE.get(report_id)
    if not result:
        abort(404, description="Report not found or has expired. Please re-run the analysis.")

    html_out = build_html_report(result)
    out_name = f"HawkEye_Report_{result.get('filename', 'log')}.html".replace(" ", "_")
    buf = io.BytesIO(html_out.encode("utf-8"))
    return send_file(
        buf, mimetype="text/html",
        as_attachment=True, download_name=out_name,
    )


# --- Error handlers --------------------------------------------------------

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    max_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    flash(f"File too large. Maximum upload size is {max_mb} MB.", "error")
    return redirect(url_for("index"))


@app.errorhandler(404)
def handle_404(e):
    return render_template("error.html", code=404, message=str(getattr(e, "description", "Page not found."))), 404


@app.errorhandler(500)
def handle_500(e):
    logger.exception("Internal server error")
    return render_template("error.html", code=500, message="Something went wrong on our end. Please try again."), 500


if __name__ == "__main__":
    debug_mode = os.environ.get("HAWKEYE_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)
