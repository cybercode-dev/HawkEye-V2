"""
HawkEye SIEM Engine
Orchestrates the Module 1-5 pipeline: parse -> detect -> map to MITRE ->
correlate -> extract IOCs. This is the single entry point app.py calls
for the "SIEM view" of an uploaded file (alerts / incidents / IOCs),
kept separate from analyzer.py's simpler summary-stat pipeline so both
can be used side by side without interfering with each other.
"""

import io

from parser import parse_events, LogParsingError
from detector import run_all_detectors
from mitre import attach_mitre_bulk, mitre_distribution
from correlation import correlate_alerts
from ioc import extract_iocs, flatten_iocs
from incident_response import attach_incident_response_bulk, collect_recommended_controls
from utils import risk_level_from_score, clamp


def _web_summary_from_events(http_events):
    """
    Same summary-stat shape as summary_from_events(), computed for web
    server access logs (Apache/Nginx) with no SSH-style auth events at
    all. HTTP error responses (4xx/5xx) stand in for 'failed' and
    successful responses (<400) for 'success' so the existing dashboard
    (pie chart, threat score, top-IP table, etc.) renders meaningfully
    for web traffic too.
    """
    from collections import Counter, defaultdict as dd

    error_events = [e for e in http_events if e["extra"]["status"] >= 400]
    ok_events = [e for e in http_events if e["extra"]["status"] < 400]

    failed = len(error_events)
    success = len(ok_events)
    total = failed + success

    ip_error_counter = Counter(e["source_ip"] for e in error_events if e["source_ip"])
    ip_total_counter = Counter(e["source_ip"] for e in http_events if e["source_ip"])
    top_ips = ip_error_counter.most_common(5) or ip_total_counter.most_common(5)
    top_ips_full = [
        {"ip": ip, "failed": ip_error_counter.get(ip, 0),
         "success": ip_total_counter.get(ip, 0) - ip_error_counter.get(ip, 0)}
        for ip, _ in top_ips
    ]
    top_ip = top_ips[0][0] if top_ips else "N/A"
    attempts = ip_error_counter.get(top_ip, ip_total_counter.get(top_ip, 0)) if top_ips else 0

    url_counter = Counter(e["extra"]["path"] for e in http_events if e["extra"].get("path"))
    top_urls = [{"url": u, "hits": c} for u, c in url_counter.most_common(5)]
    status_distribution = dict(Counter(e["extra"]["status"] for e in http_events))

    timeline_counter = dd(int)
    for e in error_events:
        if e["timestamp"]:
            timeline_counter[e["timestamp"].strftime("%m-%d %H:00")] += 1
    timeline = [{"time": t, "count": c} for t, c in sorted(timeline_counter.items())]

    attack_flag_counter = Counter()
    for e in http_events:
        for flag in e["extra"].get("attack_flags", []):
            attack_flag_counter[flag] += 1

    scanning_ips = [ip for ip, c in ip_error_counter.items() if c >= 15]
    brute_force = "Yes" if scanning_ips else "No"

    error_ratio = failed / total if total else 0
    concentration = (attempts / failed) if failed else 0
    volume_factor = min(failed, 200) / 200
    attack_factor = min(sum(attack_flag_counter.values()), 10) / 10
    score = error_ratio * 25 + concentration * 20 + volume_factor * 20 + attack_factor * 35
    threat_score = int(round(clamp(score)))

    if threat_score >= 70:
        risk, risk_class = "High", "high"
    elif threat_score >= 35:
        risk, risk_class = "Medium", "medium"
    else:
        risk, risk_class = "Low", "low"

    if attack_flag_counter:
        top_attack = attack_flag_counter.most_common(1)[0]
        insight = (
            f"HawkEye detected {sum(attack_flag_counter.values())} web attack pattern(s) in this "
            f"access log, most commonly '{top_attack[0]}' ({top_attack[1]} occurrence(s)). "
            f"Review the flagged requests below and consider a WAF rule or input validation fix."
        )
    elif scanning_ips:
        lead_ip = scanning_ips[0]
        insight = (
            f"HawkEye detected a high volume of error responses ({ip_error_counter[lead_ip]}) from "
            f"{lead_ip}, consistent with automated scanning/probing rather than normal traffic."
        )
    else:
        insight = (
            f"HawkEye processed {total} HTTP request(s) with no significant attack patterns or "
            f"error concentration detected."
        )

    return {
        "failed": failed, "success": success, "total": total,
        "top_ip": top_ip, "attempts": attempts,
        "top_ips": top_ips_full, "top_users": [], "top_urls": top_urls,
        "status_distribution": status_distribution, "timeline": timeline,
        "brute_force": brute_force, "brute_force_ips": scanning_ips,
        "threat_score": threat_score, "risk": risk, "risk_class": risk_class,
        "insight": insight,
        "unique_ips": len(ip_total_counter), "unique_users": 0,
        "log_type": "web_access",
    }


def _generic_summary_from_events(events):
    """
    Last-resort summary for uploads (arbitrary CSV/JSON/text) that contain
    parsed events but none of them match the auth or web-request shapes
    above. Keeps every upload that produced *some* structured data usable
    instead of hard-failing, while being honest that it's a light-weight view.
    """
    from collections import Counter

    total = len(events)
    ip_counter = Counter(e["source_ip"] for e in events if e.get("source_ip"))
    user_counter = Counter(e["username"] for e in events if e.get("username"))
    top_ips_full = [{"ip": ip, "failed": c, "success": 0} for ip, c in ip_counter.most_common(5)]
    top_ip = top_ips_full[0]["ip"] if top_ips_full else "N/A"
    attempts = top_ips_full[0]["failed"] if top_ips_full else 0
    top_users = [{"username": u, "attempts": c} for u, c in user_counter.most_common(5)]

    threat_score = 10 if ip_counter or user_counter else 0
    risk, risk_class = risk_level_from_score(threat_score)

    insight = (
        f"HawkEye parsed {total} event(s) from this file, but none matched a known "
        f"authentication or web-request pattern. Showing a general activity summary; "
        f"for full threat detection, upload a Linux auth.log or Apache/Nginx access log."
    )

    return {
        "failed": 0, "success": 0, "total": total,
        "top_ip": top_ip, "attempts": attempts,
        "top_ips": top_ips_full, "top_users": top_users, "top_urls": [],
        "status_distribution": {}, "timeline": [],
        "brute_force": "No", "brute_force_ips": [],
        "threat_score": threat_score, "risk": risk, "risk_class": risk_class,
        "insight": insight,
        "unique_ips": len(ip_counter), "unique_users": len(user_counter),
        "log_type": "generic",
    }


def summary_from_events(events):
    """
    Produces the same summary-stat shape as analyzer.analyze_log() (failed,
    success, total, top_ips, top_users, timeline, brute_force, threat_score,
    risk, insight, ...) but computed from already-parsed normalized events
    instead of raw syslog text. This is what makes CSV/JSON/GZ uploads (which
    analyzer.py's syslog-only regexes can't read) work end to end through the
    exact same dashboard as .log/.txt uploads.
    """
    from collections import Counter, defaultdict as dd

    failed_events = [e for e in events if e["event_type"] in ("auth_failure", "invalid_user")]
    success_events = [e for e in events if e["event_type"] == "auth_success"]

    total_relevant = len(failed_events) + len(success_events)
    if total_relevant == 0:
        http_events = [e for e in events if e["event_type"] == "http_request"]
        if http_events:
            return _web_summary_from_events(http_events)
        if events:
            return _generic_summary_from_events(events)
        from parser import LogParsingError
        raise LogParsingError(
            "No recognizable events were found in this file."
        )

    failed = len(failed_events)
    success = len(success_events)
    total = failed + success

    ip_failed_counter = Counter(e["source_ip"] for e in failed_events if e["source_ip"])
    ip_total_counter = Counter(e["source_ip"] for e in (failed_events + success_events) if e["source_ip"])
    top_ips = ip_failed_counter.most_common(5)
    top_ips_full = [
        {"ip": ip, "failed": count, "success": ip_total_counter.get(ip, 0) - count}
        for ip, count in top_ips
    ]
    top_ip = top_ips[0][0] if top_ips else "N/A"
    attempts = top_ips[0][1] if top_ips else 0

    user_counter = Counter(e["username"] for e in failed_events if e["username"])
    top_users = [{"username": u, "attempts": c} for u, c in user_counter.most_common(5)]

    timeline_counter = dd(int)
    for e in failed_events:
        if e["timestamp"]:
            timeline_counter[e["timestamp"].strftime("%m-%d %H:00")] += 1
    timeline = [{"time": t, "count": c} for t, c in sorted(timeline_counter.items())]

    brute_force_ips = [ip for ip, c in ip_failed_counter.items() if c >= 10]
    brute_force = "Yes" if brute_force_ips else "No"

    fail_ratio = failed / total if total else 0
    concentration = (attempts / failed) if failed else 0
    username_breadth = min(len(user_counter), 20) / 20
    volume_factor = min(failed, 200) / 200
    score = fail_ratio * 35 + concentration * 30 + username_breadth * 15 + volume_factor * 20
    if brute_force_ips:
        score = min(100, score + 10)
    threat_score = int(round(clamp(score)))

    if threat_score >= 70:
        risk, risk_class = "High", "high"
    elif threat_score >= 35:
        risk, risk_class = "Medium", "medium"
    else:
        risk, risk_class = "Low", "low"

    if brute_force_ips:
        lead_ip = brute_force_ips[0]
        insight = (
            f"HawkEye detected a likely brute-force pattern originating from {lead_ip}, "
            f"with {ip_failed_counter[lead_ip]} failed login attempts. "
            f"{len(user_counter)} unique username(s) were targeted across {failed} failed "
            f"authentication events."
        )
    elif failed > 0:
        insight = (
            f"HawkEye recorded {failed} failed authentication attempt(s) out of {total} total "
            f"events, with no single source crossing the brute-force threshold."
        )
    else:
        insight = "No failed authentication attempts were detected in this log."

    return {
        "failed": failed, "success": success, "total": total,
        "top_ip": top_ip, "attempts": attempts,
        "top_ips": top_ips_full, "top_users": top_users, "timeline": timeline,
        "brute_force": brute_force, "brute_force_ips": brute_force_ips,
        "threat_score": threat_score, "risk": risk, "risk_class": risk_class,
        "insight": insight,
        "unique_ips": len(ip_total_counter), "unique_users": len(user_counter),
        "log_type": "auth",
    }


def run_siem_analysis(file_bytes, filename):
    """
    Run the full Module 1-5 pipeline against raw uploaded file bytes.
    Returns a dict ready to merge into the template context.
    Raises LogParsingError if the file can't be parsed at all.
    """
    events = list(parse_events(io.BytesIO(file_bytes), filename))

    event_list, alerts = run_all_detectors(events)
    alerts = attach_mitre_bulk(alerts)
    alerts = attach_incident_response_bulk(alerts)
    incidents = correlate_alerts(alerts)
    iocs = extract_iocs(event_list)
    ioc_flat = flatten_iocs(iocs)
    recommended_controls = collect_recommended_controls(alerts)

    # One playbook entry per distinct rule actually triggered, for a
    # dedicated "Incident Response Playbooks" section (avoids repeating
    # the same playbook once per individual alert row).
    seen_rules = {}
    for a in alerts:
        if a["rule_key"] not in seen_rules:
            seen_rules[a["rule_key"]] = {"rule": a["rule"], "mitre": a["mitre"], "ir": a["ir"]}
    unique_playbooks = list(seen_rules.values())

    # SIEM-level threat score: driven by the strongest alerts/incidents
    # rather than the simple failure ratio analyzer.py uses — a handful
    # of high-confidence, high-risk alerts should dominate the score.
    if incidents:
        top_scores = sorted((i["risk_score"] for i in incidents), reverse=True)[:3]
    else:
        top_scores = sorted((a["risk_score"] for a in alerts), reverse=True)[:3]
    siem_threat_score = clamp(int(sum(top_scores) / len(top_scores))) if top_scores else 0
    siem_risk, siem_risk_class = risk_level_from_score(siem_threat_score)

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in alerts:
        severity_counts[a["severity"]] = severity_counts.get(a["severity"], 0) + 1

    attack_distribution = {}
    for a in alerts:
        attack_distribution[a["rule"]] = attack_distribution.get(a["rule"], 0) + 1

    return {
        "events": event_list,
        "event_count": len(event_list),
        "alerts": alerts,
        "alert_count": len(alerts),
        "incidents": incidents,
        "incident_count": len(incidents),
        "iocs": iocs,
        "ioc_flat": ioc_flat,
        "siem_threat_score": siem_threat_score,
        "siem_risk": siem_risk,
        "siem_risk_class": siem_risk_class,
        "severity_counts": severity_counts,
        "attack_distribution": attack_distribution,
        "mitre_distribution": mitre_distribution(alerts),
        "recommended_controls": recommended_controls,
        "unique_playbooks": unique_playbooks,
        **summary_from_events(event_list),
    }
