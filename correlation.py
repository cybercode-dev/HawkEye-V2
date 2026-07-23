"""
HawkEye Correlation Engine (Module 3)
Chains individually-detected alerts (detector.py) into higher-level
incidents by shared IP, username, and time proximity. A classic example:

    20 failed logins  -->  same IP  -->  root login attempt
                                              |
                                              v
                                    HIGH/CRITICAL severity incident

Correlation never invents new evidence — it only groups and re-scores
alerts that are already backed by real detector output.
"""

import uuid
from collections import defaultdict
from datetime import timedelta

from utils import severity_rank, clamp

CORRELATION_WINDOW = timedelta(hours=2)

SEVERITY_ESCALATION = {2: "High", 3: "Critical", 4: "Critical"}

# Aggregate/global alerts summarize the whole log rather than one specific
# actor, so chaining them into every IP/user incident would just create
# noisy near-duplicates. They still stand alone as alerts — just excluded
# from the correlation grouping itself.
NON_CORRELATABLE_RULES = {"excessive_auth_failure"}


def _escalate_severity(alerts):
    """
    Combining N related alerts escalates severity: 2 correlated alerts ->
    at least High, 3+ -> Critical, capped by the strongest single alert.
    """
    base = max((severity_rank(a["severity"]) for a in alerts), default=1)
    bump = SEVERITY_ESCALATION.get(min(len(alerts), 4), "Medium")
    bump_rank = severity_rank(bump)
    final_rank = max(base, bump_rank)
    for name, rank in [("Critical", 4), ("High", 3), ("Medium", 2), ("Low", 1)]:
        if final_rank >= rank:
            return name
    return "Low"


def _time_overlaps(a, b, window=CORRELATION_WINDOW):
    a_first, a_last = a.get("first_seen"), a.get("last_seen")
    b_first, b_last = b.get("first_seen"), b.get("last_seen")
    if not (a_first and a_last and b_first and b_last):
        return True  # missing timestamps -> don't block correlation on time
    return a_first <= b_last + window and b_first <= a_last + window


def _build_incident(key_type, key_value, alerts):
    alerts_sorted = sorted(alerts, key=lambda a: a["risk_score"], reverse=True)
    severity = _escalate_severity(alerts_sorted)
    rules_chain = " → ".join(a["rule"] for a in alerts_sorted)

    all_ips = sorted(set(ip for a in alerts for ip in a.get("source_ips", [])))
    all_users = sorted(set(u for a in alerts for u in a.get("usernames", [])))
    timestamps_first = [a["first_seen"] for a in alerts if a.get("first_seen")]
    timestamps_last = [a["last_seen"] for a in alerts if a.get("last_seen")]

    risk_score = clamp(max(a["risk_score"] for a in alerts_sorted) + 5 * (len(alerts_sorted) - 1))

    return {
        "id": uuid.uuid4().hex[:12],
        "correlated_by": key_type,
        "correlated_value": key_value,
        "severity": severity,
        "risk_score": risk_score,
        "alert_count": len(alerts_sorted),
        "alerts": alerts_sorted,
        "alert_ids": [a["id"] for a in alerts_sorted],
        "rule_chain": rules_chain,
        "source_ips": all_ips,
        "usernames": all_users,
        "first_seen": min(timestamps_first) if timestamps_first else None,
        "last_seen": max(timestamps_last) if timestamps_last else None,
        "summary": (
            f"{len(alerts_sorted)} correlated alert(s) linked by {key_type} "
            f"'{key_value}': {rules_chain}."
        ),
    }


def correlate_alerts(alerts):
    """
    Groups alerts that share a source IP or a username (and are within
    a reasonable time window of each other) into incidents. An alert can
    appear in more than one incident if it legitimately links multiple
    groups (e.g. an IP-based incident and a username-based incident);
    single, un-correlated alerts are not turned into incidents.

    Returns a list of incident dicts, highest risk first.
    """
    if not alerts:
        return []

    correlatable = [a for a in alerts if a["rule_key"] not in NON_CORRELATABLE_RULES]
    incidents = []

    # --- Correlate by shared source IP ---
    by_ip = defaultdict(list)
    for a in correlatable:
        for ip in a.get("source_ips") or []:
            by_ip[ip].append(a)

    for ip, ip_alerts in by_ip.items():
        distinct_rules = {a["rule_key"] for a in ip_alerts}
        if len(distinct_rules) < 2:
            continue  # need at least 2 *different* attack patterns to call it a chain
        windowed = [a for a in ip_alerts if _time_overlaps(a, ip_alerts[0])]
        if len(windowed) < 2:
            continue
        incidents.append(_build_incident("Source IP", ip, windowed))

    # --- Correlate by shared username ---
    by_user = defaultdict(list)
    for a in correlatable:
        for user in a.get("usernames") or []:
            by_user[user].append(a)

    for user, user_alerts in by_user.items():
        distinct_rules = {a["rule_key"] for a in user_alerts}
        if len(distinct_rules) < 2:
            continue
        windowed = [a for a in user_alerts if _time_overlaps(a, user_alerts[0])]
        if len(windowed) < 2:
            continue
        incidents.append(_build_incident("Username", user, windowed))

    incidents.sort(key=lambda i: i["risk_score"], reverse=True)
    return incidents
