"""
HawkEye Detection Engine (Module 2)
Ten independent, rule-based detectors. Each takes the full list of
normalized events (see parser.py) plus a couple of pre-computed indexes,
and returns zero or more Alert dicts.

Every alert carries: rule, severity, confidence, risk_score, evidence,
plus enough structured data (source_ips, usernames, count, first/last
seen) for the correlation engine (correlation.py) and MITRE mapping
(mitre.py) to consume.
"""

import uuid
from collections import Counter, defaultdict
from datetime import timedelta

from utils import clamp, is_private_ip

# --- Tunable thresholds -------------------------------------------------------

BRUTE_FORCE_THRESHOLD = 10          # failed attempts from one IP
SPRAY_MIN_USERS = 5                 # distinct usernames targeted by one IP
SPRAY_MAX_ATTEMPTS_PER_USER = 3     # low attempts per user = spraying, not brute force
ENUMERATION_MIN_INVALID_USERS = 5   # distinct invalid usernames from one IP
MULTI_IP_MIN_IPS = 4                # distinct IPs targeting one username
EXCESSIVE_FAILURE_RATIO = 0.6       # failed / total ratio, with a minimum volume
EXCESSIVE_FAILURE_MIN_TOTAL = 10
SUSPICIOUS_HOUR_START = 0           # 00:00
SUSPICIOUS_HOUR_END = 5             # 05:00 (inclusive)
SUCCESS_AFTER_FAILURES_MIN = 5      # failures before a success = suspicious

# --- Web/HTTP thresholds -------------------------------------------------
WEB_SCANNING_MIN_ERRORS = 15        # 4xx/5xx responses from one IP = scanning
WEB_LOGIN_BRUTE_MIN = 8             # failed hits on a login-like path from one IP
WEB_HIGH_5XX_MIN = 10               # server errors from one IP


def _new_alert(rule, severity, confidence, risk_score, evidence,
                source_ips=None, usernames=None, count=0,
                first_seen=None, last_seen=None, rule_key=None):
    return {
        "id": uuid.uuid4().hex[:12],
        "rule": rule,
        "rule_key": rule_key or rule,
        "severity": severity,
        "confidence": clamp(confidence),
        "risk_score": clamp(risk_score),
        "evidence": evidence,
        "source_ips": sorted(set(source_ips or [])),
        "usernames": sorted(set(usernames or [])),
        "count": count,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


# --- 1. SSH Brute Force -------------------------------------------------------

def detect_ssh_brute_force(events, **_):
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if e["event_type"] in ("auth_failure", "invalid_user"):
            by_ip[e["source_ip"]].append(e)

    for ip, evs in by_ip.items():
        if not ip or len(evs) < BRUTE_FORCE_THRESHOLD:
            continue
        users = [e["username"] for e in evs if e["username"]]
        timestamps = [e["timestamp"] for e in evs if e["timestamp"]]
        confidence = 70 + min(25, (len(evs) - BRUTE_FORCE_THRESHOLD) * 2)
        risk = 60 + min(35, (len(evs) - BRUTE_FORCE_THRESHOLD) * 2)
        alerts.append(_new_alert(
            rule="SSH Brute Force",
            rule_key="ssh_brute_force",
            severity="High" if len(evs) < 25 else "Critical",
            confidence=confidence,
            risk_score=risk,
            evidence=[f"{len(evs)} failed authentication attempts from {ip}",
                      f"Targeted username(s): {', '.join(sorted(set(users))[:5]) or 'unknown'}"],
            source_ips=[ip], usernames=users, count=len(evs),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))
    return alerts


# --- 2. Password Spraying -----------------------------------------------------

def detect_password_spraying(events, **_):
    """Low attempts per account, but many distinct accounts, from one IP."""
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if e["event_type"] in ("auth_failure", "invalid_user") and e["source_ip"]:
            by_ip[e["source_ip"]].append(e)

    for ip, evs in by_ip.items():
        user_counts = Counter(e["username"] for e in evs if e["username"])
        if len(user_counts) < SPRAY_MIN_USERS:
            continue
        max_per_user = max(user_counts.values())
        if max_per_user > SPRAY_MAX_ATTEMPTS_PER_USER:
            continue  # looks more like brute force against a few accounts
        timestamps = [e["timestamp"] for e in evs if e["timestamp"]]
        alerts.append(_new_alert(
            rule="Password Spraying",
            rule_key="password_spraying",
            severity="High",
            confidence=65 + min(25, len(user_counts) - SPRAY_MIN_USERS),
            risk_score=65,
            evidence=[f"{ip} attempted {sum(user_counts.values())} logins across "
                      f"{len(user_counts)} distinct usernames with low per-account volume",
                      f"Sample targeted accounts: {', '.join(list(user_counts)[:8])}"],
            source_ips=[ip], usernames=list(user_counts), count=sum(user_counts.values()),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))
    return alerts


# --- 3. Invalid User Enumeration ----------------------------------------------

def detect_invalid_user_enumeration(events, **_):
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if e["event_type"] == "invalid_user" and e["source_ip"]:
            by_ip[e["source_ip"]].append(e)

    for ip, evs in by_ip.items():
        users = set(e["username"] for e in evs if e["username"])
        if len(users) < ENUMERATION_MIN_INVALID_USERS:
            continue
        timestamps = [e["timestamp"] for e in evs if e["timestamp"]]
        alerts.append(_new_alert(
            rule="Invalid User Enumeration",
            rule_key="invalid_user_enum",
            severity="Medium",
            confidence=60 + min(30, len(users) - ENUMERATION_MIN_INVALID_USERS),
            risk_score=50,
            evidence=[f"{ip} probed {len(users)} non-existent usernames, "
                      f"consistent with account/username enumeration",
                      f"Sample: {', '.join(sorted(users)[:8])}"],
            source_ips=[ip], usernames=list(users), count=len(evs),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))
    return alerts


# --- 4. Successful Login After Multiple Failures -----------------------------

def detect_success_after_failures(events, **_):
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if e["event_type"] in ("auth_failure", "invalid_user", "auth_success") and e["source_ip"]:
            by_ip[e["source_ip"]].append(e)

    for ip, evs in by_ip.items():
        evs_sorted = sorted(evs, key=lambda e: e["timestamp"] or 0)
        fail_streak = 0
        for e in evs_sorted:
            if e["event_type"] in ("auth_failure", "invalid_user"):
                fail_streak += 1
            elif e["event_type"] == "auth_success":
                if fail_streak >= SUCCESS_AFTER_FAILURES_MIN:
                    alerts.append(_new_alert(
                        rule="Successful Login After Multiple Failures",
                        rule_key="success_after_failures",
                        severity="Critical",
                        confidence=80,
                        risk_score=85,
                        evidence=[f"{fail_streak} failed attempt(s) from {ip} immediately preceded "
                                  f"a successful login as '{e['username']}'",
                                  "This pattern is consistent with a successful brute-force or "
                                  "credential-stuffing compromise."],
                        source_ips=[ip], usernames=[e["username"]] if e["username"] else [],
                        count=fail_streak + 1,
                        first_seen=evs_sorted[0]["timestamp"], last_seen=e["timestamp"],
                    ))
                fail_streak = 0
    return alerts


# --- 5. Root Login Detection --------------------------------------------------

def detect_root_login(events, **_):
    alerts = []
    root_success = [e for e in events if e["event_type"] == "auth_success" and e["username"] == "root"]
    if not root_success:
        return alerts
    ips = [e["source_ip"] for e in root_success if e["source_ip"]]
    timestamps = [e["timestamp"] for e in root_success if e["timestamp"]]
    alerts.append(_new_alert(
        rule="Root Login Detection",
        rule_key="root_login",
        severity="High",
        confidence=90,
        risk_score=70,
        evidence=[f"{len(root_success)} successful direct root login(s) detected",
                  f"Source IP(s): {', '.join(sorted(set(ips))[:5]) or 'unknown'}",
                  "Direct root SSH login is a high-value target and a common "
                  "policy violation (should be disabled in favor of sudo)."],
        source_ips=ips, usernames=["root"], count=len(root_success),
        first_seen=min(timestamps) if timestamps else None,
        last_seen=max(timestamps) if timestamps else None,
    ))
    return alerts


# --- 6. Sudo Privilege Escalation ---------------------------------------------

def detect_sudo_privilege_escalation(events, **_):
    alerts = []
    sudo_events = [e for e in events if e["event_type"] == "sudo_command"]
    if not sudo_events:
        return alerts

    by_user = defaultdict(list)
    for e in sudo_events:
        by_user[e["username"]].append(e)

    sensitive_keywords = ("passwd", "useradd", "usermod", "visudo", "chmod 777",
                           "/etc/shadow", "/etc/sudoers", "systemctl", "iptables", "ufw")

    for user, evs in by_user.items():
        sensitive = [e for e in evs
                     if any(k in (e.get("extra", {}).get("command") or "") for k in sensitive_keywords)]
        if not sensitive:
            continue
        timestamps = [e["timestamp"] for e in sensitive if e["timestamp"]]
        commands = [e["extra"].get("command", "") for e in sensitive]
        alerts.append(_new_alert(
            rule="Sudo Privilege Escalation",
            rule_key="sudo_privesc",
            severity="Medium" if len(sensitive) < 3 else "High",
            confidence=60,
            risk_score=55 + min(25, len(sensitive) * 5),
            evidence=[f"User '{user}' ran {len(sensitive)} sensitive sudo command(s)",
                      f"Example: {commands[0]}" if commands else ""],
            source_ips=[], usernames=[user], count=len(sensitive),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))
    return alerts


# --- 7. Multiple Failed Logins (per account) ----------------------------------

def detect_multiple_failed_logins(events, **_):
    alerts = []
    by_user = defaultdict(list)
    for e in events:
        if e["event_type"] in ("auth_failure", "invalid_user") and e["username"]:
            by_user[e["username"]].append(e)

    for user, evs in by_user.items():
        if len(evs) < 5:
            continue
        ips = [e["source_ip"] for e in evs if e["source_ip"]]
        timestamps = [e["timestamp"] for e in evs if e["timestamp"]]
        alerts.append(_new_alert(
            rule="Multiple Failed Logins",
            rule_key="multiple_failed_logins",
            severity="Medium" if len(evs) < 10 else "High",
            confidence=55 + min(30, len(evs)),
            risk_score=45 + min(30, len(evs)),
            evidence=[f"Account '{user}' had {len(evs)} failed login attempts",
                      f"From {len(set(ips))} distinct IP(s)"],
            source_ips=ips, usernames=[user], count=len(evs),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))
    return alerts


# --- 8. Multiple Source IP Attack (distributed attack on one account) --------

def detect_multi_ip_attack(events, **_):
    alerts = []
    by_user = defaultdict(set)
    events_by_user = defaultdict(list)
    for e in events:
        if e["event_type"] in ("auth_failure", "invalid_user") and e["username"] and e["source_ip"]:
            by_user[e["username"]].add(e["source_ip"])
            events_by_user[e["username"]].append(e)

    for user, ips in by_user.items():
        if len(ips) < MULTI_IP_MIN_IPS:
            continue
        evs = events_by_user[user]
        timestamps = [e["timestamp"] for e in evs if e["timestamp"]]
        alerts.append(_new_alert(
            rule="Multiple Source IP Attack",
            rule_key="multi_ip_attack",
            severity="High",
            confidence=70,
            risk_score=75,
            evidence=[f"Account '{user}' was targeted from {len(ips)} distinct IP addresses",
                      "This distributed pattern suggests a botnet or coordinated attack "
                      "rather than a single misbehaving client."],
            source_ips=list(ips), usernames=[user], count=len(evs),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))
    return alerts


# --- 9. Suspicious Login Time -------------------------------------------------

def detect_suspicious_login_time(events, **_):
    alerts = []
    night_success = [
        e for e in events
        if e["event_type"] == "auth_success" and e["timestamp"]
        and (SUSPICIOUS_HOUR_START <= e["timestamp"].hour <= SUSPICIOUS_HOUR_END)
    ]
    if not night_success:
        return alerts

    by_user = defaultdict(list)
    for e in night_success:
        by_user[e["username"]].append(e)

    for user, evs in by_user.items():
        timestamps = [e["timestamp"] for e in evs]
        ips = [e["source_ip"] for e in evs if e["source_ip"]]
        alerts.append(_new_alert(
            rule="Suspicious Login Time",
            rule_key="suspicious_login_time",
            severity="Low" if len(evs) == 1 else "Medium",
            confidence=45,
            risk_score=35,
            evidence=[f"'{user}' logged in successfully {len(evs)} time(s) between "
                      f"{SUSPICIOUS_HOUR_START:02d}:00-{SUSPICIOUS_HOUR_END:02d}:59, outside typical business hours",
                      f"Time(s): {', '.join(t.strftime('%Y-%m-%d %H:%M') for t in timestamps[:5])}"],
            source_ips=ips, usernames=[user], count=len(evs),
            first_seen=min(timestamps), last_seen=max(timestamps),
        ))
    return alerts


# --- 10. Excessive Authentication Failure (overall volume/ratio) -------------

def detect_excessive_auth_failure(events, **_):
    alerts = []
    failed = [e for e in events if e["event_type"] in ("auth_failure", "invalid_user")]
    total = [e for e in events if e["event_type"] in ("auth_failure", "invalid_user", "auth_success")]
    if not total or len(total) < EXCESSIVE_FAILURE_MIN_TOTAL:
        return alerts

    ratio = len(failed) / len(total)
    if ratio < EXCESSIVE_FAILURE_RATIO:
        return alerts

    ips = [e["source_ip"] for e in failed if e["source_ip"]]
    users = [e["username"] for e in failed if e["username"]]
    timestamps = [e["timestamp"] for e in failed if e["timestamp"]]
    alerts.append(_new_alert(
        rule="Excessive Authentication Failure",
        rule_key="excessive_auth_failure",
        severity="Medium" if ratio < 0.85 else "High",
        confidence=60,
        risk_score=int(ratio * 100),
        evidence=[f"{len(failed)} of {len(total)} authentication events failed ({ratio:.0%})",
                  f"Involves {len(set(ips))} distinct IP(s) and {len(set(users))} distinct username(s)"],
        source_ips=ips, usernames=users, count=len(failed),
        first_seen=min(timestamps) if timestamps else None,
        last_seen=max(timestamps) if timestamps else None,
    ))
    return alerts


# --- 11. Web: SQL Injection Attempt -------------------------------------------

def detect_web_sqli(events, **_):
    return _web_attack_flag_alerts(
        events, flag="sqli",
        rule="SQL Injection Attempt", rule_key="web_sqli",
        severity="Critical", confidence=80, risk_score=90,
        summary="attempted SQL injection payload(s) in the request path/query string",
    )


# --- 12. Web: Cross-Site Scripting Attempt ------------------------------------

def detect_web_xss(events, **_):
    return _web_attack_flag_alerts(
        events, flag="xss",
        rule="Cross-Site Scripting (XSS) Attempt", rule_key="web_xss",
        severity="High", confidence=70, risk_score=75,
        summary="attempted XSS payload(s) in the request path/query string",
    )


# --- 13. Web: Directory Traversal Attempt -------------------------------------

def detect_web_dir_traversal(events, **_):
    return _web_attack_flag_alerts(
        events, flag="dir_traversal",
        rule="Directory Traversal Attempt", rule_key="web_dir_traversal",
        severity="Critical", confidence=75, risk_score=85,
        summary="attempted path/directory traversal request(s) (e.g. '../', '/etc/passwd')",
    )


def _web_attack_flag_alerts(events, flag, rule, rule_key, severity, confidence, risk_score, summary):
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if e["event_type"] != "http_request":
            continue
        if flag in (e.get("extra") or {}).get("attack_flags", []):
            by_ip[e["source_ip"]].append(e)

    for ip, evs in by_ip.items():
        if not ip:
            continue
        timestamps = [e["timestamp"] for e in evs if e["timestamp"]]
        paths = [e["extra"].get("path", "") for e in evs]
        alerts.append(_new_alert(
            rule=rule, rule_key=rule_key, severity=severity,
            confidence=confidence + min(15, len(evs)),
            risk_score=risk_score,
            evidence=[f"{ip} sent {len(evs)} {summary}",
                      f"Example request: {paths[0]}" if paths else ""],
            source_ips=[ip], usernames=[], count=len(evs),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))
    return alerts


# --- 14. Web: Reconnaissance / Scanning (high error-response volume) ---------

def detect_web_scanning(events, **_):
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if e["event_type"] == "http_request" and e["extra"].get("status", 0) >= 400 and e["source_ip"]:
            by_ip[e["source_ip"]].append(e)

    for ip, evs in by_ip.items():
        if len(evs) < WEB_SCANNING_MIN_ERRORS:
            continue
        timestamps = [e["timestamp"] for e in evs if e["timestamp"]]
        not_found = sum(1 for e in evs if e["extra"]["status"] == 404)
        alerts.append(_new_alert(
            rule="Web Reconnaissance / Scanning",
            rule_key="web_scanning",
            severity="Medium" if len(evs) < 30 else "High",
            confidence=65 + min(25, len(evs) - WEB_SCANNING_MIN_ERRORS),
            risk_score=60,
            evidence=[f"{ip} generated {len(evs)} error response(s), including {not_found} 404 Not Found",
                      "This volume of probing is consistent with automated directory/vulnerability scanning."],
            source_ips=[ip], usernames=[], count=len(evs),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))
    return alerts


# --- 15. Web: Login Brute Force -----------------------------------------------

def detect_web_login_brute_force(events, **_):
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if (e["event_type"] == "http_request" and e["extra"].get("is_login_path")
                and e["extra"].get("status", 0) in (401, 403) and e["source_ip"]):
            by_ip[e["source_ip"]].append(e)

    for ip, evs in by_ip.items():
        if len(evs) < WEB_LOGIN_BRUTE_MIN:
            continue
        timestamps = [e["timestamp"] for e in evs if e["timestamp"]]
        alerts.append(_new_alert(
            rule="Web Login Brute Force",
            rule_key="web_login_brute_force",
            severity="High",
            confidence=70,
            risk_score=80,
            evidence=[f"{ip} made {len(evs)} rejected login attempt(s) against login/admin endpoints"],
            source_ips=[ip], usernames=[], count=len(evs),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))
    return alerts


# --- 16. Web: High Server Error Rate (5xx spike) ------------------------------

def detect_web_high_error_rate(events, **_):
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if e["event_type"] == "http_request" and e["extra"].get("status", 0) >= 500 and e["source_ip"]:
            by_ip[e["source_ip"]].append(e)

    for ip, evs in by_ip.items():
        if len(evs) < WEB_HIGH_5XX_MIN:
            continue
        timestamps = [e["timestamp"] for e in evs if e["timestamp"]]
        alerts.append(_new_alert(
            rule="High Server Error Rate",
            rule_key="web_high_error_rate",
            severity="Medium",
            confidence=55,
            risk_score=50,
            evidence=[f"{ip} triggered {len(evs)} server error (5xx) response(s)",
                      "May indicate an exploit attempt causing application crashes, or a struggling backend."],
            source_ips=[ip], usernames=[], count=len(evs),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))
    return alerts


# --- 17. Web: Suspicious User-Agent (known scanner/tooling) -------------------

def detect_web_suspicious_agent(events, **_):
    alerts = []
    by_ip = defaultdict(list)
    seen_agents = {}
    for e in events:
        if e["event_type"] == "http_request" and "suspicious_agent" in (e.get("extra") or {}).get("attack_flags", []):
            by_ip[e["source_ip"]].append(e)
            seen_agents[e["source_ip"]] = e["extra"].get("user_agent", "")

    for ip, evs in by_ip.items():
        if not ip:
            continue
        timestamps = [e["timestamp"] for e in evs if e["timestamp"]]
        alerts.append(_new_alert(
            rule="Suspicious User-Agent (Scanner Tooling)",
            rule_key="web_suspicious_agent",
            severity="Medium",
            confidence=60,
            risk_score=55,
            evidence=[f"{ip} made {len(evs)} request(s) with a known scanner/exploit-tool user-agent",
                      f"User-Agent: {seen_agents.get(ip, 'unknown')}"],
            source_ips=[ip], usernames=[], count=len(evs),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        ))
    return alerts


DETECTORS = [
    detect_ssh_brute_force,
    detect_password_spraying,
    detect_invalid_user_enumeration,
    detect_success_after_failures,
    detect_root_login,
    detect_sudo_privilege_escalation,
    detect_multiple_failed_logins,
    detect_multi_ip_attack,
    detect_suspicious_login_time,
    detect_excessive_auth_failure,
    detect_web_sqli,
    detect_web_xss,
    detect_web_dir_traversal,
    detect_web_scanning,
    detect_web_login_brute_force,
    detect_web_high_error_rate,
    detect_web_suspicious_agent,
]


def run_all_detectors(events):
    """
    Materializes the event stream once (detectors each need multiple
    passes) and runs every detector against it. Returns a flat list of
    alert dicts, highest risk first.
    """
    event_list = list(events)
    alerts = []
    for detector in DETECTORS:
        try:
            alerts.extend(detector(event_list))
        except Exception:
            # A single misbehaving detector must never take down the
            # whole analysis pipeline.
            continue
    alerts.sort(key=lambda a: a["risk_score"], reverse=True)
    return event_list, alerts
