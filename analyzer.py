"""
HawkEye Log Analyzer
Parses Linux authentication logs (auth.log / secure style) and produces
security statistics: failed/success counts, top offending IPs, targeted
usernames, an attack timeline, a threat score and a risk classification.
"""

import re
import json
import gzip
from collections import Counter
from datetime import datetime
import stat

# --- Regex patterns for common auth.log / secure log lines -----------------

IP_RE = r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from " + IP_RE
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from " + IP_RE
)
ACCEPTED_RE = re.compile(
    r"Accepted (password|publickey) for (?P<user>\S+) from " + IP_RE
)
# syslog-style timestamp, e.g. "Jan 15 03:22:11"
TIMESTAMP_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
SSH_DISCONNECT_RE = re.compile(
    r"Disconnected from .* " + IP_RE
)

ROOT_LOGIN_RE = re.compile(
    r"Accepted .* for root from " + IP_RE
)

SUDO_RE = re.compile(
    r"sudo:.*COMMAND="
)

SESSION_OPEN_RE = re.compile(
    r"session opened for user (?P<user>\S+)"
) 
# ---------------- Apache Access Log ----------------

APACHE_ACCESS_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

# ---------------- Apache Error Log ----------------

APACHE_ERROR_RE = re.compile(
    r"\[(?P<time>.*?)\].*?\[(?P<level>error|warn|notice|crit)\].*?(?P<message>.*)",
    re.IGNORECASE
)

# ---------------- Web Attack Patterns ----------------

SQLI_RE = re.compile(
    r"(union\s+select|or\s+1=1|information_schema|sleep\(|benchmark\(|select\s+.*from)",
    re.IGNORECASE,
)

XSS_RE = re.compile(
    r"(<script|javascript:|onerror=|onload=|alert\()",
    re.IGNORECASE,
)

DIR_TRAVERSAL_RE = re.compile(
    r"(\.\./|\.\.\\|%2e%2e)",
    re.IGNORECASE,
)
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_timestamp(line, fallback_year=None):
    """Best-effort syslog timestamp parse -> datetime or None."""
    m = TIMESTAMP_RE.match(line)
    if not m:
        return None
    ts = m.group("ts")
    try:
        month_str, day, time_str = ts.split(None, 2)
        year = fallback_year or datetime.now().year
        dt = datetime.strptime(
            f"{year} {month_str} {int(day):02d} {time_str}", "%Y %b %d %H:%M:%S"
        )
        return dt
    except Exception:
        return None


class LogAnalysisError(Exception):
    pass


def analyze_log(text):
    """
    Parse raw log text and return a dict of computed statistics.
    Raises LogAnalysisError if the file doesn't look like a usable auth log.
    """
    lines = text.splitlines()
    log_source = "Linux Authentication Log"

    for line in lines[:30]:
        if APACHE_ACCESS_RE.search(line):
            log_source = "Apache Access Log"
            break
        if APACHE_ERROR_RE.search(line):
            log_source = "Apache Error Log"
            break
    
    if not lines:
        raise LogAnalysisError("The uploaded file is empty.")

    failed_events = []   # (datetime|None, user, ip)
    success_events = []  # (datetime|None, user, ip)
    
    # -------- Advanced Analysis --------
    timeline_events = []
    security_events = []

    ioc_summary = {
        "ips": set(),
        "users": set(),
    }
    apache_requests = []

    apache_status = Counter()

    apache_urls = Counter()

    apache_ips = Counter()

    web_security_events = []
    for line in lines:
        ts = _parse_timestamp(line)
        # ---------------- Apache Access Log ----------------
        if log_source == "Apache Access Log":
            m = APACHE_ACCESS_RE.search(line)
            if not m:
                continue

            ip = m.group("ip")
            url = m.group("url")
            status = int(m.group("status"))
            method = m.group("method")

            apache_requests.append((ip, url, status))

            apache_ips[ip] += 1
            apache_urls[url] += 1
            apache_status[status] += 1

            timeline_events.append({
                "timestamp": None,
                "event": f"{method} {url}",
                "severity": "Info"
            })

            ioc_summary["ips"].add(ip)

            if status >= 500:
                web_security_events.append({
                    "type": "Server Error",
                    "severity": "Medium"
                })
            elif status == 403:
                web_security_events.append({
                    "type": "Forbidden Request",
                    "severity": "Medium"
                })
            elif status == 404:
                web_security_events.append({
                    "type": "Missing Resource",
                    "severity": "Low"
                })

            if SQLI_RE.search(url):
                web_security_events.append({
                    "type": "SQL Injection Attempt",
                    "severity": "Critical"
                })

            if XSS_RE.search(url):
                web_security_events.append({
                    "type": "XSS Attempt",
                    "severity": "High"
                })

            if DIR_TRAVERSAL_RE.search(url):
                web_security_events.append({
                    "type": "Directory Traversal",
                    "severity": "Critical"
                })
            continue

        m = FAILED_RE.search(line)
        if m:
            user = m.group("user")
            ip = m.group("ip")

            failed_events.append((ts, user, ip))

            timeline_events.append({
                "timestamp": ts,
                "event": f"Failed Login ({user})",
                "severity": "Medium"
            })

            ioc_summary["ips"].add(ip)
            ioc_summary["users"].add(user)
            continue

        m = INVALID_USER_RE.search(line)
        if m:
            user = m.group("user")
            ip = m.group("ip")

            failed_events.append((ts, user, ip))

            timeline_events.append({
                "timestamp": ts,
                "event": f"Invalid User ({user})",
                "severity": "High"
            })

            ioc_summary["ips"].add(ip)
            ioc_summary["users"].add(user)

            security_events.append({
                "type": "Invalid User Login",
                "severity": "High"
            })
            security_events.extend(web_security_events)

            continue

        m = ACCEPTED_RE.search(line)
        if m:
            user = m.group("user")
            ip = m.group("ip")

            success_events.append((ts, user, ip))

            timeline_events.append({
                "timestamp": ts,
                "event": f"Successful Login ({user})",
                "severity": "Low"
            })

            ioc_summary["ips"].add(ip)
            ioc_summary["users"].add(user)

            continue

        # -------- Additional Security Events --------
        if ROOT_LOGIN_RE.search(line):
            security_events.append({
                "type": "Root Login",
                "severity": "Critical",
                "timestamp": ts
            })

            timeline_events.append({
                "timestamp": ts,
                "event": "Root Login",
                "severity": "Critical"
            })

        if SUDO_RE.search(line):
            security_events.append({
                "type": "Privilege Escalation",
                "severity": "High",
                "timestamp": ts
            })

            timeline_events.append({
                "timestamp": ts,
                "event": "Sudo Command Executed",
                "severity": "High"
            })

        if SSH_DISCONNECT_RE.search(line):
            security_events.append({
                "type": "SSH Disconnect",
                "severity": "Info",
                "timestamp": ts
            })

            timeline_events.append({
                "timestamp": ts,
                "event": "SSH Session Disconnected",
                "severity": "Info"
            })

    total_relevant = len(failed_events) + len(success_events) + len(apache_requests)
    if total_relevant == 0:
        raise LogAnalysisError(
            "No recognizable SSH authentication or web-access events were found in this "
            "file. Please upload a valid Linux auth.log / secure log or an Apache/Nginx "
            "access log."
        )

    failed = len(failed_events)
    success = len(success_events)
    total = failed + success

    # --- Top suspicious IPs (by failed attempts) ---
    ip_failed_counter = Counter(ip for _, _, ip in failed_events)
    ip_total_counter = Counter(ip for _, _, ip in failed_events + success_events)

    # Pure Apache/Nginx access logs never populate SSH failed/success events,
    # so fall back to error-response volume (4xx/5xx) per IP as the
    # "offending IP" signal for web traffic.
    if log_source == "Apache Access Log" and not ip_failed_counter:
        ip_failed_counter = Counter(ip for ip, _, status in apache_requests if status >= 400)
        ip_total_counter = Counter(ip for ip, _, _ in apache_requests)
        total = len(apache_requests)
        failed = sum(ip_failed_counter.values())
        success = total - failed

    top_ips = ip_failed_counter.most_common(5)
    top_ips_full = [
        {
            "ip": ip,
            "failed": count,
            "success": ip_total_counter[ip] - count if ip in ip_total_counter else 0,
        }
        for ip, count in top_ips
    ]

    top_ip = top_ips[0][0] if top_ips else "N/A"
    attempts = top_ips[0][1] if top_ips else 0

    # --- Username attack statistics ---
    user_counter = Counter(user for _, user, _ in failed_events)
    top_users = [
        {"username": u, "attempts": c} for u, c in user_counter.most_common(5)
    ]
    top_urls = [
        {"url": u, "hits": c}
        for u, c in apache_urls.most_common(5)
    ] if apache_urls else []

    status_distribution = dict(apache_status) if apache_status else {}

    # -------- Detailed Attack Timeline --------

    timeline_events.sort(
        key=lambda x: x["timestamp"] or datetime.min
    )

    timeline = []

    for event in timeline_events:
        ts = event.get("timestamp")

        timeline.append({
            "time": ts.strftime("%H:%M:%S") if ts else "--:--:--",
            "event": event.get("event"),
            "severity": event.get("severity"),
        })

    # --- Brute force detection ---
    brute_force_threshold = 10
    brute_force_ips = [ip for ip, c in ip_failed_counter.items() if c >= brute_force_threshold]
    brute_force = "Yes" if brute_force_ips else "No"

    # --- Threat scoring (0-100) ---
    # Weighted blend of: failure ratio, concentration of attempts from a
    # single IP, breadth of usernames targeted, and raw volume of failures.
    fail_ratio = failed / total if total else 0
    concentration = (attempts / failed) if failed else 0
    username_breadth = min(len(user_counter), 20) / 20
    volume_factor = min(failed, 200) / 200

    score = (
        fail_ratio * 35
        + concentration * 30
        + username_breadth * 15
        + volume_factor * 20
    )
    # -------- Security Event Weighting --------

    critical_events = sum(
        1 for e in security_events
        if e["severity"] == "Critical"
    )

    high_events = sum(
        1 for e in security_events
        if e["severity"] == "High"
    )

    score += critical_events * 8
    score += high_events * 4

    web_critical = sum(
        1 for e in web_security_events
        if e["severity"] == "Critical"
    )

    web_high = sum(
        1 for e in web_security_events
        if e["severity"] == "High"
    )

    score += web_critical * 10
    score += web_high * 5

    if brute_force_ips:
        score = min(100, score + 10)
    threat_score = int(round(min(max(score, 0), 100)))

    if threat_score >= 70:
        risk, risk_class = "High", "high"
    elif threat_score >= 35:
        risk, risk_class = "Medium", "medium"
    else:
        risk, risk_class = "Low", "low"

    # -------- Severity Distribution --------

    severity_distribution = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    for event in timeline_events:
        sev = event.get("severity")
        if sev in severity_distribution:
            severity_distribution[sev] += 1

    # -------- Recommendations --------
    recommendations = []

    if brute_force == "Yes":
        recommendations.extend([
            "Block attacker IP using firewall",
            "Enable Fail2Ban",
            "Disable SSH Root Login",
            "Use SSH Key Authentication",
            "Enable Multi-Factor Authentication (MFA)"
        ])

    elif failed > 0:
        recommendations.extend([
            "Monitor repeated failed logins",
            "Review authentication logs regularly",
            "Enforce strong password policy"
        ])

    else:
        recommendations.append(
            "No immediate action required. Continue monitoring."
        )

    # -------- MITRE ATT&CK Mapping --------
    
    mitre_mapping = []

    if brute_force == "Yes":
        mitre_mapping.append({
            "id": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access"
        })

    if success > 0 and failed > 0:
        mitre_mapping.append({
            "id": "T1078",
            "name": "Valid Accounts",
            "tactic": "Defense Evasion"
        })

    if any(e["type"] == "Privilege Escalation" for e in security_events):
        mitre_mapping.append({
            "id": "T1548",
            "name": "Abuse Elevation Control Mechanism",
            "tactic": "Privilege Escalation"
        })

    if any(e["type"] == "Root Login" for e in security_events):
        mitre_mapping.append({
            "id": "T1078.003",
            "name": "Local Accounts",
            "tactic": "Persistence"
        })
    if any(e["type"] == "SQL Injection Attempt" for e in web_security_events):
        mitre_mapping.append({
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access"
        })

    if any(e["type"] == "Directory Traversal" for e in web_security_events):
        mitre_mapping.append({
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access"
        })

    if any(e["type"] == "XSS Attempt" for e in web_security_events):
        mitre_mapping.append({
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution"
        })

    # --- Insight text ---
    if log_source == "Apache Access Log":
        attack_count = sum(1 for e in web_security_events
                            if e["type"] in ("SQL Injection Attempt", "XSS Attempt", "Directory Traversal"))
        if attack_count:
            insight = (
                f"HawkEye flagged {attack_count} web attack pattern(s) (SQL injection / XSS / "
                f"directory traversal) in this access log. Review the affected requests and "
                f"consider deploying or tightening a Web Application Firewall (WAF)."
            )
        elif brute_force_ips:
            lead_ip = brute_force_ips[0]
            insight = (
                f"HawkEye detected a high volume of error responses ({ip_failed_counter[lead_ip]}) "
                f"from {lead_ip}, consistent with automated scanning/probing rather than normal "
                f"browsing traffic."
            )
        elif failed > 0:
            insight = (
                f"HawkEye recorded {failed} error response(s) (4xx/5xx) out of {total} total "
                f"requests, with no single source showing a clear attack pattern."
            )
        else:
            insight = "No error responses or attack patterns were detected in this access log."
    elif brute_force_ips:
        lead_ip = brute_force_ips[0]
        insight = (
            f"HawkEye detected a likely brute-force pattern originating from {lead_ip}, "
            f"with {ip_failed_counter[lead_ip]} failed login attempts. "
            f"{len(user_counter)} unique username(s) were targeted across {failed} failed "
            f"authentication events. Consider blocking the offending IP address(es), "
            f"enabling fail2ban or equivalent rate limiting, and enforcing key-based "
            f"SSH authentication."
        )
    elif failed > 0:
        insight = (
            f"HawkEye recorded {failed} failed authentication attempt(s) out of {total} total "
            f"events, with no single source crossing the brute-force threshold. "
            f"Continue monitoring {len(ip_failed_counter)} distinct source IP(s) for "
            f"escalating activity."
        )
    else:
        insight = (
            "No failed authentication attempts were detected in this log. "
            "All recorded events were successful logins."
        )

    return {
        "failed": failed,
        "success": success,
        "total": total,
        "top_ip": top_ip,
        "attempts": attempts,
        "top_ips": top_ips_full,
        "top_users": top_users,
        "top_urls": top_urls,
        "status_distribution": status_distribution,
        "timeline": timeline,
        "brute_force": brute_force,
        "brute_force_ips": brute_force_ips,
        "threat_score": threat_score, 
        "risk": risk,
        "risk_class": risk_class,
        "insight": insight,
        "unique_ips": max(len(ip_total_counter), len(apache_ips)),
        "unique_users": len(user_counter),
        "ioc_summary": {
            "ips": sorted(list(ioc_summary["ips"])),
            "users": sorted(list(ioc_summary["users"]))
        },
        "security_events": security_events,
        "web_events": web_security_events,
        "severity_distribution": severity_distribution,
        "mitre_mapping": mitre_mapping,
        "recommendations": recommendations,
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "log_source": log_source,
        "log_type": "web_access" if log_source == "Apache Access Log" else "auth",
    }
