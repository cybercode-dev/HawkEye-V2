"""
HawkEye MITRE ATT&CK Mapping (Module 4)
Maps every detection rule (see detector.py's `rule_key`) onto the
corresponding MITRE ATT&CK technique, tactic, and reference link.
"""

# Reference: https://attack.mitre.org
ATTACK_MAP = {
    "ssh_brute_force": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to repeatedly guess "
            "passwords for a known account until a valid credential is found."
        ),
        "reference": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "password_spraying": {
        "technique_id": "T1110.003",
        "technique_name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use a single or small list of commonly used passwords "
            "against many different accounts to attempt to acquire valid credentials "
            "while avoiding account lockouts."
        ),
        "reference": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "invalid_user_enum": {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of valid accounts, usernames, "
            "or email addresses on a system or within a network by probing for their "
            "existence, often via authentication error differences."
        ),
        "reference": "https://attack.mitre.org/techniques/T1087/",
    },
    "success_after_failures": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts as a "
            "means of gaining initial access. A successful login immediately after "
            "repeated failures indicates a likely compromised credential."
        ),
        "reference": "https://attack.mitre.org/techniques/T1078/",
    },
    "root_login": {
        "technique_id": "T1078.003",
        "technique_name": "Valid Accounts: Local Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "description": (
            "Direct authentication as the root/superuser account bypasses "
            "least-privilege controls and provides immediate full system access."
        ),
        "reference": "https://attack.mitre.org/techniques/T1078/003/",
    },
    "sudo_privesc": {
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation / Defense Evasion",
        "description": (
            "Adversaries may perform sudo caching and/or use the suoders file to "
            "elevate privileges, or run sensitive administrative commands to modify "
            "accounts, credentials, or system security controls."
        ),
        "reference": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "multiple_failed_logins": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Repeated failed authentication attempts against a single account "
            "indicate an ongoing credential-guessing attempt."
        ),
        "reference": "https://attack.mitre.org/techniques/T1110/",
    },
    "multi_ip_attack": {
        "technique_id": "T1110",
        "technique_name": "Brute Force (Distributed)",
        "tactic": "Credential Access",
        "description": (
            "Credential attacks distributed across many source IPs against a single "
            "account are consistent with botnet-driven or proxy-rotated brute-forcing "
            "intended to evade IP-based rate limiting."
        ),
        "reference": "https://attack.mitre.org/techniques/T1110/",
    },
    "suspicious_login_time": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts (Anomalous Usage Pattern)",
        "tactic": "Defense Evasion",
        "description": (
            "Logins occurring far outside a user's normal working hours can indicate "
            "use of a compromised account by an adversary in a different timezone or "
            "attempting to avoid detection."
        ),
        "reference": "https://attack.mitre.org/techniques/T1078/",
    },
    "excessive_auth_failure": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "A high overall ratio of failed to successful authentication events "
            "across the log is a strong volumetric indicator of active credential "
            "attacks."
        ),
        "reference": "https://attack.mitre.org/techniques/T1110/",
    },
    "web_sqli": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may attempt to exploit a public-facing web application via SQL "
            "injection to read, modify, or exfiltrate backend database contents."
        ),
        "reference": "https://attack.mitre.org/techniques/T1190/",
    },
    "web_xss": {
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
        "description": (
            "Adversaries may inject malicious client-side scripts (XSS) into a web "
            "application to execute code in victims' browsers, steal session cookies, "
            "or perform actions on their behalf."
        ),
        "reference": "https://attack.mitre.org/techniques/T1059/007/",
    },
    "web_dir_traversal": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may exploit path/directory traversal vulnerabilities to read "
            "files outside a web application's intended root directory."
        ),
        "reference": "https://attack.mitre.org/techniques/T1190/",
    },
    "web_scanning": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": (
            "Adversaries may probe a target web application to discover valid endpoints, "
            "hidden directories, or vulnerabilities ahead of an exploitation attempt."
        ),
        "reference": "https://attack.mitre.org/techniques/T1595/",
    },
    "web_login_brute_force": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may repeatedly guess credentials against a web application's "
            "login endpoint until a valid combination is found."
        ),
        "reference": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "web_high_error_rate": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": (
            "A high volume of server errors from one source may indicate an exploit "
            "attempt destabilizing the application, or a denial-of-service condition."
        ),
        "reference": "https://attack.mitre.org/techniques/T1499/",
    },
    "web_suspicious_agent": {
        "technique_id": "T1595.002",
        "technique_name": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "description": (
            "Requests carrying a known scanner or exploitation-tool user-agent string "
            "(e.g. sqlmap, nikto, nmap) indicate active vulnerability scanning against "
            "the application."
        ),
        "reference": "https://attack.mitre.org/techniques/T1595/002/",
    },
}

DEFAULT_MAPPING = {
    "technique_id": "N/A",
    "technique_name": "Unmapped",
    "tactic": "N/A",
    "description": "No MITRE ATT&CK mapping is defined for this rule yet.",
    "reference": "https://attack.mitre.org",
}


def get_mitre_info(rule_key):
    """Return the MITRE ATT&CK mapping dict for a detector rule_key."""
    return ATTACK_MAP.get(rule_key, DEFAULT_MAPPING)


def attach_mitre(alert):
    """Return a new alert dict with a 'mitre' key merged in."""
    enriched = dict(alert)
    enriched["mitre"] = get_mitre_info(alert.get("rule_key"))
    return enriched


def attach_mitre_bulk(alerts):
    return [attach_mitre(a) for a in alerts]


def mitre_distribution(alerts):
    """Count alerts per MITRE technique — used for the dashboard's MITRE chart."""
    counts = {}
    for a in alerts:
        info = a.get("mitre") or get_mitre_info(a.get("rule_key"))
        key = f"{info['technique_id']} - {info['technique_name']}"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))
