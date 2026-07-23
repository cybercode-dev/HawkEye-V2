"""
HawkEye Incident Response Engine (Module 6)
For every detection rule, provides a structured incident-response
playbook: description, root cause, business impact, concrete Linux
mitigation commands, recovery steps, prevention guidance, and
recommended security controls. Attached to each alert so the dashboard
and PDF/HTML reports can render actionable guidance, not just a verdict.
"""

IR_PLAYBOOKS = {
    "ssh_brute_force": {
        "description": (
            "A single source IP repeatedly attempted to guess valid SSH credentials "
            "via password authentication."
        ),
        "root_cause": (
            "SSH is exposed to a network the attacker can reach, password "
            "authentication is enabled, and there is no rate limiting or lockout "
            "policy on repeated failures."
        ),
        "business_impact": (
            "If successful, grants the attacker a shell on the host, potentially "
            "leading to data theft, lateral movement, ransomware deployment, or use "
            "of the host as a pivot/relay for further attacks."
        ),
        "mitigation_commands": [
            "sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP",
            "sudo ufw deny from <ATTACKER_IP> to any",
            "sudo fail2ban-client set sshd banip <ATTACKER_IP>",
        ],
        "recovery_steps": [
            "Confirm no successful logins occurred from the offending IP (cross-check "
            "the 'Successful Login After Multiple Failures' alert).",
            "If a compromise is confirmed, rotate the affected account's password/keys "
            "and review recent shell history and cron jobs on the host.",
        ],
        "prevention": [
            "Disable SSH password authentication in favor of key-based auth.",
            "Install and configure Fail2Ban to auto-block repeat offenders.",
            "Move SSH to a non-default port and restrict access via a firewall/VPN.",
        ],
        "recommended_controls": [
            "Enable MFA for SSH (e.g. via PAM + TOTP).",
            "Configure Fail2Ban with a short ban-escalation policy.",
            "Enforce key-based authentication only (PasswordAuthentication no).",
        ],
    },
    "password_spraying": {
        "description": (
            "One source IP attempted low-volume logins against many different "
            "usernames — a pattern designed to avoid per-account lockout thresholds."
        ),
        "root_cause": (
            "A large or guessable username space combined with weak/common "
            "passwords in use across the account base, and no IP-based anomaly "
            "detection for 'many accounts, few attempts each' patterns."
        ),
        "business_impact": (
            "Even a low per-account attempt count can eventually succeed against "
            "weak passwords, and success grants the attacker a foothold under a "
            "legitimate, less-scrutinized account."
        ),
        "mitigation_commands": [
            "sudo ufw deny from <ATTACKER_IP> to any",
            "sudo fail2ban-client set sshd banip <ATTACKER_IP>",
        ],
        "recovery_steps": [
            "Force a password reset for every targeted account.",
            "Review authentication logs for any of the targeted accounts showing a "
            "success event.",
        ],
        "prevention": [
            "Enforce a strong password policy and reject breached/common passwords.",
            "Rate-limit authentication attempts per source IP across all accounts, "
            "not just per account.",
        ],
        "recommended_controls": [
            "Enable MFA account-wide.",
            "Deploy an account-lockout policy that also considers cross-account "
            "velocity from a single source.",
        ],
    },
    "invalid_user_enum": {
        "description": (
            "One source IP probed many usernames that don't exist on the system, "
            "consistent with reconnaissance / username enumeration ahead of a "
            "targeted attack."
        ),
        "root_cause": (
            "SSH is reachable from the internet and the service's error responses "
            "(or timing) allow an attacker to distinguish valid from invalid "
            "usernames."
        ),
        "business_impact": (
            "Enumeration itself doesn't compromise the system, but narrows the "
            "attacker's target list for a follow-up brute-force or spraying attack."
        ),
        "mitigation_commands": [
            "sudo ufw deny from <ATTACKER_IP> to any",
        ],
        "recovery_steps": [
            "No account compromise implied by enumeration alone — monitor the same "
            "IP for follow-up brute-force/spraying alerts.",
        ],
        "prevention": [
            "Keep OpenSSH patched (recent versions reduce username-enumeration timing "
            "differences).",
            "Restrict SSH exposure to known IP ranges or a VPN/bastion host.",
        ],
        "recommended_controls": [
            "Deploy an intrusion-detection/prevention rule for rapid multi-username "
            "probing from a single source.",
        ],
    },
    "success_after_failures": {
        "description": (
            "A source IP had several consecutive failed login attempts immediately "
            "followed by a successful login — a strong indicator of a compromised "
            "credential."
        ),
        "root_cause": (
            "A weak or reused password was eventually guessed, or valid credentials "
            "were obtained separately (e.g. leaked elsewhere) and confirmed via a "
            "short guessing sequence."
        ),
        "business_impact": (
            "High — this pattern indicates likely successful initial access. "
            "Treat as an active incident, not just a detection."
        ),
        "mitigation_commands": [
            "sudo pkill -KILL -u <COMPROMISED_USER>   # terminate active sessions",
            "sudo passwd -l <COMPROMISED_USER>          # lock the account immediately",
        ],
        "recovery_steps": [
            "Immediately rotate the compromised account's password and any SSH keys.",
            "Review shell history, cron jobs, authorized_keys, and running processes "
            "for that account.",
            "Check for new SSH keys or backdoor accounts created after the login.",
        ],
        "prevention": [
            "Enforce MFA so a guessed password alone is insufficient.",
            "Set an account lockout threshold below the observed failure count.",
        ],
        "recommended_controls": [
            "Enable MFA.",
            "Enable real-time alerting on this exact pattern (fail-streak + success).",
        ],
    },
    "root_login": {
        "description": (
            "A successful direct login as the root/superuser account was recorded."
        ),
        "root_cause": (
            "SSH is configured to permit root login (PermitRootLogin yes), so "
            "authentication directly as root — the highest-privilege account — is "
            "possible without first authenticating as a lower-privilege user."
        ),
        "business_impact": (
            "Root sessions bypass least-privilege controls entirely; any compromise "
            "of this credential grants full system control immediately."
        ),
        "mitigation_commands": [
            "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
            "sudo systemctl restart sshd",
        ],
        "recovery_steps": [
            "Confirm this login was expected/authorized; if not, treat as a full "
            "compromise and rotate all credentials on the host.",
        ],
        "prevention": [
            "Disable direct root login; require sudo from a named account instead.",
            "Audit sudoers and named accounts regularly.",
        ],
        "recommended_controls": [
            "PermitRootLogin no in sshd_config.",
            "Require MFA + sudo for any privileged action.",
        ],
    },
    "sudo_privesc": {
        "description": (
            "A user account ran one or more sensitive administrative commands via "
            "sudo (e.g. modifying passwords, sudoers, firewall rules, or system "
            "services)."
        ),
        "root_cause": (
            "The account holds sudo privileges broad enough to run sensitive "
            "commands, and either that access was intentional (routine admin work) "
            "or the account itself is compromised."
        ),
        "business_impact": (
            "If the account is compromised, sudo access means the attacker can "
            "achieve full root-equivalent control — this alert alone does not "
            "distinguish legitimate admin activity from abuse."
        ),
        "mitigation_commands": [
            "sudo passwd -l <USER>   # if the activity is confirmed malicious",
            "sudo visudo   # review and tighten this user's sudoers entry",
        ],
        "recovery_steps": [
            "Correlate against other alerts for this user/IP (brute force, root "
            "login) to judge whether this is legitimate admin work or abuse.",
            "Review the exact command(s) run and any resulting system/config changes.",
        ],
        "prevention": [
            "Apply least-privilege sudoers rules (restrict to specific commands "
            "rather than ALL=(ALL)).",
            "Log all sudo command usage centrally (auditd / sudo I/O logging).",
        ],
        "recommended_controls": [
            "Enable detailed sudo logging (Defaults logfile=... or auditd).",
            "Require MFA for sudo (pam_google_authenticator or similar).",
        ],
    },
    "multiple_failed_logins": {
        "description": (
            "A single account accumulated many failed login attempts, possibly "
            "from more than one source."
        ),
        "root_cause": (
            "The account is a live target for credential attacks — commonly due to "
            "a predictable username (root, admin) or because it appeared in a "
            "leaked-credential list."
        ),
        "business_impact": (
            "Sustained attack pressure on one account increases the odds of "
            "eventual compromise, especially with a weak password."
        ),
        "mitigation_commands": [
            "sudo fail2ban-client set sshd banip <ATTACKER_IP>",
        ],
        "recovery_steps": [
            "Force a password reset for the targeted account as a precaution.",
        ],
        "prevention": [
            "Rename/disable high-value default usernames where possible.",
            "Apply account lockout after N consecutive failures.",
        ],
        "recommended_controls": [
            "MFA on all accounts, especially administrative ones.",
            "Fail2Ban or equivalent adaptive rate limiting.",
        ],
    },
    "multi_ip_attack": {
        "description": (
            "A single account was targeted with failed logins from many distinct "
            "source IPs — consistent with a distributed/botnet-driven attack."
        ),
        "root_cause": (
            "The account is being targeted by a coordinated or automated "
            "distributed attack, often via a botnet or rotating proxy pool "
            "specifically to evade single-IP rate limiting."
        ),
        "business_impact": (
            "Per-IP blocking is ineffective against this pattern; the account "
            "remains at risk until account-level controls are applied."
        ),
        "mitigation_commands": [
            "sudo passwd -l <TARGETED_USER>   # temporary lock while investigating",
        ],
        "recovery_steps": [
            "Apply an account-level (not just IP-level) lockout/rate-limit.",
            "Force a password reset and consider a temporary account lock.",
        ],
        "prevention": [
            "Apply per-account rate limiting independent of source IP.",
            "Consider geo-based access restrictions if the account has no need for "
            "global access.",
        ],
        "recommended_controls": [
            "MFA — the single most effective control against distributed credential "
            "attacks.",
            "Web Application Firewall / reverse proxy with adaptive rate limiting "
            "if applicable.",
        ],
    },
    "suspicious_login_time": {
        "description": (
            "A successful login occurred well outside the account's typical "
            "working hours (00:00-05:59)."
        ),
        "root_cause": (
            "Either legitimate off-hours/remote work, or use of a compromised "
            "account by an adversary in a different timezone."
        ),
        "business_impact": (
            "Low confidence on its own, but combined with other alerts on the same "
            "account/IP it strengthens the case for compromise."
        ),
        "mitigation_commands": [],
        "recovery_steps": [
            "Verify with the account owner whether this login was expected.",
        ],
        "prevention": [
            "Establish user behavior baselines and alert on deviations.",
        ],
        "recommended_controls": [
            "User and Entity Behavior Analytics (UEBA) if available.",
            "Conditional access policies based on time/location where supported.",
        ],
    },
    "excessive_auth_failure": {
        "description": (
            "The overall ratio of failed to successful authentication events "
            "across the log is unusually high."
        ),
        "root_cause": (
            "Volumetric credential attack activity across multiple accounts/IPs, "
            "or (less likely) a misconfigured client repeatedly failing to "
            "authenticate."
        ),
        "business_impact": (
            "Indicates broad attack pressure on the host; individual per-account or "
            "per-IP alerts above provide the specific actionable detail."
        ),
        "mitigation_commands": [
            "sudo fail2ban-client status sshd   # review currently banned IPs",
        ],
        "recovery_steps": [
            "Review the specific alerts above (brute force / spraying / multi-IP) "
            "for concrete remediation targets.",
        ],
        "prevention": [
            "Deploy Fail2Ban or equivalent with a low tolerance threshold.",
        ],
        "recommended_controls": [
            "Centralized log monitoring with alerting on failure-ratio thresholds.",
        ],
    },
    "web_sqli": {
        "description": (
            "One or more requests contained a SQL injection payload in the URL path or "
            "query string, attempting to manipulate the backend database query."
        ),
        "root_cause": (
            "User-supplied input is concatenated directly into SQL queries without "
            "parameterization, escaping, or an ORM layer."
        ),
        "business_impact": (
            "Successful exploitation can expose or modify the entire database, including "
            "credentials, personal data, or financial records."
        ),
        "mitigation_commands": [
            "sudo ufw deny from <ATTACKER_IP> to any",
            "# Enable/verify a WAF rule set (e.g. OWASP CRS) in front of the application",
        ],
        "recovery_steps": [
            "Review application/database logs for any query that actually executed the payload.",
            "Rotate database credentials if compromise is suspected.",
        ],
        "prevention": [
            "Use parameterized queries / prepared statements everywhere.",
            "Deploy a Web Application Firewall (WAF) with SQLi rule sets enabled.",
        ],
        "recommended_controls": [
            "Parameterized queries or an ORM for all database access.",
            "WAF with OWASP Core Rule Set (or equivalent).",
        ],
    },
    "web_xss": {
        "description": (
            "One or more requests contained a cross-site scripting (XSS) payload in the "
            "URL path or query string."
        ),
        "root_cause": (
            "User input is reflected or stored and rendered in HTML/JS context without "
            "output encoding or a Content-Security-Policy."
        ),
        "business_impact": (
            "Can lead to session hijacking, credential theft, or actions performed on "
            "behalf of a victim user in their browser session."
        ),
        "mitigation_commands": [
            "sudo ufw deny from <ATTACKER_IP> to any",
        ],
        "recovery_steps": [
            "Check whether the payload was ever stored/rendered back to other users.",
            "Invalidate active sessions if stored XSS is confirmed.",
        ],
        "prevention": [
            "Encode all user-supplied output rendered into HTML/JS/attributes.",
            "Deploy a strict Content-Security-Policy (CSP) header.",
        ],
        "recommended_controls": [
            "Context-aware output encoding on every user-controlled field.",
            "Content-Security-Policy header restricting inline scripts.",
        ],
    },
    "web_dir_traversal": {
        "description": (
            "One or more requests attempted to traverse outside the web root (e.g. "
            "'../' sequences or a direct request for '/etc/passwd')."
        ),
        "root_cause": (
            "File paths are built from user input without normalization or a strict "
            "allow-list of accessible files."
        ),
        "business_impact": (
            "Can expose configuration files, credentials, or source code stored on the "
            "server outside the intended web-accessible directory."
        ),
        "mitigation_commands": [
            "sudo ufw deny from <ATTACKER_IP> to any",
        ],
        "recovery_steps": [
            "Confirm whether any traversal request returned a 200 OK (successful read).",
            "Rotate any credentials found in exposed configuration files.",
        ],
        "prevention": [
            "Normalize and validate file paths against an allow-list before serving.",
            "Run the web server process with least-privilege filesystem access.",
        ],
        "recommended_controls": [
            "Strict path normalization/allow-listing for all file-serving endpoints.",
            "Chroot/containerized filesystem isolation for the web server process.",
        ],
    },
    "web_scanning": {
        "description": (
            "A single source generated a large volume of error responses (mostly 404s), "
            "consistent with automated directory/vulnerability scanning."
        ),
        "root_cause": (
            "The application is reachable from the internet with no rate limiting on "
            "repeated invalid requests from a single source."
        ),
        "business_impact": (
            "Reconnaissance often precedes a targeted exploitation attempt once a "
            "vulnerable endpoint is discovered."
        ),
        "mitigation_commands": [
            "sudo ufw deny from <ATTACKER_IP> to any",
            "# Rate-limit at the reverse proxy / WAF layer",
        ],
        "recovery_steps": [
            "Review which endpoints returned a non-404 status to the scanning IP.",
        ],
        "prevention": [
            "Rate-limit requests per IP at the reverse proxy or WAF layer.",
            "Hide or restrict access to admin/debug endpoints from the public internet.",
        ],
        "recommended_controls": [
            "Reverse proxy / WAF rate limiting per source IP.",
            "Centralized web-log monitoring with alerting on error-rate spikes.",
        ],
    },
    "web_login_brute_force": {
        "description": (
            "A single source made many rejected attempts against a login/admin endpoint."
        ),
        "root_cause": (
            "The login endpoint has no rate limiting, CAPTCHA, or account-lockout policy."
        ),
        "business_impact": (
            "Successful brute forcing grants the attacker a valid application account, "
            "potentially with administrative privileges."
        ),
        "mitigation_commands": [
            "sudo ufw deny from <ATTACKER_IP> to any",
        ],
        "recovery_steps": [
            "Check for any 200/302 (successful) response mixed into the failed attempts.",
            "Force a password reset for any account that was targeted repeatedly.",
        ],
        "prevention": [
            "Add rate limiting and CAPTCHA to the login endpoint.",
            "Enforce account lockout after N consecutive failures.",
        ],
        "recommended_controls": [
            "MFA on the web application login.",
            "Rate limiting / CAPTCHA on authentication endpoints.",
        ],
    },
    "web_high_error_rate": {
        "description": (
            "A single source triggered an unusually high number of server error (5xx) "
            "responses."
        ),
        "root_cause": (
            "Could be an exploit attempt destabilizing the application, a resource "
            "exhaustion condition, or an unrelated application bug being repeatedly hit."
        ),
        "business_impact": (
            "Repeated crashes/errors can indicate an active exploitation attempt or "
            "degrade service availability for legitimate users."
        ),
        "mitigation_commands": [
            "# Review application error logs correlated to this source IP and time window",
        ],
        "recovery_steps": [
            "Check application logs/stack traces for the same time window.",
        ],
        "prevention": [
            "Add input validation before requests reach fragile application code paths.",
            "Monitor and alert on 5xx rate spikes in real time.",
        ],
        "recommended_controls": [
            "Application performance monitoring (APM) with 5xx alerting.",
        ],
    },
    "web_suspicious_agent": {
        "description": (
            "Requests were made using a known scanner or exploitation-tool user-agent "
            "string (e.g. sqlmap, nikto, nmap)."
        ),
        "root_cause": (
            "The application is reachable by automated security-testing/exploitation "
            "tooling with no user-agent-based filtering or WAF in place."
        ),
        "business_impact": (
            "Indicates active, tool-assisted reconnaissance or exploitation attempts "
            "against the application."
        ),
        "mitigation_commands": [
            "sudo ufw deny from <ATTACKER_IP> to any",
        ],
        "recovery_steps": [
            "Cross-check this IP's activity against the other web alerts above.",
        ],
        "prevention": [
            "Deploy a WAF that fingerprints and blocks known scanner user-agents.",
        ],
        "recommended_controls": [
            "WAF with bot/scanner user-agent fingerprinting enabled.",
        ],
    },
}

DEFAULT_PLAYBOOK = {
    "description": "No detailed playbook is defined for this rule yet.",
    "root_cause": "Not documented.",
    "business_impact": "Review manually.",
    "mitigation_commands": [],
    "recovery_steps": [],
    "prevention": [],
    "recommended_controls": [],
}


def get_playbook(rule_key):
    return IR_PLAYBOOKS.get(rule_key, DEFAULT_PLAYBOOK)


def attach_incident_response(alert):
    """Return a new alert dict with an 'ir' key holding its IR playbook."""
    enriched = dict(alert)
    enriched["ir"] = get_playbook(alert.get("rule_key"))
    return enriched


def attach_incident_response_bulk(alerts):
    return [attach_incident_response(a) for a in alerts]


def collect_recommended_controls(alerts):
    """De-duplicated list of recommended controls across all alerts, for the
    report's 'Recommendations' section."""
    seen = []
    for a in alerts:
        for control in (a.get("ir") or {}).get("recommended_controls", []):
            if control not in seen:
                seen.append(control)
    return seen
