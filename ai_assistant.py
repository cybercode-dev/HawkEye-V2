"""
HawkEye AI Security Assistant (Module 7)
Answers natural-language questions about a completed analysis, grounded
in that analysis's actual alerts/incidents/IOCs/MITRE data — never
generic or fabricated advice detached from what was actually detected.

Two tiers, so the assistant is fully functional with zero configuration:
  1. Rule-based engine (always available) — pattern-matches the question
     against intents (explain alert / why high risk / explain MITRE /
     how to fix / explain this IP / how to prevent) and answers using the
     scan's real data plus the Module 4/6 MITRE + IR knowledge bases.
  2. Optional LLM enhancement — if ANTHROPIC_API_KEY is set in the
     environment, the same grounded context is handed to Claude for a
     more natural free-form answer. If the key is absent or the request
     fails for any reason, it transparently falls back to tier 1 so the
     assistant never breaks.
"""

import os
import re

from utils import extract_ip
from mitre import get_mitre_info
from incident_response import get_playbook

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-sonnet-4-6"


# --- Context building --------------------------------------------------------

def build_context_snapshot(result):
    """
    Extract a compact, chat-friendly summary of a scan result — used both
    to ground the rule-based engine and, when available, as the prompt
    context for the LLM tier.
    """
    if not result:
        return None

    alerts = result.get("alerts") or []
    incidents = result.get("incidents") or []
    top_alert = alerts[0] if alerts else None

    return {
        "filename": result.get("filename"),
        "threat_score": result.get("threat_score"),
        "siem_threat_score": result.get("siem_threat_score"),
        "risk": result.get("risk"),
        "brute_force": result.get("brute_force"),
        "top_ip": result.get("top_ip"),
        "failed": result.get("failed"),
        "success": result.get("success"),
        "alert_count": len(alerts),
        "incident_count": len(incidents),
        "alerts": alerts,
        "incidents": incidents,
        "top_ips": result.get("top_ips") or [],
        "top_alert": top_alert,
        "mitre_distribution": result.get("mitre_distribution") or {},
        "recommendations": result.get("recommendations") or [],
        "timeline": result.get("timeline") or [],
        "ioc_summary": result.get("ioc_summary") or {},
        "severity_distribution": result.get("severity_distribution") or {},
        "username_stats": result.get("username_stats") or {},
        "geo_locations": result.get("geo_locations") or [],
        "analysis_time": result.get("analysis_time"),
        "log_source": result.get("log_source"),
        "top_attack": result.get("top_attack"),
    }


def _find_alert_by_keyword(alerts, question_lower):
    for a in alerts:
        if a["rule"].lower() in question_lower or a["rule_key"] in question_lower:
            return a
    return None


def _find_ip_in_context(question, ctx):
    ip = extract_ip(question)
    if not ip:
        return None
    for row in ctx.get("top_ips", []):
        if row.get("ip") == ip:
            return row
    for a in ctx.get("alerts", []):
        if ip in a.get("source_ips", []):
            return {"ip": ip, "failed": a.get("count", 0), "success": 0, "from_alert": a}
    return {"ip": ip}


# --- Rule-based intents -------------------------------------------------------

def _answer_explain_alert(ctx, target_alert):

    a = target_alert or ctx.get("top_alert")

    if not a:
        return (
            "✅ No security alerts were detected in this scan.\n\n"
            "The uploaded log appears clean based on the current detection rules."
        )

    mitre = a.get("mitre") or get_mitre_info(a.get("rule_key"))
    ir = a.get("ir") or get_playbook(a.get("rule_key"))

    evidence = a.get("evidence") or []
    evidence_text = "\n".join(f"   • {e}" for e in evidence) if evidence else "   • No evidence available"

    source_ips = a.get("source_ips") or []
    ip_text = ", ".join(source_ips) if source_ips else "Unknown"

    lines = []

    lines.append("🚨 HawkEye Security Alert")
    lines.append("=" * 45)
    lines.append("")

    lines.append(f"📌 Alert")
    lines.append(f"   {a['rule']}")
    lines.append("")

    lines.append(f"🔥 Severity")
    lines.append(f"   {a['severity']}")
    lines.append("")

    lines.append(f"🎯 Risk Score")
    lines.append(f"   {a['risk_score']}/100")
    lines.append("")

    lines.append(f"📈 Confidence")
    lines.append(f"   {a['confidence']}%")
    lines.append("")

    lines.append("🌐 Source IP(s)")
    lines.append(f"   {ip_text}")
    lines.append("")

    lines.append("🧾 Evidence")
    lines.append(evidence_text)
    lines.append("")

    lines.append("🧠 Root Cause")
    lines.append(f"   {ir.get('root_cause','Unknown')}")
    lines.append("")

    lines.append("💥 Business Impact")
    lines.append(f"   {ir.get('business_impact','Potential security impact detected.')}")
    lines.append("")

    if mitre:
        lines.append("🗺 MITRE ATT&CK")
        lines.append(
            f"   {mitre.get('technique_id')} - "
            f"{mitre.get('technique_name')}"
        )
        lines.append(f"   Tactic : {mitre.get('tactic')}")
        lines.append("")

    lines.append("🛡 Recommended Action")

    recovery = ir.get("recovery_steps") or []

    if recovery:
        for step in recovery:
            lines.append(f"   • {step}")
    else:
        lines.append("   • Investigate affected host.")
        lines.append("   • Review authentication logs.")
        lines.append("   • Block malicious IP if confirmed.")

    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("Ask Next:")
    lines.append("• How do I fix this?")
    lines.append("• Explain MITRE")
    lines.append("• Explain this IP")
    lines.append("• Why High Risk?")
    lines.append("• Show Timeline")

    return "\n".join(lines)


def _answer_why_high_risk(ctx, target_alert):

    a = target_alert or ctx.get("top_alert")

    if not a:
        return (
            "✅ No High-Risk security event was detected in the current scan.\n\n"
            f"Overall Risk Level : {ctx.get('risk','Low')}\n"
            f"Threat Score : {ctx.get('threat_score',0)}/100"
        )

    ir = a.get("ir") or get_playbook(a.get("rule_key"))

    evidence = a.get("evidence") or []

    response = []

    response.append("🚨 Risk Assessment")
    response.append("=" * 45)
    response.append("")

    response.append(f"Risk Level : {a['severity']}")
    response.append(f"Threat Score : {a['risk_score']}/100")
    response.append(f"Confidence : {a['confidence']}%")
    response.append("")

    response.append("📌 Why HawkEye marked this as High Risk?")
    response.append("")

    if evidence:
        for item in evidence:
            response.append(f"• {item}")
    else:
        response.append("• Multiple suspicious activities matched detection rules.")

    response.append("")

    response.append("💥 Business Impact")

    impact = ir.get(
        "business_impact",
        "The detected activity may compromise authentication security."
    )

    response.append(impact)
    response.append("")

    response.append("🧠 Detection Logic")

    response.append(
        f"HawkEye assigned a risk score of {a['risk_score']}/100 "
        "based on the severity of the detection rule, confidence level, "
        "log evidence, and attack indicators."
    )

    response.append("")

    response.append("⚠ Recommended Priority")

    if a["risk_score"] >= 90:
        response.append("Immediate investigation required.")
    elif a["risk_score"] >= 70:
        response.append("Investigate as soon as possible.")
    else:
        response.append("Monitor the activity and verify legitimacy.")

    response.append("")
    response.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
    response.append("Next Questions:")
    response.append("• Explain MITRE")
    response.append("• How to fix this?")
    response.append("• Explain this IP")
    response.append("• Show IOC")
    response.append("• Show Timeline")

    return "\n".join(response)


def _answer_explain_mitre(ctx, target_alert):
    if target_alert:
        mitre = target_alert.get("mitre") or get_mitre_info(target_alert.get("rule_key"))
        return (
            f"**{mitre.get('technique_id')} — {mitre.get('technique_name')}**\n"
            f"Tactic: {mitre.get('tactic')}\n\n"
            f"{mitre.get('description')}\n\n"
            f"Reference: {mitre.get('reference')}"
        )
    dist = ctx.get("mitre_distribution") or {}
    if not dist:
        return ("MITRE ATT&CK is a global knowledge base of adversary tactics and techniques. "
                "No techniques were mapped in this scan since no alerts were detected.")
    lines = ["This scan mapped detected activity to the following MITRE ATT&CK techniques:", ""]
    for technique, count in dist.items():
        lines.append(f"- {technique} — {count} alert(s)")
    return "\n".join(lines)


def _answer_how_to_fix(ctx, target_alert):

    a = target_alert or ctx.get("top_alert")

    if not a:
        return (
            "✅ No attack was detected.\n\n"
            "No remediation is required based on the current scan."
        )

    ir = a.get("ir") or get_playbook(a.get("rule_key"))

    mitigation_commands = ir.get("mitigation_commands") or []
    recovery_steps = ir.get("recovery_steps") or []
    prevention = ir.get("prevention") or []
    controls = ir.get("recommended_controls") or []

    lines = []

    lines.append("🛡 HawkEye Incident Response Playbook")
    lines.append("=" * 50)
    lines.append("")

    lines.append(f"🚨 Alert : {a['rule']}")
    lines.append(f"🔥 Severity : {a['severity']}")
    lines.append(f"🎯 Risk Score : {a['risk_score']}/100")
    lines.append("")

    lines.append("⚡ Immediate Actions")

    if mitigation_commands:
        for cmd in mitigation_commands:
            lines.append(f"   $ {cmd}")
    else:
        lines.append("   • Block malicious IP")
        lines.append("   • Review authentication logs")
        lines.append("   • Disable compromised account")

    lines.append("")
    lines.append("🔧 Recovery Steps")

    if recovery_steps:
        for step in recovery_steps:
            lines.append(f"   • {step}")
    else:
        lines.append("   • Reset affected credentials")
        lines.append("   • Review SSH configuration")
        lines.append("   • Verify system integrity")

    lines.append("")
    lines.append("🛡 Long-Term Prevention")

    if prevention:
        for item in prevention:
            lines.append(f"   • {item}")

    elif controls:
        for item in controls:
            lines.append(f"   • {item}")

    else:
        lines.append("   • Enable MFA")
        lines.append("   • Install Fail2Ban")
        lines.append("   • Disable Root Login")
        lines.append("   • Use Strong Password Policy")

    lines.append("")
    lines.append("📋 Analyst Recommendation")

    lines.append(
        "Treat this incident according to your organization's Incident Response "
        "process. Preserve logs, validate affected systems, and monitor for "
        "recurring activity before closing the incident."
    )

    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("Suggested Questions")
    lines.append("• Explain MITRE")
    lines.append("• Explain this IP")
    lines.append("• Why High Risk?")
    lines.append("• Show IOC")
    lines.append("• Show Timeline")
    lines.append("• Executive Summary")

    return "\n".join(lines)


def _answer_how_to_prevent(ctx, target_alert):
    a = target_alert or ctx.get("top_alert")
    if not a:
        return "No attacks were detected in this scan. General best practice: enable MFA, disable root SSH login, and use Fail2Ban."
    ir = a.get("ir") or get_playbook(a.get("rule_key"))
    controls = ir.get("recommended_controls") or ir.get("prevention") or []
    if not controls:
        return f"No specific prevention guidance is documented yet for {a['rule']}."
    return f"To prevent **{a['rule']}** going forward:\n\n" + "\n".join(f"- {c}" for c in controls)


def _answer_explain_ip(ctx, ip_info):

    if not ip_info:
        return (
            "❌ I couldn't find that IP address in the current scan.\n\n"
            "Please enter an IP that exists in the analyzed log."
        )

    ip = ip_info.get("ip", "Unknown")

    failed = ip_info.get("failed", 0)
    success = ip_info.get("success", 0)

    location = (
        ip_info.get("location")
        or ip_info.get("country")
        or "Unknown"
    )

    isp = ip_info.get("isp") or "Unknown"

    related_alerts = [
        a for a in ctx.get("alerts", [])
        if ip in a.get("source_ips", [])
    ]

    lines = []

    lines.append("🌐 HawkEye IP Intelligence")
    lines.append("=" * 45)
    lines.append("")

    lines.append(f"IP Address : {ip}")
    lines.append(f"Country : {location}")
    lines.append(f"ISP : {isp}")
    lines.append("")

    lines.append("📊 Authentication Activity")
    lines.append(f"Failed Logins : {failed}")
    lines.append(f"Successful Logins : {success}")
    lines.append("")

    lines.append(f"🚨 Related Alerts : {len(related_alerts)}")
    lines.append("")

    if related_alerts:

        lines.append("Detected Security Events")

        for alert in related_alerts:

            mitre = alert.get("mitre") or {}

            lines.append(
                f"• {alert['rule']} "
                f"({alert['severity']})"
            )

            if mitre:
                lines.append(
                    f"    ↳ {mitre.get('technique_id','')} "
                    f"{mitre.get('technique_name','')}"
                )

    else:

        lines.append("No security alert is directly associated with this IP.")

    lines.append("")

    lines.append("🛡 Analyst Recommendation")

    if failed >= 20:

        lines.append("• High number of failed logins detected.")
        lines.append("• Block the IP immediately.")
        lines.append("• Investigate authentication attempts.")

    elif failed >= 5:

        lines.append("• Monitor this IP closely.")
        lines.append("• Enable Fail2Ban or firewall rules.")

    else:

        lines.append("• Continue monitoring this IP.")

    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━")

    lines.append("Next Questions")

    lines.append("• Explain MITRE")
    lines.append("• Show Timeline")
    lines.append("• Why High Risk?")
    lines.append("• How to Fix?")
    lines.append("• Executive Summary")

    return "\n".join(lines)

def _answer_timeline(ctx):

    timeline = ctx.get("timeline") or []

    if not timeline:
        return (
            "📅 No event timeline is available for this scan.\n\n"
            "Timeline support will appear when chronological events are generated."
        )

    lines = []

    lines.append("📅 HawkEye Attack Timeline")
    lines.append("=" * 45)
    lines.append("")

    for event in timeline:

        if isinstance(event, dict):

            time = event.get("time") or event.get("timestamp") or "--:--:--"

            activity = (
                event.get("event")
                or event.get("activity")
                or event.get("description")
                or "Unknown Event"
            )

            severity = event.get("severity", "")

            lines.append(f"🕒 {time}")
            lines.append(f"   {activity}")

            if severity:
                lines.append(f"   Severity : {severity}")

            lines.append("")

        else:

            lines.append(f"• {event}")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("Timeline Completed")

    return "\n".join(lines)

def _answer_general_summary(ctx, target_alert=None):

    top_ip = ctx.get("top_ip") or "N/A"
    alerts = ctx.get("alert_count", 0)
    incidents = ctx.get("incident_count", 0)
    failed = ctx.get("failed", 0)
    success = ctx.get("success", 0)
    risk = ctx.get("risk", "Unknown")
    score = ctx.get("threat_score", 0)
    filename = ctx.get("filename", "Unknown")

    lines = []

    lines.append("🛡 HawkEye SOC Analysis Summary")
    lines.append("=" * 45)
    lines.append("")
    lines.append(f"📄 File : {filename}")
    lines.append(f"🚨 Risk Level : {risk}")
    lines.append(f"🎯 Threat Score : {score}/100")
    lines.append("")
    lines.append("📊 Authentication")
    lines.append(f"   • Failed Logins : {failed}")
    lines.append(f"   • Successful Logins : {success}")
    lines.append("")
    lines.append("🚨 Detection")
    lines.append(f"   • Alerts : {alerts}")
    lines.append(f"   • Incidents : {incidents}")
    lines.append("")
    lines.append(f"🌐 Top Attacker : {top_ip}")
    lines.append("")

    if alerts > 0:
        lines.append("⚠ Status : Security events detected.")
    else:
        lines.append("✅ Status : No suspicious activity detected.")

    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("You can also ask:")
    lines.append("• Explain this alert")
    lines.append("• Explain MITRE")
    lines.append("• How to fix this attack?")
    lines.append("• Explain this IP")
    lines.append("• Why High Risk?")
    lines.append("• Show Timeline")
    lines.append("• Show IOC")
    lines.append("• Executive Summary")

    return "\n".join(lines)


INTENT_PATTERNS = [

    # Risk
    (re.compile(r"\bwhy\b.*\b(high|critical)\b.*\brisk\b|\brisk\b"), _answer_why_high_risk),

    # Alert
    (re.compile(r"\b(alert|attack|incident|detection)\b"), _answer_explain_alert),

    # MITRE
    (re.compile(r"\bmitre\b|\battack framework\b"), _answer_explain_mitre),

    # Fix
    (re.compile(r"\bfix\b|\bremediation\b|\bmitigation\b|\bsolution\b"), _answer_how_to_fix),

    # Prevention
    (re.compile(r"\bprevent\b|\bprotection\b|\bhardening\b"), _answer_how_to_prevent),

    # Summary
    (re.compile(r"\bsummary\b|\boverview\b|\bscan summary\b"), _answer_general_summary),

    # Executive
    (re.compile(r"\bexecutive\b"), _answer_general_summary),

    # SOC
    (re.compile(r"\bsoc\b"), _answer_general_summary),

    # IOC
    (re.compile(r"\bioc\b|\bindicator\b"), _answer_general_summary),

    # Timeline
    (re.compile(r"\btimeline\b|\bevents\b|\battack flow\b|\bsequence\b"), _answer_timeline),

    # Confidence
    (re.compile(r"\bconfidence\b"), _answer_why_high_risk),

    # Score
    (re.compile(r"\bscore\b|\bthreat score\b"), _answer_why_high_risk),

    # Evidence
    (re.compile(r"\bevidence\b"), _answer_explain_alert),

    # Recommendation
    (re.compile(r"\brecommend\b|\brecommendation\b"), _answer_how_to_fix),

    # Commands
    (re.compile(r"\bcommand\b|\blinux\b"), _answer_how_to_fix),
]


def ask_assistant(question, result):
    """
    Main entry point. `result` is a full analysis result dict (or None if
    no scan is loaded yet). Returns a plain-text/markdown-ish answer
    string. Tries the LLM tier first (if configured), then always has
    the rule-based tier as a working fallback.
    """
    question = (question or "").strip()
    if not question:
        return "Ask me a question about your scan — e.g. \"why is this high risk?\" or \"how do I fix this attack?\""

    ctx = build_context_snapshot(result)
    if not ctx:
        return ("No scan is currently loaded. Upload and analyze a log file first, "
                "then come back and ask me about the results.")

    if ANTHROPIC_API_KEY:
        llm_answer = _try_llm_answer(question, ctx)
        if llm_answer:
            return llm_answer

    return _rule_based_answer(question, ctx)


def _rule_based_answer(question, ctx):
    q_lower = question.lower()
    target_alert = _find_alert_by_keyword(ctx.get("alerts", []), q_lower)

    ip_mentioned = extract_ip(question)
    if ip_mentioned or "this ip" in q_lower or " ip " in f" {q_lower} ":
        if ip_mentioned:
            return _answer_explain_ip(ctx, _find_ip_in_context(question, ctx))

    for pattern, handler in INTENT_PATTERNS:
        if pattern.search(q_lower):
            return handler(ctx, target_alert)

    if target_alert:
        return _answer_explain_alert(ctx, target_alert)

    return _answer_general_summary(ctx)


def _try_llm_answer(question, ctx):
    """Optional LLM tier. Returns None on any failure so the caller falls
    back to the rule-based engine — the assistant must never break."""
    try:
        import requests
    except ImportError:
        return None

    alerts_summary = "\n".join(
        f"- {a['rule']} (severity={a['severity']}, risk={a['risk_score']}, "
        f"mitre={a.get('mitre', {}).get('technique_id')}, evidence={a.get('evidence')})"
        for a in ctx.get("alerts", [])[:10]
    ) or "No alerts detected."

    system_prompt = (
        "You are HawkEye's built-in Security Assistant, embedded in a SOC dashboard. "
        "Answer the analyst's question using ONLY the scan data provided below. "
        "Be concise, technical, and actionable. Do not invent data not present below.\n\n"
        f"Scan file: {ctx.get('filename')}\n"
        f"Threat score: {ctx.get('threat_score')}/100, Risk: {ctx.get('risk')}\n"
        f"Failed/Success: {ctx.get('failed')}/{ctx.get('success')}\n"
        f"Alerts:\n{alerts_summary}"
    )

    try:
        resp = requests.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 600,
                "system": system_prompt,
                "messages": [{"role": "user", "content": question}],
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        answer = "\n".join(text_blocks).strip()
        return answer or None
    except Exception:
        return None
