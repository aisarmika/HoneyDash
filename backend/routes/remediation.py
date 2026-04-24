"""
Dynamic remediation steps — HD_UC_13

GET /api/remediation?attack_type=SSH+Brute+Force
  → returns generic steps for that attack class

GET /api/remediation/session/{session_id}
  → returns steps enriched with session context
    (extra urgency flags if login succeeded, malware downloaded, ML anomaly, etc.)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import IPEnrichment, Session

router = APIRouter()

# ─── Remediation library ─────────────────────────────────────────────────────

_LIBRARY: dict[str, dict] = {
    "SSH Brute Force": {
        "icon": "fa-user-slash",
        "color": "warning",
        "description": "Systematic credential-guessing over SSH from a single source.",
        "immediate": [
            "Block the source IP at your firewall or security group",
            "Check /var/log/auth.log for any successful logins from this IP",
            "Verify no new user accounts were created",
        ],
        "short_term": [
            "Disable password-based SSH — enforce SSH key authentication only",
            "Move SSH to a non-standard port (e.g. 2222) to reduce automated attacks",
            "Deploy fail2ban: ban after 3 failures within 60 seconds",
            "Implement IP allowlisting for SSH management access",
        ],
        "long_term": [
            "Deploy an IDS/IPS (Snort or Suricata) with SSH brute-force signatures",
            "Implement SIEM alerting for repeated authentication failures",
            "Conduct an SSH hardening audit following CIS Benchmark Level 2",
        ],
    },
    "SSH Login": {
        "icon": "fa-door-open",
        "color": "danger",
        "description": "Attacker successfully authenticated to SSH.",
        "immediate": [
            "IMMEDIATELY block the source IP at all network boundaries",
            "Terminate any active SSH sessions from this IP: pkill -u <user> sshd",
            "Rotate all credentials on the compromised host",
            "Isolate the host from internal networks if possible",
        ],
        "short_term": [
            "Audit all commands executed during the session (see Timeline tab)",
            "Check for persistence: cron jobs, ~/.bashrc, ~/.ssh/authorized_keys, systemd units",
            "Scan /tmp, /var/tmp, /dev/shm for dropped files",
            "Review all outbound connections made during the session window",
            "Check for new sudo rules or SUID/SGID binaries added",
        ],
        "long_term": [
            "Mandate MFA for all SSH access (e.g. TOTP via libpam-google-authenticator)",
            "Deploy endpoint detection and response (EDR) tooling on all servers",
            "Conduct a full forensic review of the compromised host",
            "Rotate all secrets that may have been visible in the session",
        ],
    },
    "Command Execution": {
        "icon": "fa-terminal",
        "color": "danger",
        "description": "Attacker executed shell commands after gaining access.",
        "immediate": [
            "Review the full list of commands run (visible in the session Timeline)",
            "Search for files created in /tmp, /var/tmp, /dev/shm since the session",
            "Check for modifications to /etc/passwd, /etc/cron*, /etc/sudoers",
            "Look for new SUID binaries: find / -perm -4000 -newer /tmp -type f",
        ],
        "short_term": [
            "Block any outbound C2 connections identified from commands",
            "Scan all binaries modified in the last 24 hours for tampering",
            "Review all network connections established during the session",
            "Check for installed backdoors or reverse-shell listeners (netstat -tlnp)",
        ],
        "long_term": [
            "Enable auditd for comprehensive command logging on all hosts",
            "Deploy file integrity monitoring (AIDE or Wazuh FIM)",
            "Implement application allowlisting to restrict executable commands",
            "Adopt least-privilege principle: remove unnecessary shell access",
        ],
    },
    "Malware Download": {
        "icon": "fa-virus",
        "color": "danger",
        "description": "A file was downloaded to the honeypot — potential malware deployment.",
        "immediate": [
            "Isolate the affected host from the network immediately",
            "Copy the downloaded file hash and submit to VirusTotal",
            "Block the download URL at your web proxy and DNS firewall",
            "Check if the file was executed (review commands in session Timeline)",
        ],
        "short_term": [
            "Run a full antivirus/EDR scan on the host",
            "Check all running processes for suspicious activity (ps auxf)",
            "Inspect all outbound connections established after the download",
            "Hunt for lateral movement: scan adjacent hosts for the same malware",
        ],
        "long_term": [
            "Implement egress filtering: block unapproved outbound downloads from servers",
            "Deploy a web proxy with real-time malware scanning (e.g. Squid + ClamAV)",
            "Enable VirusTotal integration in HoneyDash for automated hash lookups",
            "Conduct threat hunting across all hosts for the same malware family/hash",
        ],
    },
    "SSH Connect": {
        "icon": "fa-plug",
        "color": "info",
        "description": "A connection was opened to the SSH service with no login attempt yet.",
        "immediate": [
            "Monitor this IP for follow-up brute-force or login activity",
            "Check if this IP has been seen in previous sessions",
        ],
        "short_term": [
            "Add the IP to a watchlist in your threat intelligence platform",
            "Look up IP reputation using AbuseIPDB, Shodan, or GreyNoise",
        ],
        "long_term": [
            "Implement port knocking to hide SSH from automated scanners",
            "Consider deploying a network-level honeypot (e.g. Artillery) to identify scanners early",
        ],
    },
}

_DEFAULT: dict = {
    "icon": "fa-shield-alt",
    "color": "secondary",
    "description": "Suspicious activity detected — review the session details.",
    "immediate": [
        "Review the full session details and event timeline",
        "Check source IP reputation via AbuseIPDB or VirusTotal",
        "Determine if any sensitive data may have been exposed",
    ],
    "short_term": [
        "Block the source IP if activity is confirmed malicious",
        "Update firewall rules to restrict unnecessary access",
    ],
    "long_term": [
        "Review and tighten security policies and access controls",
        "Ensure comprehensive logging and monitoring are in place",
    ],
}


def _get_steps(attack_type: str | None) -> dict:
    return _LIBRARY.get(attack_type or "", _DEFAULT)


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.get("")
async def get_remediation_by_type(
    attack_type: str = Query(""),
    _user: str = Depends(get_current_user),
):
    """Returns remediation steps for the given attack type."""
    steps = _get_steps(attack_type)
    return {"attack_type": attack_type or "Unknown", **steps}


@router.get("/session/{session_id}")
async def get_remediation_for_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """
    Returns context-aware remediation steps for a specific session.
    Prepends urgency alerts based on what actually happened:
      - Successful login → CRITICAL banner + extra immediate actions
      - Files downloaded → isolation warning
      - ML anomaly flagged → AI insight note
      - Many commands run → command audit emphasis
    """
    result = await db.execute(
        select(Session, IPEnrichment)
        .outerjoin(IPEnrichment, IPEnrichment.ip_address == Session.src_ip)
        .where(Session.session_id == session_id)
    )
    row = result.first()
    if not row:
        return {"attack_type": "Unknown", **_DEFAULT, "context_alerts": []}

    sess, enrich = row
    steps = dict(_get_steps(sess.attack_type))

    # Build context-specific urgency alerts shown at the top of the modal
    context_alerts: list[dict] = []

    if sess.login_success:
        context_alerts.append({
            "level": "critical",
            "icon": "fa-radiation-alt",
            "message": "CRITICAL: Attacker gained successful SSH access. Immediate containment required.",
        })

    if (sess.files_downloaded or 0) > 0:
        context_alerts.append({
            "level": "danger",
            "icon": "fa-virus",
            "message": f"{sess.files_downloaded} file(s) downloaded — potential malware deployment. Isolate host immediately.",
        })

    if sess.is_anomaly:
        score = f" (anomaly score: {sess.anomaly_score:.4f})" if sess.anomaly_score is not None else ""
        context_alerts.append({
            "level": "warning",
            "icon": "fa-robot",
            "message": f"ML model flagged this session as anomalous{score}. Behaviour deviates significantly from normal attack patterns.",
        })

    if (sess.commands_run or 0) > 10:
        context_alerts.append({
            "level": "warning",
            "icon": "fa-terminal",
            "message": f"{sess.commands_run} commands executed — review the full command list in the session timeline.",
        })

    if enrich and enrich.vt_malicious and enrich.vt_malicious >= 3:
        context_alerts.append({
            "level": "danger",
            "icon": "fa-shield-virus",
            "message": f"VirusTotal flagged this IP as malicious: {enrich.vt_malicious}/{enrich.vt_total} engines.",
        })

    return {
        "attack_type": sess.attack_type or "Unknown",
        "session_id":  session_id,
        "src_ip":      sess.src_ip,
        "country":     enrich.country if enrich else None,
        "context_alerts": context_alerts,
        **steps,
    }
