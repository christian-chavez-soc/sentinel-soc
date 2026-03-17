"""
Sentinel SOC - Option I: Incident Response Playbook Engine
modules/playbook_engine.py

Generates step-by-step IR playbooks based on:
  - MITRE ATT&CK techniques detected
  - Risk severity level
  - Event type (logon, process, network, vulnerability)
  - Affected user/host context
"""

from datetime import datetime

# ─────────────────────────────────────────────────────────────
# Playbook definitions keyed by MITRE technique ID
# Each playbook has: title, severity_threshold, steps[]
# ─────────────────────────────────────────────────────────────
TECHNIQUE_PLAYBOOKS = {
    "T1110": {
        "title": "Brute Force Attack Response",
        "category": "credential_access",
        "steps": [
            {"phase": "Detect",    "action": "Confirm brute force pattern — check for 5+ failed logons (Event 4625) from same source IP within 10 minutes"},
            {"phase": "Contain",   "action": "Block source IP at firewall/WAF immediately"},
            {"phase": "Contain",   "action": "Lock the targeted user account temporarily via Active Directory"},
            {"phase": "Eradicate", "action": "Reset targeted account password and revoke active sessions"},
            {"phase": "Eradicate", "action": "Check if any logon succeeded (Event 4624) after the failed attempts — if yes, treat as compromised"},
            {"phase": "Recover",   "action": "Re-enable account after confirming with user via out-of-band contact (phone/secondary email)"},
            {"phase": "Review",    "action": "Check if same IP attempted other accounts — widen scope if yes"},
            {"phase": "Review",    "action": "Add IP to threat intelligence blocklist"},
            {"phase": "Document",  "action": "Generate incident report with timeline of attempts, accounts targeted, and actions taken"},
        ]
    },
    "T1110.001": {
        "title": "Password Guessing Response",
        "category": "credential_access",
        "steps": [
            {"phase": "Detect",    "action": "Review failed logon events (4625) — confirm sequential password attempts from single source"},
            {"phase": "Contain",   "action": "Enable account lockout policy if not already enforced"},
            {"phase": "Contain",   "action": "Block source IP at perimeter firewall"},
            {"phase": "Eradicate", "action": "Force password reset on targeted accounts"},
            {"phase": "Review",    "action": "Verify MFA is enabled on all targeted accounts"},
            {"phase": "Document",  "action": "Record accounts targeted, attempt count, timestamps, and source IP"},
        ]
    },
    "T1021.001": {
        "title": "RDP Lateral Movement Response",
        "category": "lateral_movement",
        "steps": [
            {"phase": "Detect",    "action": "Confirm RDP logon (Event 4624 Type 10) from unexpected source host"},
            {"phase": "Detect",    "action": "Check if source host is a known admin workstation — if not, escalate immediately"},
            {"phase": "Contain",   "action": "Isolate destination host from network if compromise is suspected"},
            {"phase": "Contain",   "action": "Block RDP port (3389) at internal firewall for non-admin subnets"},
            {"phase": "Eradicate", "action": "Terminate active RDP session if malicious actor is connected"},
            {"phase": "Eradicate", "action": "Reset credentials for all accounts used in the session"},
            {"phase": "Recover",   "action": "Restore host from clean backup if evidence of tampering found"},
            {"phase": "Review",    "action": "Audit all RDP connections in last 30 days from same source"},
            {"phase": "Document",  "action": "Document source/destination hosts, user accounts, session duration"},
        ]
    },
    "T1021.002": {
        "title": "SMB Lateral Movement Response",
        "category": "lateral_movement",
        "steps": [
            {"phase": "Detect",    "action": "Confirm SMB network logon (Event 4624 Type 3) from unexpected source"},
            {"phase": "Detect",    "action": "Check for SMB share enumeration or file access events"},
            {"phase": "Contain",   "action": "Block SMB (445) at internal firewall between workstation subnets"},
            {"phase": "Contain",   "action": "Disable SMBv1 if still enabled — critical vulnerability surface"},
            {"phase": "Eradicate", "action": "Audit shared folder permissions and remove unnecessary access"},
            {"phase": "Eradicate", "action": "Check for EternalBlue (MS17-010) vulnerability on affected hosts"},
            {"phase": "Review",    "action": "Scan all hosts in subnet for SMB exposure"},
            {"phase": "Document",  "action": "Document files accessed, shares enumerated, and accounts used"},
        ]
    },
    "T1190": {
        "title": "Exploit Public-Facing Application Response",
        "category": "initial_access",
        "steps": [
            {"phase": "Detect",    "action": "Identify which application and endpoint was targeted — review web/app server logs"},
            {"phase": "Detect",    "action": "Check for successful exploitation indicators: unexpected process spawning, file writes, outbound connections"},
            {"phase": "Contain",   "action": "Take application offline or enable maintenance mode if compromise confirmed"},
            {"phase": "Contain",   "action": "Block attacker IP at WAF/firewall"},
            {"phase": "Eradicate", "action": "Patch the exploited vulnerability immediately"},
            {"phase": "Eradicate", "action": "Remove any webshells or backdoors placed by attacker"},
            {"phase": "Eradicate", "action": "Rotate all credentials that may have been exposed"},
            {"phase": "Recover",   "action": "Restore application from clean backup if code tampering detected"},
            {"phase": "Review",    "action": "Conduct full vulnerability scan of all public-facing applications"},
            {"phase": "Document",  "action": "Record CVE exploited, payload observed, and remediation steps taken"},
        ]
    },
    "T1505.003": {
        "title": "Web Shell Detection Response",
        "category": "persistence",
        "steps": [
            {"phase": "Detect",    "action": "Locate webshell file — search web root for recently modified PHP/ASPX/JSP files"},
            {"phase": "Detect",    "action": "Review web server access logs for requests to suspicious filenames"},
            {"phase": "Contain",   "action": "Take web server offline immediately if active webshell access detected"},
            {"phase": "Contain",   "action": "Block all external access to web root path containing the webshell"},
            {"phase": "Eradicate", "action": "Delete webshell file and audit all files modified in same timeframe"},
            {"phase": "Eradicate", "action": "Check for additional persistence: scheduled tasks, startup entries, new user accounts"},
            {"phase": "Recover",   "action": "Restore web application from verified clean backup"},
            {"phase": "Review",    "action": "Implement file integrity monitoring on web root"},
            {"phase": "Document",  "action": "Preserve webshell file (quarantined) for forensic analysis"},
        ]
    },
    "T1078": {
        "title": "Valid Account Abuse Response",
        "category": "defense_evasion",
        "steps": [
            {"phase": "Detect",    "action": "Confirm legitimate credentials used from anomalous location, time, or device"},
            {"phase": "Detect",    "action": "Check user travel history and working hours — is this access possible for this user?"},
            {"phase": "Contain",   "action": "Suspend account pending verification with account owner"},
            {"phase": "Contain",   "action": "Revoke all active sessions and tokens for the account"},
            {"phase": "Eradicate", "action": "Force full credential reset including MFA re-enrollment"},
            {"phase": "Eradicate", "action": "Review account activity for past 30 days — identify all actions taken"},
            {"phase": "Recover",   "action": "Restore any data modified or deleted during unauthorized access"},
            {"phase": "Review",    "action": "Determine how credentials were obtained — phishing, breach, insider?"},
            {"phase": "Document",  "action": "Record full timeline of unauthorized access with all actions performed"},
        ]
    },
    "T1040": {
        "title": "Network Sniffing / Cleartext Protocol Response",
        "category": "credential_access",
        "steps": [
            {"phase": "Detect",    "action": "Identify which cleartext protocol is in use (Telnet, FTP, HTTP, SMTP)"},
            {"phase": "Contain",   "action": "Block cleartext protocol at firewall — force encrypted alternatives"},
            {"phase": "Eradicate", "action": "Disable Telnet/FTP services on all hosts — replace with SSH/SFTP"},
            {"phase": "Eradicate", "action": "Rotate all credentials that may have been transmitted in cleartext"},
            {"phase": "Recover",   "action": "Deploy encrypted protocol equivalents across the environment"},
            {"phase": "Review",    "action": "Conduct network scan to identify any remaining cleartext services"},
            {"phase": "Document",  "action": "Record all services migrated to encrypted protocols"},
        ]
    },
    "default": {
        "title": "General Security Incident Response",
        "category": "general",
        "steps": [
            {"phase": "Detect",    "action": "Review all available logs related to the alert — correlate Event IDs, timestamps, and source IPs"},
            {"phase": "Detect",    "action": "Determine scope: single user, single host, or wider environment?"},
            {"phase": "Contain",   "action": "Isolate affected system(s) from network if active compromise suspected"},
            {"phase": "Contain",   "action": "Block source IP addresses at perimeter firewall"},
            {"phase": "Eradicate", "action": "Identify and remove malicious artifacts: files, processes, scheduled tasks, registry keys"},
            {"phase": "Eradicate", "action": "Reset credentials for all affected accounts"},
            {"phase": "Recover",   "action": "Restore affected systems from clean backups after verification"},
            {"phase": "Recover",   "action": "Re-enable services and confirm normal operation"},
            {"phase": "Review",    "action": "Conduct post-incident review — what detection gaps allowed this?"},
            {"phase": "Document",  "action": "Complete incident report: timeline, affected assets, actions taken, lessons learned"},
        ]
    }
}

PHASE_COLORS = {
    "Detect":    "#58a6ff",
    "Contain":   "#f85149",
    "Eradicate": "#d29922",
    "Recover":   "#3fb950",
    "Review":    "#a371f7",
    "Document":  "#8b949e",
}

CATEGORY_LABELS = {
    "credential_access": "Credential Access",
    "lateral_movement":  "Lateral Movement",
    "initial_access":    "Initial Access",
    "persistence":       "Persistence",
    "defense_evasion":   "Defense Evasion",
    "general":           "General",
}


def generate_playbook(event: dict) -> dict:
    """
    Generate an IR playbook for a given Sentinel event.
    Selects the best matching playbook based on MITRE techniques.
    Returns structured playbook dict.
    """
    techniques = event.get("mitre_techniques", [])
    risk_score  = event.get("risk_score", 0)
    username    = event.get("username", "unknown")
    source_ip   = event.get("source_ip", "unknown")
    agent_host  = event.get("agent_host", "unknown")
    timestamp   = event.get("timestamp", datetime.utcnow().isoformat())

    # Find best matching playbook
    matched_technique = None
    playbook_data = None

    for t in techniques:
        tid = t.get("id") if isinstance(t, dict) else str(t)
        if tid in TECHNIQUE_PLAYBOOKS:
            matched_technique = tid
            playbook_data = TECHNIQUE_PLAYBOOKS[tid]
            break

    if not playbook_data:
        playbook_data = TECHNIQUE_PLAYBOOKS["default"]
        matched_technique = "general"

    # Determine priority based on risk score
    if risk_score >= 250:
        priority = "P1 - CRITICAL"
        priority_color = "#f85149"
    elif risk_score >= 150:
        priority = "P2 - HIGH"
        priority_color = "#d29922"
    elif risk_score >= 75:
        priority = "P3 - MEDIUM"
        priority_color = "#e3b341"
    else:
        priority = "P4 - LOW"
        priority_color = "#3fb950"

    return {
        "id":               f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "title":            playbook_data["title"],
        "category":         CATEGORY_LABELS.get(playbook_data["category"], "General"),
        "technique_id":     matched_technique,
        "priority":         priority,
        "priority_color":   priority_color,
        "status":           "OPEN",
        "created_at":       datetime.utcnow().isoformat(),
        "affected_user":    username,
        "affected_host":    agent_host,
        "source_ip":        source_ip,
        "risk_score":       risk_score,
        "original_event":   event,
        "steps":            [
            {
                "id":        i + 1,
                "phase":     s["phase"],
                "action":    s["action"],
                "color":     PHASE_COLORS.get(s["phase"], "#8b949e"),
                "status":    "pending",
                "completed_at": None,
                "notes":     ""
            }
            for i, s in enumerate(playbook_data["steps"])
        ],
        "completion_pct":   0,
        "total_steps":      len(playbook_data["steps"]),
    }


def get_all_playbooks() -> list:
    """Return metadata for all available playbook templates."""
    result = []
    for tid, pb in TECHNIQUE_PLAYBOOKS.items():
        result.append({
            "technique_id": tid,
            "title":        pb["title"],
            "category":     CATEGORY_LABELS.get(pb["category"], "General"),
            "step_count":   len(pb["steps"]),
        })
    return result
