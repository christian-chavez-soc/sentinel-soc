import json
import os
import time

PATH_FILE = "C:\\AI\\sentinel\\attack_paths.json"

CRITICAL_ASSETS = ["DC01", "DC02", "DB01", "BACKUP01"]
TIME_WINDOW = 600  # 10 minutes

# MITRE ATT&CK technique definitions
MITRE_TECHNIQUES = {
    "T1110": {
        "name": "Brute Force",
        "description": "Adversary attempting to gain access via repeated login attempts",
        "severity": "HIGH"
    },
    "T1078": {
        "name": "Valid Accounts",
        "description": "Adversary using legitimate credentials to maintain access",
        "severity": "HIGH"
    },
    "T1550": {
        "name": "Pass the Hash",
        "description": "Adversary using stolen password hashes to authenticate",
        "severity": "CRITICAL"
    },
    "T1021": {
        "name": "Remote Services",
        "description": "Adversary using remote services for lateral movement",
        "severity": "HIGH"
    },
    "T1484": {
        "name": "Domain Policy Modification",
        "description": "Adversary modifying domain policy for privilege escalation",
        "severity": "CRITICAL"
    },
    "T1003": {
        "name": "Credential Dumping",
        "description": "Adversary attempting to dump credentials from the system",
        "severity": "CRITICAL"
    },
    "T1558": {
        "name": "Kerberoasting",
        "description": "Adversary stealing Kerberos tickets to crack offline",
        "severity": "CRITICAL"
    },
    "T1098": {
        "name": "Account Manipulation",
        "description": "Adversary manipulating accounts to maintain persistence",
        "severity": "HIGH"
    },
    "T1136": {
        "name": "Create Account",
        "description": "Adversary creating accounts to maintain persistence",
        "severity": "HIGH"
    },
    "T1087": {
        "name": "Account Discovery",
        "description": "Adversary enumerating accounts for reconnaissance",
        "severity": "MEDIUM"
    },
    "T1018": {
        "name": "Remote System Discovery",
        "description": "Adversary enumerating remote systems on the network",
        "severity": "MEDIUM"
    },
    "T1574": {
        "name": "Hijack Execution Flow",
        "description": "Adversary hijacking execution to run malicious code",
        "severity": "CRITICAL"
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "description": "Adversary exploiting vulnerabilities to escalate privileges",
        "severity": "CRITICAL"
    },
    "T1569": {
        "name": "System Services Abuse",
        "description": "Adversary abusing system services for execution",
        "severity": "HIGH"
    },
    "T1566": {
        "name": "Phishing",
        "description": "Adversary using phishing for initial access",
        "severity": "HIGH"
    }
}

def load_paths():
    if not os.path.exists(PATH_FILE):
        return {}
    try:
        with open(PATH_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_paths(data):
    with open(PATH_FILE, "w") as f:
        json.dump(data, f, indent=4)

def identify_mitre_techniques(event, history, risk_score):
    techniques = []
    username = event.get("username", "unknown")
    host = event.get("origin", "unknown")
    logon_type = event.get("logon_type", 0)
    event_id = str(event.get("event_id", "4624"))
    failed_count = sum(1 for h in history if h.get("failed", False))
    unique_hosts = len(set(h["host"] for h in history))

    # T1110 - Brute Force (multiple failed logons)
    if event_id == "4625" and failed_count >= 3:
        techniques.append({
            "id": "T1110",
            "name": MITRE_TECHNIQUES["T1110"]["name"],
            "description": MITRE_TECHNIQUES["T1110"]["description"],
            "severity": MITRE_TECHNIQUES["T1110"]["severity"],
            "confidence": min(failed_count / 10, 1.0),
            "evidence": f"{failed_count} failed logon attempts detected"
        })

    # T1550 - Pass the Hash (network logon type 3 with no password)
    if logon_type == 3 and event_id == "4624" and unique_hosts >= 2:
        techniques.append({
            "id": "T1550",
            "name": MITRE_TECHNIQUES["T1550"]["name"],
            "description": MITRE_TECHNIQUES["T1550"]["description"],
            "severity": MITRE_TECHNIQUES["T1550"]["severity"],
            "confidence": 0.7,
            "evidence": f"Network logon type 3 across {unique_hosts} hosts"
        })

    # T1021 - Remote Services (remote interactive logon)
    if logon_type in [10, 3] and unique_hosts >= 2:
        techniques.append({
            "id": "T1021",
            "name": MITRE_TECHNIQUES["T1021"]["name"],
            "description": MITRE_TECHNIQUES["T1021"]["description"],
            "severity": MITRE_TECHNIQUES["T1021"]["severity"],
            "confidence": 0.8,
            "evidence": f"Remote logon type {logon_type} detected across {unique_hosts} hosts"
        })

    # T1078 - Valid Accounts (privileged account used across multiple hosts)
    privileged = ["administrator", "admin", "root", "sysadmin"]
    if username.lower() in privileged and unique_hosts >= 2:
        techniques.append({
            "id": "T1078",
            "name": MITRE_TECHNIQUES["T1078"]["name"],
            "description": MITRE_TECHNIQUES["T1078"]["description"],
            "severity": MITRE_TECHNIQUES["T1078"]["severity"],
            "confidence": 0.85,
            "evidence": f"Privileged account '{username}' active on {unique_hosts} hosts"
        })

    # T1558 - Kerberoasting (service account with network logon hitting multiple hosts)
    if any(p in username.lower() for p in ["svc_", "service_", "_svc"]) and logon_type == 3:
        techniques.append({
            "id": "T1558",
            "name": MITRE_TECHNIQUES["T1558"]["name"],
            "description": MITRE_TECHNIQUES["T1558"]["description"],
            "severity": MITRE_TECHNIQUES["T1558"]["severity"],
            "confidence": 0.65,
            "evidence": f"Service account '{username}' making network logons"
        })

    # T1018 - Remote System Discovery (hitting many unique hosts quickly)
    if unique_hosts >= 4:
        techniques.append({
            "id": "T1018",
            "name": MITRE_TECHNIQUES["T1018"]["name"],
            "description": MITRE_TECHNIQUES["T1018"]["description"],
            "severity": MITRE_TECHNIQUES["T1018"]["severity"],
            "confidence": min(unique_hosts / 8, 1.0),
            "evidence": f"Activity detected across {unique_hosts} unique hosts"
        })

    # T1068 - Privilege Escalation (normal user hitting critical assets)
    if host in CRITICAL_ASSETS and username.lower() not in privileged:
        techniques.append({
            "id": "T1068",
            "name": MITRE_TECHNIQUES["T1068"]["name"],
            "description": MITRE_TECHNIQUES["T1068"]["description"],
            "severity": MITRE_TECHNIQUES["T1068"]["severity"],
            "confidence": 0.75,
            "evidence": f"Non-privileged user '{username}' accessing critical asset '{host}'"
        })

    # T1484 - Domain Policy Modification (hitting DC with network logon)
    if host in ["DC01", "DC02"] and logon_type == 3:
        techniques.append({
            "id": "T1484",
            "name": MITRE_TECHNIQUES["T1484"]["name"],
            "description": MITRE_TECHNIQUES["T1484"]["description"],
            "severity": MITRE_TECHNIQUES["T1484"]["severity"],
            "confidence": 0.6,
            "evidence": f"Network logon to domain controller '{host}'"
        })

    # T1098 - Account Manipulation (rapid host spread by same user)
    if unique_hosts >= 3 and risk_score >= 100:
        techniques.append({
            "id": "T1098",
            "name": MITRE_TECHNIQUES["T1098"]["name"],
            "description": MITRE_TECHNIQUES["T1098"]["description"],
            "severity": MITRE_TECHNIQUES["T1098"]["severity"],
            "confidence": 0.7,
            "evidence": f"High risk user '{username}' active across {unique_hosts} hosts"
        })

    return techniques

def detect(event):
    username = event.get("username", "unknown")
    host = event.get("origin", "unknown")
    event_id = str(event.get("event_id", "4624"))
    current_time = int(time.time())
    paths = load_paths()

    if username not in paths:
        paths[username] = []

    history = paths[username]
    history = [h for h in history if current_time - h.get("time", 0) <= TIME_WINDOW]

    risk = 0
    reasons = []

    # Track this event
    if not any(h["host"] == host for h in history):
        history.append({
            "host": host,
            "time": current_time,
            "failed": event_id == "4625"
        })
        if len(history) >= 3:
            risk += 40
            reasons.append("Rapid multi-host movement detected")

    if host in CRITICAL_ASSETS:
        risk += 80
        reasons.append(f"Access to critical infrastructure: {host}")

    # MITRE ATT&CK detection
    techniques = identify_mitre_techniques(event, history, risk)
    for technique in techniques:
        technique_risk = {"CRITICAL": 60, "HIGH": 40, "MEDIUM": 20, "LOW": 10}.get(technique["severity"], 10)
        risk += technique_risk
        reasons.append(f"MITRE {technique['id']} - {technique['name']}: {technique['evidence']}")

    paths[username] = history
    save_paths(paths)

    return {
        "username": username,
        "origin": host,
        "risk_score": risk,
        "reasons": reasons,
        "path": [h["host"] for h in history],
        "mitre_techniques": techniques
    }

def get_mitre_summary():
    paths = load_paths()
    all_techniques = {}
    for username, history in paths.items():
        if username.startswith("user_"):
            continue
    return all_techniques
