import json
import os
from datetime import datetime

BASELINE_FILE = "C:\\AI\\sentinel\\identity_baselines.json"

def load_baselines():
    if not os.path.exists(BASELINE_FILE):
        return {}
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)

def save_baselines(data):
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=4)

def analyze(event):
    baselines = load_baselines()
    username = event.get("username", "unknown")
    origin = event.get("origin", "unknown")
    logon_type = event.get("logon_type", 0)
    event_id = str(event.get("event_id", "4624"))
    current_hour = datetime.now().hour
    current_day = datetime.now().weekday()

    if username not in baselines:
        baselines[username] = {
            "known_hosts": [],
            "login_hours": [],
            "login_days": [],
            "logon_types": [],
            "failed_logons": 0,
            "successful_logons": 0,
            "first_seen": str(datetime.now()),
            "anomaly_score": 0,
            "event_count": 0
        }

    profile = baselines[username]
    risk = 0
    reasons = []
    anomalies = []

    profile["event_count"] = profile.get("event_count", 0) + 1

    # Track failed vs successful logons
    if event_id == "4625":
        profile["failed_logons"] = profile.get("failed_logons", 0) + 1
        fail_rate = profile["failed_logons"] / max(profile["event_count"], 1)
        if fail_rate > 0.5 and profile["event_count"] > 3:
            risk += 35
            reasons.append(f"High failure rate: {round(fail_rate * 100)}% of logons failed")
            anomalies.append("high_failure_rate")
    else:
        profile["successful_logons"] = profile.get("successful_logons", 0) + 1

    # New host detection
    if origin not in profile["known_hosts"]:
        profile["known_hosts"].append(origin)
        if len(profile["known_hosts"]) > 1:
            risk += 20
            reasons.append(f"New host accessed: {origin} (total: {len(profile['known_hosts'])})")
            anomalies.append("new_host")

    # Off-hours detection with adaptive baseline
    if current_hour not in profile["login_hours"]:
        if len(profile["login_hours"]) >= 3:
            risk += 25
            reasons.append(f"Login outside learned hours (hour {current_hour})")
            anomalies.append("off_hours")
        profile["login_hours"].append(current_hour)

    # Weekend detection
    if current_day not in profile.get("login_days", []):
        profile.setdefault("login_days", []).append(current_day)
        if current_day >= 5 and profile["event_count"] > 5:
            risk += 20
            reasons.append("Weekend login detected")
            anomalies.append("weekend_login")

    # Unusual logon type
    if logon_type not in profile.get("logon_types", []):
        profile.setdefault("logon_types", []).append(logon_type)
        if logon_type in [10, 7] and profile["event_count"] > 3:
            risk += 15
            reasons.append(f"New logon type observed: {logon_type}")
            anomalies.append("new_logon_type")

    # Update anomaly score (rolling)
    profile["anomaly_score"] = profile.get("anomaly_score", 0) * 0.9 + risk * 0.1
    profile["last_seen"] = str(datetime.now())
    baselines[username] = profile
    save_baselines(baselines)

    return {
        "username": username,
        "origin": origin,
        "risk_score": risk,
        "reasons": reasons,
        "anomalies": anomalies,
        "anomaly_score": round(profile["anomaly_score"], 2),
        "profile_maturity": profile["event_count"]
    }

def get_all_baselines():
    return load_baselines()
