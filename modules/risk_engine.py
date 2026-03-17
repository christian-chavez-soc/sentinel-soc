CRITICAL_ASSETS = ["DC01", "DC02", "DB01", "BACKUP01"]
PRIVILEGED_ACCOUNTS = ["administrator", "admin", "root", "sysadmin"]

user_risk_history = {}
failed_logon_tracker = {}

def calculate_risk(event, host_result, lateral_result):
    username = event.get("username", "unknown")
    host = event.get("origin", "unknown")
    logon_type = event.get("logon_type", 0)
    event_id = str(event.get("event_id", "4624"))
    risk_score = 0
    reasons = []

    # Host expansion
    if host_result.get("host_expansion_detected"):
        risk_score += 20
        reasons.append("Host expansion detected")

    # Lateral movement
    if lateral_result.get("lateral_movement_detected"):
        risk_score += 40
        reasons.append("Lateral movement detected")

    # Critical asset access
    if host in CRITICAL_ASSETS:
        risk_score += 80
        reasons.append(f"Access to critical asset: {host}")

    # Privileged account usage
    if username.lower() in PRIVILEGED_ACCOUNTS:
        risk_score += 30
        reasons.append(f"Privileged account used: {username}")

    # Brute force detection (track failed logons 4625)
    if event_id == "4625":
        failed_logon_tracker[username] = failed_logon_tracker.get(username, 0) + 1
        count = failed_logon_tracker[username]
        if count >= 10:
            risk_score += 90
            reasons.append(f"Brute force detected: {count} failed logons")
        elif count >= 5:
            risk_score += 50
            reasons.append(f"Multiple failed logons: {count} attempts")
        elif count >= 3:
            risk_score += 20
            reasons.append(f"Repeated failed logons: {count} attempts")

    # Suspicious logon type (3=network, 10=remote interactive)
    if logon_type in [3, 10]:
        risk_score += 10
        reasons.append(f"Suspicious logon type: {logon_type}")

    # Accumulate user risk history
    if username not in user_risk_history:
        user_risk_history[username] = 0
    user_risk_history[username] += risk_score

    # Threat confidence score 0.0 - 1.0
    confidence = min(user_risk_history[username] / 300, 1.0)

    return {
        "username": username,
        "origin": host,
        "risk_score": user_risk_history[username],
        "confidence": round(confidence, 2),
        "reasons": reasons,
        "event_id": event_id
    }
