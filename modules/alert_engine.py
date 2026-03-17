SEVERITY_LEVELS = {
    "CRITICAL": 200,
    "HIGH": 100,
    "MEDIUM": 50,
    "LOW": 20
}

alert_queue = []

def get_severity(score):
    if score >= SEVERITY_LEVELS["CRITICAL"]:
        return "CRITICAL"
    elif score >= SEVERITY_LEVELS["HIGH"]:
        return "HIGH"
    elif score >= SEVERITY_LEVELS["MEDIUM"]:
        return "MEDIUM"
    elif score >= SEVERITY_LEVELS["LOW"]:
        return "LOW"
    return None

def generate_alert(risk):
    score = risk["risk_score"]
    severity = get_severity(score)
    if not severity:
        return None

    alert = {
        "alert": True,
        "severity": severity,
        "username": risk["username"],
        "origin": risk["origin"],
        "risk_score": score,
        "confidence": risk.get("confidence", 0),
        "reasons": risk.get("reasons", [])
    }

    alert_queue.append(alert)

    print()
    print(f"[{severity}] SECURITY ALERT")
    print("-------------------------")
    print("User:      ", alert["username"])
    print("Origin:    ", alert["origin"])
    print("Risk Score:", alert["risk_score"])
    print("Confidence:", alert["confidence"])
    print("Reasons:")
    for r in alert["reasons"]:
        print("  -", r)
    print()

    return alert

def get_alert_queue():
    return alert_queue
