from datetime import datetime

def generate_threat_summary(risk):
    username = risk.get("username", "unknown")
    origin = risk.get("origin", "unknown")
    score = risk.get("risk_score", 0)
    confidence = risk.get("confidence", 0)
    reasons = risk.get("reasons", [])
    agent_host = risk.get("agent_host", "local")

    print()
    print("AI THREAT ANALYSIS")
    print("-----------------------------")
    print(f"Subject:    {username}")
    print(f"Origin:     {origin}")
    print(f"Agent:      {agent_host}")
    print(f"Risk Score: {score}")
    print(f"Confidence: {confidence}")

    patterns = []
    if any("lateral" in r.lower() for r in reasons):
        patterns.append("LATERAL_MOVEMENT")
    if any("brute" in r.lower() or "failed" in r.lower() for r in reasons):
        patterns.append("BRUTE_FORCE")
    if any("critical" in r.lower() for r in reasons):
        patterns.append("CRITICAL_ASSET_ACCESS")
    if any("privilege" in r.lower() for r in reasons):
        patterns.append("PRIVILEGE_ABUSE")
    if any("spread" in r.lower() or "hosts" in r.lower() for r in reasons):
        patterns.append("HOST_SPREADING")
    if any("escalat" in r.lower() for r in reasons):
        patterns.append("RISK_ESCALATION")
    if any("hours" in r.lower() or "weekend" in r.lower() for r in reasons):
        patterns.append("OFF_HOURS_ACTIVITY")

    print()
    print("Behavioral Patterns Detected:", ", ".join(patterns) if patterns else "None")
    print()

    if score >= 200 or confidence >= 0.8:
        print("VERDICT: CRITICAL THREAT")
        print(f"User '{username}' exhibits behavior consistent with an active attack.")
        if "LATERAL_MOVEMENT" in patterns:
            print("Lateral movement detected - attacker is spreading across the network.")
        if "BRUTE_FORCE" in patterns:
            print("Brute force pattern detected - credential stuffing likely in progress.")
        if "CRITICAL_ASSET_ACCESS" in patterns:
            print("Critical infrastructure targeted - possible domain compromise underway.")
        print("RECOMMENDATION: Immediately isolate affected hosts and reset credentials.")

    elif score >= 100 or confidence >= 0.5:
        print("VERDICT: HIGH RISK")
        print(f"User '{username}' shows significant anomalous behavior.")
        if "PRIVILEGE_ABUSE" in patterns:
            print("Privileged account misuse detected.")
        if "HOST_SPREADING" in patterns:
            print("User is accessing an unusual number of hosts.")
        print("RECOMMENDATION: Investigate account activity and review access logs.")

    elif score >= 50 or confidence >= 0.3:
        print("VERDICT: MEDIUM RISK")
        print(f"User '{username}' shows some unusual patterns worth monitoring.")
        if "OFF_HOURS_ACTIVITY" in patterns:
            print("Activity outside normal hours detected.")
        print("RECOMMENDATION: Flag for review and monitor closely.")

    else:
        print("VERDICT: LOW RISK")
        print(f"User '{username}' activity appears mostly normal.")
        print("RECOMMENDATION: Continue passive monitoring.")

    if reasons:
        print()
        print("Evidence:")
        for r in reasons:
            print(f"  - {r}")

    print()
    return {
        "username": username,
        "score": score,
        "confidence": confidence,
        "patterns": patterns,
        "timestamp": str(datetime.now())
    }
