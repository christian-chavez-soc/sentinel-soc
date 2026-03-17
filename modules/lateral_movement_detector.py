"""
Sentinel Lateral Movement Detector

Detects when an identity logs into multiple hosts
within a short observation window.
"""

user_host_history = {}


def detect(telemetry):

    result = {
        "lateral_movement_detected": False,
        "risk_score": 0
    }

    if "events" not in telemetry:
        return result

    for event in telemetry["events"]:

        username = event.get("username")
        host = event.get("origin")

        if username not in user_host_history:
            user_host_history[username] = set()

        user_host_history[username].add(host)

        if len(user_host_history[username]) > 2:
            result["lateral_movement_detected"] = True
            result["risk_score"] = 40

    return result
