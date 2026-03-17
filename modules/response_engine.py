import subprocess

response_log = []

def log_response(action, target, success, detail=""):
    entry = {
        "action": action,
        "target": target,
        "success": success,
        "detail": detail
    }
    response_log.append(entry)
    status = "OK" if success else "FAILED"
    print(f"  [{status}] {action} -> {target} | {detail}")
    return entry

def respond(risk):
    username = risk.get("username", "unknown")
    origin = risk.get("origin", "unknown")
    score = risk.get("risk_score", 0)
    confidence = risk.get("confidence", 0)
    responses = []

    if score < 50 and confidence < 0.3:
        return responses

    print()
    print("AUTOMATED RESPONSE TRIGGERED")
    print("----------------------------")
    print(f"User: {username} | Origin: {origin} | Score: {score} | Confidence: {confidence}")

    if score >= 20:
        entry = log_response("LOGGED", username, True, f"Risk score {score} flagged for monitoring")
        responses.append(entry)

    if score >= 50:
        entry = log_response("MONITOR", username, True, f"User {username} placed under enhanced monitoring")
        responses.append(entry)

    if score >= 120 or confidence >= 0.5:
        try:
            result = subprocess.run(
                ["net", "user", username, "/active:no"],
                capture_output=True, text=True, shell=True
            )
            success = result.returncode == 0
            entry = log_response("DISABLE_ACCOUNT", username, success,
                result.stdout.strip() or result.stderr.strip() or "Account disable attempted")
            responses.append(entry)
        except Exception as e:
            entry = log_response("DISABLE_ACCOUNT", username, False, str(e))
            responses.append(entry)

    # ISOLATE_HOST disabled for safety - logs intent only
    if score >= 200 or confidence >= 0.8:
        entry = log_response("ISOLATE_HOST", origin, True, f"[SIMULATION] Host isolation would be triggered for {origin}")
        responses.append(entry)

    risk["responses"] = responses
    return responses

def get_response_log():
    return response_log
