import json
import os
from datetime import datetime

MEMORY_FILE = "C:\\AI\\sentinel\\attack_history.json"

def load_memory():
    if not os.path.exists(MEMORY_FILE):
        return {}
    with open(MEMORY_FILE, "r") as f:
        return json.load(f)

def save_memory(data):
    with open(MEMORY_FILE, "w") as f:
        json.dump(data, f, indent=4)

def analyze_history(risk):
    memory = load_memory()
    origin = risk.get("origin", "unknown")
    username = risk.get("username", "unknown")
    score = risk.get("risk_score", 0)
    risk_bonus = 0
    reasons = []

    # Check if this origin has been seen before
    if origin in memory:
        prev = memory[origin]
        prev_risk = prev.get("risk", 0)
        seen_count = prev.get("seen_count", 1)

        # Escalating risk if same origin keeps appearing
        if seen_count >= 5:
            risk_bonus += 50
            reasons.append(f"High frequency origin: seen {seen_count} times")
        elif seen_count >= 3:
            risk_bonus += 30
            reasons.append(f"Recurring origin: seen {seen_count} times")
        else:
            risk_bonus += 15
            reasons.append("Known attacker origin seen before")

        # If risk is escalating from this origin
        if score > prev_risk:
            risk_bonus += 20
            reasons.append(f"Escalating risk from origin (was {prev_risk}, now {score})")

        memory[origin]["seen_count"] = seen_count + 1
        memory[origin]["last_seen"] = str(datetime.now())
        memory[origin]["risk"] = score
        memory[origin]["username"] = username
    else:
        memory[origin] = {
            "username": username,
            "first_seen": str(datetime.now()),
            "last_seen": str(datetime.now()),
            "risk": score,
            "seen_count": 1
        }

    # Track per-user history
    user_key = f"user_{username}"
    if user_key not in memory:
        memory[user_key] = {
            "total_events": 0,
            "total_risk": 0,
            "origins": [],
            "peak_risk": 0
        }

    user_mem = memory[user_key]
    user_mem["total_events"] += 1
    user_mem["total_risk"] += score
    user_mem["peak_risk"] = max(user_mem.get("peak_risk", 0), score)
    if origin not in user_mem["origins"]:
        user_mem["origins"].append(origin)

    # Behavioral clustering - flag users spreading across many hosts
    if len(user_mem["origins"]) >= 4:
        risk_bonus += 40
        reasons.append(f"Lateral spread detected: {len(user_mem['origins'])} unique hosts")
    elif len(user_mem["origins"]) >= 2:
        risk_bonus += 15
        reasons.append(f"Multi-host activity: {len(user_mem['origins'])} hosts")

    # Predict future risk based on trajectory
    avg_risk = user_mem["total_risk"] / max(user_mem["total_events"], 1)
    if avg_risk > 100:
        risk_bonus += 30
        reasons.append(f"High average risk trajectory: {round(avg_risk)}")

    memory[user_key] = user_mem
    save_memory(memory)

    return {
        "risk_score": risk_bonus,
        "reasons": reasons,
        "user_profile": {
            "total_events": user_mem["total_events"],
            "total_risk": user_mem["total_risk"],
            "peak_risk": user_mem["peak_risk"],
            "unique_hosts": len(user_mem["origins"]),
            "avg_risk": round(avg_risk)
        }
    }

def get_user_profiles():
    memory = load_memory()
    profiles = {}
    for key, val in memory.items():
        if key.startswith("user_"):
            username = key.replace("user_", "")
            profiles[username] = val
    return profiles
