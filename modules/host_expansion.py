import json
import os

BASELINE_FILE = "C:\\AI\\sentinel\\baseline_profiles.json"

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return {}

    with open(BASELINE_FILE,"r") as f:
        return json.load(f)

def save_baseline(data):
    with open(BASELINE_FILE,"w") as f:
        json.dump(data,f,indent=4)

def detect(telemetry):

    baseline = load_baseline()

    events = telemetry["events"]
    event = events[0]

    username = event["username"]
    origin = event["origin"]

    if username not in baseline:
        baseline[username] = []

    risk = 0
    reasons = []

    # New host detection
    if origin not in baseline[username]:

        if len(baseline[username]) > 0:
            risk += 40
            reasons.append("New host access detected")

        baseline[username].append(origin)

    save_baseline(baseline)

    return {
        "username": username,
        "origin": origin,
        "risk_score": risk,
        "reasons": reasons
    }
