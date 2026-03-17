attack_paths = {}

def update_timeline(telemetry, risk):

    for event in telemetry["events"]:

        username = event["username"]
        host = event["origin"]
        time = event["time"]

        if username not in attack_paths:
            attack_paths[username] = []

        attack_paths[username].append(host)

        print("Attack Timeline Update:", username, host, time)

        if risk["risk_score"] >= 80:

            print()
            print("ATTACK PATH DETECTED")
            print("User:", username)
            print("Path:", " -> ".join(attack_paths[username]))
            print("Risk Score:", risk["risk_score"])
            print()
