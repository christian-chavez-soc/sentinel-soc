import requests
import time
import random
from datetime import datetime

SENTINEL_SERVER = "http://127.0.0.1:5000"

FAKE_AGENTS = [
    {"host": "WORKSTATION-01", "os": "Windows", "ip": "192.168.1.101"},
    {"host": "WORKSTATION-02", "os": "Windows", "ip": "192.168.1.102"},
    {"host": "LINUX-SERVER-01", "os": "Linux",   "ip": "192.168.1.200"},
]

USERNAMES = ["jsmith", "administrator", "bjones", "attacker", "svc_account"]
EVENT_IDS = ["4624", "4624", "4624", "4625", "4625"]

# Mix of clean and suspicious IPs
SOURCE_IPS = [
    "192.168.1.101",
    "192.168.1.102",
    "10.0.0.5",
    "185.220.101.45",
    "198.51.100.1",
    "203.0.113.42",
]

def fake_checkin(agent):
    num_events = random.randint(1, 4)
    events = []
    for _ in range(num_events):
        events.append({
            "username": random.choice(USERNAMES),
            "origin": agent["host"],
            "logon_type": random.choice([2, 3, 10]),
            "event_id": random.choice(EVENT_IDS),
            "source_ip": random.choice(SOURCE_IPS),
            "agent_host": agent["host"],
            "agent_os": agent["os"],
            "time": datetime.now().isoformat()
        })
    payload = {
        "agent_host": agent["host"],
        "agent_os": agent["os"],
        "timestamp": datetime.now().isoformat(),
        "events": events
    }
    try:
        r = requests.post(f"{SENTINEL_SERVER}/agent/checkin", json=payload, timeout=5)
        print(f"Agent {agent['host']} -> {r.status_code} | {len(events)} events sent")
    except Exception as e:
        print(f"Agent {agent['host']} checkin failed: {e}")

if __name__ == "__main__":
    print("Simulating 3 remote agents with threat intel enrichment...")
    for i in range(5):
        print(f"\n--- Round {i+1} ---")
        for agent in FAKE_AGENTS:
            fake_checkin(agent)
            time.sleep(0.5)
        time.sleep(3)
    print("Simulation complete.")
