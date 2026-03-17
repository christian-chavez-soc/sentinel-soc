import sys
sys.path.insert(0, r'C:\AI\sentinel')
from modules import host_expansion
from modules import lateral_movement_detector
from modules import risk_engine
from modules import response_engine
from modules import network_containment
from datetime import datetime, timedelta
import requests

user = "attacker"
hosts = ["WS01", "SERVER01", "DC01"]
base_time = datetime.now()

for i, host in enumerate(hosts):
    event = {
        "username": user,
        "logon_type": 3,
        "origin": host,
        "event_id": "4624",
        "source_ip": "192.168.1.4" + str(i),
        "time": (base_time + timedelta(minutes=i)).isoformat()
    }
    host_result = host_expansion.detect({"events":[event]})
    lateral_result = lateral_movement_detector.detect({"events":[event]})
    risk = risk_engine.calculate_risk(event, host_result, lateral_result)
    responses = response_engine.respond(risk)
    network_containment.contain_threat(risk)
    print("Event:", event)
    print("Risk:", risk)
    print("Responses:", responses)
    print("-----")
    requests.post("http://127.0.0.1:5000/ingest", json=risk)
