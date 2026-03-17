import time
from modules import eventlog_monitor
from modules import identity_baseline
from modules import host_expansion
from modules import lateral_movement_detector
from modules import attack_path_detector
from modules import risk_engine
from modules import alert_engine
from modules import attack_timeline
from modules import domain_takeover_detector
from modules import ai_analyst
from modules import response_engine
from modules import network_containment
from modules import threat_memory
from modules import incident_reporter

IGNORE_USERS = ["SYSTEM","LOCAL SERVICE","NETWORK SERVICE","-","unknown"]

_send_event_func = None

def register_send_event(func):
    global _send_event_func
    _send_event_func = func

def send_event(data):
    if _send_event_func:
        _send_event_func(data)

def run():
    print("Sentinel starting...")
    send_event({'username':'SOC_TEST','origin':'STEALTH','risk_score':999})
    print("Monitoring Windows Security Logs...")
    while True:
        telemetry = eventlog_monitor.poll_security_events()
        if telemetry and "events" in telemetry:
            for event in telemetry["events"]:
                if event["username"] in IGNORE_USERS:
                    continue
                print("Telemetry received:", event)
                baseline_result = identity_baseline.analyze(event)
                host_result = host_expansion.detect({"events":[event]})
                lateral_result = lateral_movement_detector.detect({"events":[event]})
                path_result = attack_path_detector.detect(event)
                risk = risk_engine.calculate_risk(event, host_result, lateral_result)
                memory_result = threat_memory.analyze_history(risk)
                risk["risk_score"] += baseline_result["risk_score"]
                risk["risk_score"] += path_result["risk_score"]
                risk["risk_score"] += memory_result["risk_score"]
                risk["reasons"].extend(baseline_result["reasons"])
                risk["reasons"].extend(path_result["reasons"])
                risk["reasons"].extend(memory_result["reasons"])
                print("Risk Analysis:", risk)
                alert_engine.generate_alert(risk)
                ai_analyst.generate_threat_summary(risk)
                response_engine.respond(risk)
                network_containment.contain_threat(risk)
                incident_reporter.generate_incident_report(risk)
                print("SENDING DASHBOARD EVENT:", risk)
                send_event(risk)
                attack_timeline.update_timeline({"events":[event]}, risk)
                domain_takeover_detector.detect_domain_takeover(
                    risk["username"],
                    risk["origin"],
                    risk["risk_score"]
                )
        time.sleep(2)

if __name__ == "__main__":
    run()
