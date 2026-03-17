import time
import requests
import socket
import platform
from datetime import datetime

SENTINEL_SERVER = "http://127.0.0.1:5000"
AGENT_HOSTNAME = socket.gethostname()
AGENT_OS = platform.system()
POLL_INTERVAL = 10

def get_local_events():
    try:
        import win32evtlog
        last_record = 0
        query = "*[System[(EventID=4624 or EventID=4625)]]"
        handle = win32evtlog.EvtQuery(
            "Security",
            win32evtlog.EvtQueryReverseDirection,
            query
        )
        raw_events = win32evtlog.EvtNext(handle, 10)
        events = []
        for event in raw_events:
            xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            if "<EventRecordID>" not in xml:
                continue
            try:
                event_id = xml.split("<EventID>")[1].split("</EventID>")[0]
            except:
                event_id = "0"
            try:
                username = xml.split("<Data Name='TargetUserName'>")[1].split("</Data>")[0]
            except:
                username = "unknown"
            try:
                origin = xml.split("<Data Name='WorkstationName'>")[1].split("</Data>")[0]
            except:
                origin = AGENT_HOSTNAME
            try:
                logon_type = int(xml.split("<Data Name='LogonType'>")[1].split("</Data>")[0])
            except:
                logon_type = 0
            try:
                ip = xml.split("<Data Name='IpAddress'>")[1].split("</Data>")[0]
            except:
                ip = "unknown"
            events.append({
                "username": username,
                "origin": origin or AGENT_HOSTNAME,
                "logon_type": logon_type,
                "event_id": event_id,
                "source_ip": ip,
                "agent_host": AGENT_HOSTNAME,
                "agent_os": AGENT_OS,
                "time": datetime.now().isoformat()
            })
        return events
    except Exception as e:
        print(f"Event collection error: {e}")
        return []

def checkin():
    events = get_local_events()
    payload = {
        "agent_host": AGENT_HOSTNAME,
        "agent_os": AGENT_OS,
        "timestamp": datetime.now().isoformat(),
        "events": events
    }
    try:
        r = requests.post(f"{SENTINEL_SERVER}/agent/checkin", json=payload, timeout=5)
        print(f"Checkin: {AGENT_HOSTNAME} -> {r.status_code} | {len(events)} events")
    except Exception as e:
        print(f"Checkin failed: {e}")

if __name__ == "__main__":
    print(f"Sentinel Agent starting on {AGENT_HOSTNAME}")
    while True:
        checkin()
        time.sleep(POLL_INTERVAL)
