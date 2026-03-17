import win32evtlog

last_seen_record = 0

def poll_security_events():
    global last_seen_record
    query = "*[System[(EventID=4624 or EventID=4625)]]"
    handle = win32evtlog.EvtQuery(
        "Security",
        win32evtlog.EvtQueryReverseDirection,
        query
    )
    events = win32evtlog.EvtNext(handle, 20)
    parsed_events = []
    for event in events:
        xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
        if "<EventRecordID>" not in xml:
            continue
        record_id = int(xml.split("<EventRecordID>")[1].split("</EventRecordID>")[0])
        if record_id <= last_seen_record:
            continue
        last_seen_record = record_id
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
            origin = "unknown"
        try:
            logon_type = int(xml.split("<Data Name='LogonType'>")[1].split("</Data>")[0])
        except:
            logon_type = 0
        try:
            ip = xml.split("<Data Name='IpAddress'>")[1].split("</Data>")[0]
        except:
            ip = "unknown"
        parsed_events.append({
            "username": username,
            "origin": origin,
            "logon_type": logon_type,
            "event_id": event_id,
            "source_ip": ip,
            "time": "now"
        })
    return {"events": parsed_events}
