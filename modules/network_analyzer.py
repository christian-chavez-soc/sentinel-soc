import psutil, socket, threading, logging, time
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

POLL_INTERVAL   = 5
HISTORY_LIMIT   = 500
ALERT_THRESHOLD = 20
PRIVATE_RANGES  = ["127.","192.168.","10.","172.16.","172.17.","172.18.","172.19.","172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31.","0.0.0.0","::"]

PORT_LABELS = {
    20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",123:"NTP",143:"IMAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",587:"SMTP-TLS",993:"IMAPS",995:"POP3S",1433:"MSSQL",
    1723:"PPTP",3306:"MySQL",3389:"RDP",5900:"VNC",6379:"Redis",
    8080:"HTTP-Alt",8443:"HTTPS-Alt",9200:"Elasticsearch",27017:"MongoDB",
}
SUSPICIOUS_PORTS = {23,445,135,139,1433,3389,5900,6379,9200,27017}

_running        = False
_monitor_thread = None
_connection_history = []
_baseline_ports = set()
_baseline_ready = False
_baseline_polls = 0
_ip_counts      = defaultdict(int)
_alerts         = []
_stats = {"total_connections":0,"unique_remote_ips":0,"bytes_sent":0,"bytes_recv":0,"alerts":0,"last_poll":None,"baseline_ready":False}

def _is_private(ip):
    return any(ip.startswith(r) for r in PRIVATE_RANGES)

def _classify_port(port):
    return PORT_LABELS.get(port, f"port-{port}")

def _get_process_name(pid):
    try: return psutil.Process(pid).name()[:30]
    except: return "unknown"

def _get_network_io():
    try:
        io = psutil.net_io_counters()
        return {"bytes_sent": io.bytes_sent, "bytes_recv": io.bytes_recv}
    except: return {"bytes_sent":0,"bytes_recv":0}

def _check_anomalies(conn):
    anomalies = []
    remote_ip   = conn.get("remote_ip","")
    remote_port = conn.get("remote_port",0)
    status      = conn.get("status","")
    if status == "LISTEN" or _is_private(remote_ip): return anomalies
    if remote_port in SUSPICIOUS_PORTS:
        anomalies.append(f"Suspicious outbound port {remote_port} ({_classify_port(remote_port)})")
    if remote_port in (23,21,110,143):
        anomalies.append(f"Cleartext protocol on port {remote_port}")
    if _ip_counts[remote_ip] >= ALERT_THRESHOLD:
        anomalies.append(f"High connection count to {remote_ip} ({_ip_counts[remote_ip]})")
    return anomalies

def _take_snapshot():
    global _baseline_ready, _baseline_polls
    connections = []
    try: net_conns = psutil.net_connections(kind="inet")
    except Exception as e: logger.warning("net_connections error: %s",e); return []
    for conn in net_conns:
        try:
            local_ip    = conn.laddr.ip if conn.laddr else ""
            local_port  = conn.laddr.port if conn.laddr else 0
            remote_ip   = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0
            status      = conn.status or "UNKNOWN"
            pid         = conn.pid or 0
            if local_ip in ("127.0.0.1","::1") and remote_ip in ("127.0.0.1","::1",""): continue
            process = _get_process_name(pid)
            entry = {"timestamp":datetime.utcnow().isoformat(),"local_ip":local_ip,"local_port":local_port,"remote_ip":remote_ip,"remote_port":remote_port,"remote_service":_classify_port(remote_port) if remote_port else "","status":status,"pid":pid,"process":process,"is_private":_is_private(remote_ip) if remote_ip else True,"anomalies":[],"risk_level":"INFO"}
            if remote_ip: _ip_counts[remote_ip] += 1
            if not _baseline_ready:
                if local_port: _baseline_ports.add(local_port)
            else:
                entry["anomalies"] = _check_anomalies(entry)
                if entry["anomalies"]: entry["risk_level"] = "HIGH" if len(entry["anomalies"]) > 1 else "MEDIUM"
            connections.append(entry)
        except: continue
    if not _baseline_ready:
        _baseline_polls += 1
        if _baseline_polls >= 3: _baseline_ready = True
    return connections

def _update_stats(connections):
    global _stats
    io = _get_network_io()
    remote_ips = set(c["remote_ip"] for c in connections if c["remote_ip"])
    _stats.update({"total_connections":len(connections),"unique_remote_ips":len(remote_ips),"bytes_sent":io["bytes_sent"],"bytes_recv":io["bytes_recv"],"alerts":sum(1 for c in connections if c["anomalies"]),"last_poll":datetime.utcnow().isoformat(),"baseline_ready":_baseline_ready})

def _monitor_loop(emit_fn=None):
    global _running, _connection_history, _ip_counts
    logger.info("Network monitor started")
    while _running:
        try:
            _ip_counts.clear()
            snapshot = _take_snapshot()
            _update_stats(snapshot)
            _connection_history.extend(snapshot)
            if len(_connection_history) > HISTORY_LIMIT:
                _connection_history = _connection_history[-HISTORY_LIMIT:]
            if emit_fn:
                try: emit_fn("network_update",{"connections":snapshot,"stats":_stats,"timestamp":datetime.utcnow().isoformat()})
                except Exception as e: logger.warning("emit error: %s",e)
            for conn in snapshot:
                if conn["anomalies"] and emit_fn:
                    alert = {"timestamp":conn["timestamp"],"process":conn["process"],"remote_ip":conn["remote_ip"],"remote_port":conn["remote_port"],"anomalies":conn["anomalies"],"risk_level":conn["risk_level"]}
                    _alerts.append(alert)
                    try: emit_fn("network_alert",alert)
                    except: pass
        except Exception as e: logger.error("Monitor loop error: %s",e)
        time.sleep(POLL_INTERVAL)

def start_monitor(emit_fn=None):
    global _running, _monitor_thread
    if _running: return
    _running = True
    _monitor_thread = threading.Thread(target=_monitor_loop,args=(emit_fn,),daemon=True,name="network-monitor")
    _monitor_thread.start()

def stop_monitor():
    global _running
    _running = False

def get_current_connections():
    return _take_snapshot()

def get_stats():
    return _stats

def get_alerts():
    return _alerts[-50:]

def is_running():
    return _running
