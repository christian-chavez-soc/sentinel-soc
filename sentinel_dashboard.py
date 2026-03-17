from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO
import threading
import sentinel_core

app = Flask(__name__, template_folder="templates")
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

from modules.vuln_scanner import run_scan_async, CVECache
_cve_cache = CVECache()
_scan_results_cache = {}
_playbook_store = []

event_history = []
agent_registry = {}
threat_intel_log = []

def send_event(data):
    print("DASHBOARD EVENT:", data)
    event_history.append(data)
    socketio.emit("new_event", data)
    try:
        from modules.ueba_engine import analyze_event, get_stats as ueba_stats
        anomalies = analyze_event(data)
        for anomaly in anomalies:
            socketio.emit("ueba_anomaly", anomaly)
        if anomalies:
            socketio.emit("ueba_stats", ueba_stats())
    except Exception:
        pass

sentinel_core.register_send_event(send_event)

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/static/<path:filename>")
def static_files(filename):
    from flask import send_from_directory
    import os
    return send_from_directory(os.path.join(app.root_path, "static"), filename)

@app.route("/map")
def attack_map():
    from modules.geo_tracker import get_attack_locations
    import folium
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    locations = get_attack_locations()
    for loc in locations:
        color = "red" if loc["risk_score"] >= 200 else "orange" if loc["risk_score"] >= 100 else "yellow"
        folium.CircleMarker(
            location=[loc["latitude"], loc["longitude"]],
            radius=8, color=color, fill=True,
            fill_color=color, fill_opacity=0.8,
            popup=folium.Popup(
                f"<b>{loc['username']}</b><br>IP: {loc['ip']}<br>"
                f"Location: {loc['city']}, {loc['country']}<br>"
                f"Risk: {loc['risk_score']}<br>Agent: {loc['agent']}",
                max_width=200
            )
        ).add_to(m)
    if not locations:
        folium.Marker(
            location=[39.8283, -98.5795],
            popup="No geo data yet",
            icon=folium.Icon(color="green", icon="info-sign")
        ).add_to(m)
    return m._repr_html_()

@app.route("/generate-report", methods=["POST"])
def generate_report():
    from modules.report_generator import generate_report as gen_report
    from modules.response_engine import get_response_log
    from modules.geo_tracker import get_attack_locations
    try:
        filename = gen_report(event_history, agent_registry, get_response_log(), get_attack_locations())
        return send_file(filename, as_attachment=True, download_name="sentinel_report.pdf")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/geo")
def get_geo():
    from modules.geo_tracker import get_attack_locations, get_country_stats
    return jsonify({"locations": get_attack_locations(), "country_stats": get_country_stats()})

@app.route("/events")
def get_events():
    return jsonify(event_history)

@app.route("/agents")
def get_agents():
    return jsonify(list(agent_registry.values()))

@app.route("/threat-intel")
def get_threat_intel():
    return jsonify(threat_intel_log[-50:])

@app.route("/intelligence")
def get_intelligence():
    from modules.threat_memory import get_user_profiles
    from modules.identity_baseline import get_all_baselines
    profiles = get_user_profiles()
    baselines = get_all_baselines()
    intelligence = []
    for username, profile in profiles.items():
        baseline = baselines.get(username, {})
        intelligence.append({
            "username": username,
            "total_events": profile.get("total_events", 0),
            "total_risk": profile.get("total_risk", 0),
            "peak_risk": profile.get("peak_risk", 0),
            "avg_risk": profile.get("avg_risk", 0),
            "unique_hosts": len(profile.get("origins", [])),
            "known_hosts": baseline.get("known_hosts", []),
            "failed_logons": baseline.get("failed_logons", 0),
            "anomaly_score": round(baseline.get("anomaly_score", 0), 2),
            "profile_maturity": baseline.get("event_count", 0)
        })
    intelligence.sort(key=lambda x: x["total_risk"], reverse=True)
    return jsonify(intelligence)

@app.route("/responses")
def get_responses():
    from modules.response_engine import get_response_log
    from modules.network_containment import get_containment_log
    return jsonify({"responses": get_response_log(), "containment": get_containment_log()})

@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.get_json()
    send_event(data)
    return jsonify({"status": "ok"})

@app.route("/agent/checkin", methods=["POST"])
def agent_checkin():
    from modules import risk_engine, response_engine, network_containment
    from modules import host_expansion, lateral_movement_detector
    from modules import identity_baseline, threat_memory, attack_path_detector
    from modules import threat_intel, email_alerter, geo_tracker
    data = request.get_json()
    agent_host = data.get("agent_host", "unknown")
    agent_os = data.get("agent_os", "unknown")
    events = data.get("events", [])
    agent_registry[agent_host] = {
        "host": agent_host, "os": agent_os,
        "last_seen": data.get("timestamp"),
        "event_count": agent_registry.get(agent_host, {}).get("event_count", 0) + len(events)
    }
    socketio.emit("agent_update", list(agent_registry.values()))
    IGNORE_USERS = ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-", "unknown"]
    for event in events:
        if event.get("username") in IGNORE_USERS:
            continue
        enrichment = threat_intel.enrich_event(event)
        if enrichment["indicators"]:
            intel_entry = {"username": event.get("username"), "ip": event.get("source_ip"), "agent": agent_host, "indicators": enrichment["indicators"], "threat_score": enrichment["threat_score"]}
            threat_intel_log.append(intel_entry)
            socketio.emit("intel_hit", intel_entry)
        baseline_result = identity_baseline.analyze(event)
        host_result = host_expansion.detect({"events": [event]})
        lateral_result = lateral_movement_detector.detect({"events": [event]})
        path_result = attack_path_detector.detect(event)
        risk = risk_engine.calculate_risk(event, host_result, lateral_result)
        memory_result = threat_memory.analyze_history(risk)
        risk["risk_score"] += baseline_result["risk_score"] + path_result["risk_score"] + memory_result["risk_score"] + enrichment["threat_score"]
        risk["reasons"].extend(baseline_result["reasons"] + path_result["reasons"] + memory_result["reasons"] + enrichment["indicators"])
        risk["agent_host"] = agent_host
        risk["agent_os"] = agent_os
        risk["source_ip"] = event.get("source_ip", "unknown")
        risk["confidence"] = min(risk["risk_score"] / 300, 1.0)
        risk["threat_intel"] = enrichment
        risk["mitre_techniques"] = path_result.get("mitre_techniques", [])
        if risk["mitre_techniques"]:
            print(f"MITRE TECHNIQUES: {[t['id'] for t in risk['mitre_techniques']]}")
        geo = geo_tracker.track_attack(risk)
        if geo:
            risk["geo"] = geo
            socketio.emit("geo_update", geo)
        email_alerter.send_alert_email(risk)
        response_engine.respond(risk)
        network_containment.contain_threat(risk)
        send_event(risk)
        socketio.emit("intel_update", {})
    return jsonify({"status": "ok", "events_processed": len(events)})

@app.route("/vuln-scanner")
def vuln_scanner_page():
    return render_template("vuln_scanner.html")

@app.route("/api/vuln/scan", methods=["POST"])
def api_vuln_scan():
    import re, time
    data = request.get_json(force=True) or {}
    target = data.get("target", "").strip()
    port_range = data.get("port_range", "common")
    if not target:
        return jsonify({"error": "target is required"}), 400
    if not re.match(r"^[\w\.\-]+$", target):
        return jsonify({"error": "invalid target format"}), 400
    scan_id = f"{target}-{int(time.time())}"
    def emit_fn(event, d):
        d["scan_id"] = scan_id
        if event == "vuln_scan_complete":
            _scan_results_cache[scan_id] = d
        socketio.emit(event, d)
    run_scan_async(target=target, port_range=port_range, emit_fn=emit_fn, cve_cache=_cve_cache)
    return jsonify({"status": "started", "scan_id": scan_id, "target": target, "port_range": port_range})

@app.route("/api/vuln/report/<scan_id>")
def api_vuln_report(scan_id):
    from modules.report_generator import generate_report as gen_report
    result = _scan_results_cache.get(scan_id)
    if not result:
        return "Scan not found - run a scan first then download immediately", 404
    try:
        events = []
        for f in result.get("findings", []):
            for cve in f.get("cves", []):
                events.append({"type": "vulnerability", "username": f.get("service"), "source_ip": result.get("target"), "risk_score": f.get("risk_score", 0) * 30, "reasons": [cve.get("cve_id", ""), cve.get("description", "")[:100]]})
        filename = gen_report(events, {}, [], [])
        return send_file(filename, as_attachment=True, download_name="sentinel_vuln_report.pdf")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/network-analyzer")
def network_analyzer_page():
    return render_template("network_analyzer.html")

@app.route("/api/network/start", methods=["POST"])
def api_network_start():
    from modules.network_analyzer import start_monitor, is_running
    if is_running():
        return jsonify({"status": "already_running"})
    def emit_fn(event, data):
        socketio.emit(event, data)
    start_monitor(emit_fn=emit_fn)
    return jsonify({"status": "started"})

@app.route("/api/network/stop", methods=["POST"])
def api_network_stop():
    from modules.network_analyzer import stop_monitor
    stop_monitor()
    return jsonify({"status": "stopped"})

@app.route("/api/network/status")
def api_network_status():
    from modules.network_analyzer import get_stats, get_alerts, is_running
    return jsonify({"running": is_running(), "stats": get_stats(), "alerts": get_alerts()})

@app.route("/siem")
def siem_viewer():
    return render_template("siem_viewer.html")

@app.route("/playbooks")
def playbooks_page():
    return render_template("playbooks.html")

@app.route("/api/playbooks/templates")
def api_playbook_templates():
    from modules.playbook_engine import get_all_playbooks
    return jsonify(get_all_playbooks())

@app.route("/api/playbooks/generate", methods=["POST"])
def api_playbook_generate():
    from modules.playbook_engine import generate_playbook
    event = request.get_json(force=True) or {}
    pb = generate_playbook(event)
    _playbook_store.append(pb)
    return jsonify(pb)

@app.route("/api/playbooks/list")
def api_playbook_list():
    return jsonify(_playbook_store)

@app.route("/api/playbooks/update", methods=["POST"])
def api_playbook_update():
    data = request.get_json(force=True) or {}
    pid = data.get("id")
    for pb in _playbook_store:
        if pb["id"] == pid:
            pb["steps"] = data.get("steps", pb["steps"])
            pb["completion_pct"] = data.get("completion_pct", pb["completion_pct"])
            break
    return jsonify({"status": "ok"})

@app.route("/ueba")
def ueba_page():
    return render_template("ueba.html")

@app.route("/api/ueba/anomalies")
def api_ueba_anomalies():
    from modules.ueba_engine import get_anomalies
    return jsonify(get_anomalies())

@app.route("/api/ueba/profiles")
def api_ueba_profiles():
    from modules.ueba_engine import get_user_profiles
    return jsonify(get_user_profiles())

@app.route("/api/ueba/stats")
def api_ueba_stats():
    from modules.ueba_engine import get_stats
    return jsonify(get_stats())

@app.route("/hunting")
def hunting_page():
    return render_template("hunting.html")

@socketio.on("vuln_scan_complete")
def handle_vuln_scan_complete(data):
    _scan_results_cache[data.get("scan_id", "unknown")] = data
    if data.get("total_critical", 0) > 0:
        print(f"[SENTINEL CRITICAL] {data['total_critical']} critical CVEs on {data['target']}")

@socketio.on("connect")
def dashboard_connected():
    print("Dashboard connected - sending", len(event_history), "stored events")
    for event in event_history:
        socketio.emit("new_event", event)
    socketio.emit("agent_update", list(agent_registry.values()))

if __name__ == "__main__":
    print("Starting Sentinel + SOC Dashboard")
    threading.Thread(target=sentinel_core.run, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=5000)
