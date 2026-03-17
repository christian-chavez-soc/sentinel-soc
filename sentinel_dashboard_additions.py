# ================================================================
# ADD THESE 3 BLOCKS INTO sentinel_dashboard.py
# ================================================================
 
# BLOCK 1 - paste near your other imports at the top
from modules.vuln_scanner import run_scan_async, CVECache
_cve_cache = CVECache()
_scan_results_cache = {}
 
# BLOCK 2 - paste near your other @app.route definitions
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
        socketio.emit(event, d, broadcast=True)
    run_scan_async(target=target, port_range=port_range, emit_fn=emit_fn, cve_cache=_cve_cache)
    return jsonify({"status": "started", "scan_id": scan_id, "target": target, "port_range": port_range})
 
# BLOCK 3 - paste near your other @socketio.on definitions
@socketio.on("vuln_scan_complete")
def handle_vuln_scan_complete(data):
    _scan_results_cache[data.get("scan_id", "unknown")] = data
    if data.get("total_critical", 0) > 0:
        print(f"[SENTINEL CRITICAL] {data['total_critical']} critical CVEs on {data['target']}")
