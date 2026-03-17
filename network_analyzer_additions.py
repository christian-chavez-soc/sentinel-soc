# ================================================================
# ADD THESE BLOCKS INTO sentinel_dashboard.py
# ================================================================

# BLOCK 1 - add near your other imports at the top
from modules.network_analyzer import start_monitor, stop_monitor, get_stats, get_alerts, is_running

# BLOCK 2 - add near your other @app.route definitions
@app.route("/network-analyzer")
def network_analyzer_page():
    return render_template("network_analyzer.html")

@app.route("/api/network/start", methods=["POST"])
def api_network_start():
    if is_running():
        return jsonify({"status": "already_running"})
    def emit_fn(event, data):
        socketio.emit(event, data)
    start_monitor(emit_fn=emit_fn)
    return jsonify({"status": "started"})

@app.route("/api/network/stop", methods=["POST"])
def api_network_stop():
    stop_monitor()
    return jsonify({"status": "stopped"})

@app.route("/api/network/status")
def api_network_status():
    return jsonify({"running": is_running(), "stats": get_stats(), "alerts": get_alerts()})
