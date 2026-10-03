"""
NetMonitor Pro - Flask Dashboard Server
Web interface & REST APIs for Network & Wireless Telemetry.
"""

import os
import logging
from flask import Flask, render_template, jsonify, request

logger = logging.getLogger("netmonitor.dashboard")

def create_dashboard_app(telemetry_store, pcap_engine=None):
    """Create Flask dashboard app."""
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/flows")
    def flows_page():
        return render_template("flows.html")

    @app.route("/wifi-security")
    def wifi_page():
        return render_template("wifi_security.html")

    @app.route("/threats")
    def threats_page():
        return render_template("threats.html")

    @app.route("/settings")
    def settings_page():
        return render_template("settings.html")

    # ---- REST API Endpoints ----

    @app.route("/api/stats")
    def api_stats():
        return jsonify(telemetry_store.get_dashboard_summary())

    @app.route("/api/packets")
    def api_packets():
        count = request.args.get("count", 50, type=int)
        return jsonify({"packets": telemetry_store.get_recent_packets(count)})

    @app.route("/api/flows")
    def api_flows():
        return jsonify({"flows": telemetry_store.flow_tracker.get_flows()})

    @app.route("/api/wifi")
    def api_wifi():
        return jsonify({
            "alerts": telemetry_store.wifi_inspector.get_alerts(),
            "aps": telemetry_store.wifi_inspector.get_ap_security_posture()
        })

    @app.route("/api/threats")
    def api_threats():
        return jsonify({"threats": telemetry_store.threat_detector.get_alerts()})

    @app.route("/api/simulate-deauth", methods=["POST"])
    def api_simulate_deauth():
        bssid = request.form.get("bssid", "00:11:22:33:44:55")
        target = request.form.get("client", "AA:BB:CC:DD:EE:FF")
        telemetry_store.process_wifi_deauth(bssid, target)
        return jsonify({"success": True, "message": f"Simulated 802.11 Deauth burst against BSSID {bssid}"})

    return app
