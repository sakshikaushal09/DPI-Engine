#!/usr/bin/env python3
"""
dashboard.py
A small Flask web dashboard for the DPI engine. Lets you:
  - Upload a PCAP file (or use the bundled test_dpi.pcap)
  - Add / remove IP, app, and domain blocking rules from a web form
  - See a live-updating pie chart of the application breakdown
  - See total/forwarded/dropped counts and the list of detected SNIs

This file is completely standalone - it does NOT modify or import from
main_simple.py or dpi_mt.py, it only reuses the shared building blocks in
the dpi/ package (pcap_reader, packet_parser, sni_extractor, rule_manager,
types). Running main_simple.py / dpi_mt.py from the command line still
works exactly as before.

Setup:
    pip install -r requirements-dashboard.txt

Run:
    python3 dashboard.py
    # then open http://127.0.0.1:5000 in your browser
"""

import os
from collections import defaultdict

from flask import Flask, request, jsonify, render_template_string, redirect, url_for

from dpi.pcap_reader import PcapReader
from dpi.packet_parser import PacketParser
from dpi.sni_extractor import SNIExtractor, HTTPHostExtractor
from dpi.rule_manager import RuleManager
from dpi.types import FiveTuple, Flow, AppType, sni_to_app_type

app = Flask(__name__)

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

DEFAULT_PCAP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "test_dpi.pcap"
)

# In-memory state for this simple single-user dashboard.
STATE = {
    "current_pcap": DEFAULT_PCAP if os.path.exists(DEFAULT_PCAP) else None,
    "rules": RuleManager(),
}


def classify_flow(pkt, flow: Flow) -> None:
    """Same classification logic as main_simple.py's classify_flow -
    duplicated here on purpose so this dashboard has no dependency on
    the CLI entry points and can't accidentally break them."""
    if flow.sni:
        return
    if pkt.dst_port == 443 and len(pkt.payload) > 5:
        sni = SNIExtractor.extract(pkt.payload)
        if sni:
            flow.sni = sni
            flow.app_type = sni_to_app_type(sni)
            return
    if pkt.dst_port == 80 and len(pkt.payload) > 0:
        host = HTTPHostExtractor.extract(pkt.payload)
        if host:
            flow.sni = host
            flow.app_type = sni_to_app_type(host)
            return
    if pkt.ip_proto == 17 and pkt.dst_port == 53:
        flow.app_type = AppType.DNS


def analyze_pcap(pcap_path: str, rules: RuleManager) -> dict:
    """Runs the DPI pipeline over a pcap file and returns a JSON-friendly
    stats dict. No output pcap is written - this is read-only analysis
    for the dashboard."""
    reader = PcapReader()
    reader.open(pcap_path)

    flows = {}
    total = total_bytes = tcp_count = udp_count = forwarded = dropped = 0
    app_stats = defaultdict(int)
    detected = {}

    for header, raw in reader:
        total += 1
        total_bytes += header.incl_len

        pkt = PacketParser.parse(raw)
        if pkt is None or (not pkt.has_tcp and not pkt.has_udp):
            forwarded += 1
            continue

        if pkt.has_tcp:
            tcp_count += 1
        else:
            udp_count += 1

        tuple_ = FiveTuple(
            src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
            src_port=pkt.src_port, dst_port=pkt.dst_port,
            protocol=pkt.ip_proto,
        )
        flow = flows.setdefault(tuple_, Flow())
        flow.packet_count += 1
        flow.byte_count += header.incl_len

        classify_flow(pkt, flow)

        if flow.sni and flow.sni not in detected:
            detected[flow.sni] = str(flow.app_type)

        if not flow.blocked and rules.is_blocked(pkt.src_ip_str(), flow.app_type, flow.sni):
            flow.blocked = True

        app_stats[str(flow.app_type)] += 1

        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1

    reader.close()

    return {
        "pcap_file": os.path.basename(pcap_path),
        "total_packets": total,
        "total_bytes": total_bytes,
        "tcp_packets": tcp_count,
        "udp_packets": udp_count,
        "forwarded": forwarded,
        "dropped": dropped,
        "app_stats": dict(app_stats),
        "detected": detected,
        "rules": {
            "blocked_ips": sorted(rules.blocked_ips),
            "blocked_apps": sorted(str(a) for a in rules.blocked_apps),
            "blocked_domains": sorted(rules.blocked_domains),
        },
    }


PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DPI Engine Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #0f1117; color: #e6e6e6; }
  header { background: #161925; padding: 18px 28px; border-bottom: 1px solid #262a3a; }
  header h1 { margin: 0; font-size: 20px; }
  .container { display: flex; gap: 24px; padding: 24px 28px; flex-wrap: wrap; }
  .card { background: #161925; border: 1px solid #262a3a; border-radius: 10px; padding: 20px; }
  .stats-card { flex: 1; min-width: 280px; }
  .chart-card { flex: 1; min-width: 320px; max-width: 420px; }
  .rules-card { flex: 1; min-width: 320px; }
  .stat-row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #21243033; }
  .stat-row span:first-child { color: #9aa0b4; }
  .badge { display: inline-block; background: #2a2f45; padding: 2px 8px; border-radius: 6px; font-size: 12px; margin: 2px; }
  .blocked { background: #4a1f1f; color: #ff8080; }
  form { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
  input[type=text] { flex: 1; min-width: 140px; background: #0f1117; border: 1px solid #333; color: #eee; padding: 8px 10px; border-radius: 6px; }
  select { background: #0f1117; border: 1px solid #333; color: #eee; padding: 8px; border-radius: 6px; }
  button { background: #3d5afe; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; }
  button:hover { background: #536dfe; }
  button.secondary { background: #333; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  td, th { padding: 6px 4px; text-align: left; border-bottom: 1px solid #21243033; font-size: 14px; }
  .domains { max-height: 220px; overflow-y: auto; margin-top: 10px; }
</style>
</head>
<body>
<header><h1>🔍 DPI Engine Dashboard</h1></header>
<div class="container">

  <div class="card stats-card">
    <h3>Traffic Summary — {{ stats.pcap_file or 'no file loaded' }}</h3>
    <div class="stat-row"><span>Total Packets</span><span>{{ stats.total_packets }}</span></div>
    <div class="stat-row"><span>Total Bytes</span><span>{{ stats.total_bytes }}</span></div>
    <div class="stat-row"><span>TCP / UDP</span><span>{{ stats.tcp_packets }} / {{ stats.udp_packets }}</span></div>
    <div class="stat-row"><span>Forwarded</span><span style="color:#7CFC00">{{ stats.forwarded }}</span></div>
    <div class="stat-row"><span>Dropped</span><span style="color:#ff6b6b">{{ stats.dropped }}</span></div>

    <h4>Detected Domains / SNIs</h4>
    <div class="domains">
      <table>
        {% for sni, app in stats.detected.items() %}
        <tr><td>{{ sni }}</td><td>{{ app }}</td></tr>
        {% endfor %}
      </table>
    </div>

    <form method="post" action="/upload" enctype="multipart/form-data">
      <input type="file" name="pcap_file" accept=".pcap" required>
      <button type="submit">Upload & Analyze PCAP</button>
    </form>
  </div>

  <div class="card chart-card">
    <h3>Application Breakdown</h3>
    <canvas id="appChart"></canvas>
  </div>

  <div class="card rules-card">
    <h3>Blocking Rules</h3>
    <div>
      {% for ip in stats.rules.blocked_ips %}<span class="badge blocked">IP: {{ ip }}</span>{% endfor %}
      {% for a in stats.rules.blocked_apps %}<span class="badge blocked">App: {{ a }}</span>{% endfor %}
      {% for d in stats.rules.blocked_domains %}<span class="badge blocked">Domain: {{ d }}</span>{% endfor %}
      {% if not stats.rules.blocked_ips and not stats.rules.blocked_apps and not stats.rules.blocked_domains %}
        <span style="color:#9aa0b4">No rules active</span>
      {% endif %}
    </div>

    <form method="post" action="/rules/add">
      <select name="rule_type">
        <option value="app">App name (e.g. YouTube)</option>
        <option value="ip">Source IP</option>
        <option value="domain">Domain substring</option>
      </select>
      <input type="text" name="value" placeholder="value" required>
      <button type="submit">Block</button>
    </form>
    <form method="post" action="/rules/clear" style="margin-top:8px;">
      <button type="submit" class="secondary">Clear All Rules</button>
    </form>
  </div>

</div>

<script>
const ctx = document.getElementById('appChart');
const labels = {{ stats.app_stats.keys() | list | tojson }};
const values = {{ stats.app_stats.values() | list | tojson }};
new Chart(ctx, {
  type: 'pie',
  data: {
    labels: labels,
    datasets: [{ data: values, backgroundColor: labels.map((_, i) => `hsl(${i * 47 % 360}, 65%, 55%)`) }]
  },
  options: { plugins: { legend: { labels: { color: '#e6e6e6' } } } }
});
</script>
</body>
</html>
"""


@app.route("/")
def index():
    if STATE["current_pcap"] and os.path.exists(STATE["current_pcap"]):
        stats = analyze_pcap(STATE["current_pcap"], STATE["rules"])
    else:
        stats = {
            "pcap_file": None, "total_packets": 0, "total_bytes": 0,
            "tcp_packets": 0, "udp_packets": 0, "forwarded": 0, "dropped": 0,
            "app_stats": {}, "detected": {},
            "rules": {"blocked_ips": [], "blocked_apps": [], "blocked_domains": []},
        }
    return render_template_string(PAGE_TEMPLATE, stats=stats)


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("pcap_file")
    if f and f.filename.endswith(".pcap"):
        save_path = os.path.join(UPLOAD_DIR, f.filename)
        f.save(save_path)
        STATE["current_pcap"] = save_path
    return redirect(url_for("index"))


@app.route("/rules/add", methods=["POST"])
def add_rule():
    rule_type = request.form.get("rule_type")
    value = request.form.get("value", "").strip()
    if value:
        if rule_type == "ip":
            STATE["rules"].block_ip(value)
        elif rule_type == "domain":
            STATE["rules"].block_domain(value)
        elif rule_type == "app":
            try:
                STATE["rules"].block_app(AppType[value.upper()])
            except KeyError:
                pass  # unknown app name - silently ignored for this simple form
    return redirect(url_for("index"))


@app.route("/rules/clear", methods=["POST"])
def clear_rules():
    STATE["rules"] = RuleManager()
    return redirect(url_for("index"))


@app.route("/api/stats")
def api_stats():
    """JSON endpoint - handy for curl / external tools / future frontend."""
    if not STATE["current_pcap"] or not os.path.exists(STATE["current_pcap"]):
        return jsonify({"error": "no pcap loaded"}), 404
    return jsonify(analyze_pcap(STATE["current_pcap"], STATE["rules"]))


if __name__ == "__main__":
    print("DPI Dashboard running at http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
