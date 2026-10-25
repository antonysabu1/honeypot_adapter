"""Analytics dashboard for the SSH/Telnet honeypot.

Read-only Flask app that reads from the SQLite store and shows:
  - Live session list with attack stage predictions
  - Per-session event timeline
  - Attack-progression graph node status
  - Aggregate statistics

Run from new/:
  python3 dashboard/app.py [--port 8090]

Requires Flask (add to requirements.txt or install manually):
  pip install flask
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from flask import Flask, jsonify, render_template_string, request
except ImportError:
    print("Flask is required: pip install flask")
    sys.exit(1)

from shared.storage import get_storage
from shared.predictor import predict_stage_intent, predict_next_categories
from shared.attack_graph import session_progress, NODES

app = Flask(__name__)

# ---------------------------------------------------------------------------
# HTML template (self-contained; no external dependencies)
# ---------------------------------------------------------------------------
_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Honeypot Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:1rem}
  h1{color:#38bdf8;margin-bottom:1rem}
  h2{color:#94a3b8;font-size:.9rem;text-transform:uppercase;letter-spacing:.1em;margin:1.5rem 0 .5rem}
  .card{background:#1e293b;border-radius:.5rem;padding:1rem;margin-bottom:.75rem}
  .stat-row{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1rem}
  .stat{background:#1e293b;border-radius:.5rem;padding:1rem;flex:1;min-width:120px}
  .stat .val{font-size:2rem;font-weight:700;color:#38bdf8}
  .stat .lbl{font-size:.75rem;color:#64748b}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th{text-align:left;padding:.4rem .6rem;color:#64748b;border-bottom:1px solid #334155}
  td{padding:.4rem .6rem;border-bottom:1px solid #1e293b;vertical-align:top}
  tr:hover td{background:#1e293b}
  .badge{display:inline-block;padding:.1rem .5rem;border-radius:9999px;font-size:.7rem;font-weight:600}
  .b-recon{background:#1d4ed8;color:#bfdbfe}
  .b-discovery{background:#065f46;color:#a7f3d0}
  .b-credential_access{background:#92400e;color:#fde68a}
  .b-persistence{background:#4c1d95;color:#ddd6fe}
  .b-exfiltration{background:#7f1d1d;color:#fecaca}
  .b-other{background:#374151;color:#9ca3af}
  .b-active{background:#166534;color:#bbf7d0}
  .b-closed{background:#374151;color:#9ca3af}
  .node-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:.5rem}
  .node{padding:.5rem;border-radius:.375rem;border:1px solid}
  .node.locked{border-color:#334155;color:#475569}
  .node.unlocked{border-color:#0ea5e9;color:#e2e8f0;background:#0c4a6e22}
  a{color:#38bdf8;text-decoration:none}
  a:hover{text-decoration:underline}
  .tag{font-size:.65rem;color:#64748b}
</style>
</head>
<body>
<h1>🍯 Honeypot Dashboard</h1>

<div class="stat-row">
  <div class="stat"><div class="val">{{ stats.total_sessions }}</div><div class="lbl">Total sessions</div></div>
  <div class="stat"><div class="val">{{ stats.active_sessions }}</div><div class="lbl">Active sessions</div></div>
  <div class="stat"><div class="val">{{ stats.total_events }}</div><div class="lbl">Total events</div></div>
  <div class="stat"><div class="val">{{ stats.total_ips }}</div><div class="lbl">Unique IPs</div></div>
</div>

<h2>Active sessions</h2>
{% if active_sessions %}
<table>
  <tr><th>Session</th><th>IP</th><th>Protocol</th><th>Commands</th><th>Stage</th><th>Intent</th><th>Progress</th><th>Started</th></tr>
  {% for s in active_sessions %}
  <tr>
    <td><a href="/session/{{ s.session_id }}">{{ s.session_id[:8] }}…</a></td>
    <td>{{ s.source_ip }}</td>
    <td>{{ s.protocol }}</td>
    <td>{{ s.request_count }}</td>
    <td><span class="badge b-{{ s.stage or 'other' }}">{{ s.stage or '—' }}</span></td>
    <td><span class="badge b-{{ s.stage or 'other' }}">{{ s.intent or '—' }}</span></td>
    <td>{{ s.nodes_unlocked }}/{{ s.nodes_total }}</td>
    <td><span class="tag">{{ s.started_at[:19] }}</span></td>
  </tr>
  {% endfor %}
</table>
{% else %}
<div class="card" style="color:#64748b">No active sessions.</div>
{% endif %}

<h2>Recent sessions (last 50)</h2>
<table>
  <tr><th>Session</th><th>IP</th><th>Protocol</th><th>Commands</th><th>Stage</th><th>Duration</th><th>Status</th></tr>
  {% for s in recent_sessions %}
  <tr>
    <td><a href="/session/{{ s.session_id }}">{{ s.session_id[:8] }}…</a></td>
    <td>{{ s.source_ip }}</td>
    <td>{{ s.protocol }}</td>
    <td>{{ s.request_count }}</td>
    <td><span class="badge b-{{ s.stage or 'other' }}">{{ s.stage or '—' }}</span></td>
    <td>{{ s.duration }}</td>
    <td><span class="badge b-{{ 'active' if not s.closed_at else 'closed' }}">{{ 'active' if not s.closed_at else 'closed' }}</span></td>
  </tr>
  {% endfor %}
</table>

<h2>Top actions</h2>
<table>
  <tr><th>Action</th><th>Count</th></tr>
  {% for row in top_actions %}
  <tr><td>{{ row.action }}</td><td>{{ row.count }}</td></tr>
  {% endfor %}
</table>
</body></html>
"""

_SESSION_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Session {{ session_id[:8] }}… — Honeypot</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:1rem}
  h1{color:#38bdf8;margin-bottom:.5rem}
  h2{color:#94a3b8;font-size:.9rem;text-transform:uppercase;letter-spacing:.1em;margin:1.5rem 0 .5rem}
  .card{background:#1e293b;border-radius:.5rem;padding:1rem;margin-bottom:.75rem}
  .meta{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;font-size:.85rem;color:#94a3b8}
  table{width:100%;border-collapse:collapse;font-size:.82rem}
  th{text-align:left;padding:.4rem .6rem;color:#64748b;border-bottom:1px solid #334155}
  td{padding:.35rem .6rem;border-bottom:1px solid #1e293b;vertical-align:top}
  .badge{display:inline-block;padding:.1rem .5rem;border-radius:9999px;font-size:.7rem;font-weight:600}
  .b-command_output{background:#1e3a5f;color:#93c5fd}
  .b-command_not_found{background:#3b1f1f;color:#fca5a5}
  .b-fake_auth_success{background:#1c3a2c;color:#86efac}
  .b-session_end{background:#374151;color:#9ca3af}
  .b-recon{background:#1d4ed8;color:#bfdbfe}
  .b-discovery{background:#065f46;color:#a7f3d0}
  .b-credential_access{background:#92400e;color:#fde68a}
  .b-persistence{background:#4c1d95;color:#ddd6fe}
  .b-exfiltration{background:#7f1d1d;color:#fecaca}
  .node-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:.5rem;margin-top:.5rem}
  .node{padding:.5rem;border-radius:.375rem;border:1px solid}
  .node.locked{border-color:#334155;color:#475569}
  .node.unlocked{border-color:#0ea5e9;color:#e2e8f0;background:#0c4a6e22}
  .mitre{font-size:.65rem;color:#64748b}
  a{color:#38bdf8;text-decoration:none}
  .prediction-box{background:#1e293b;border-radius:.5rem;padding:1rem;margin-bottom:.75rem;display:flex;gap:2rem;flex-wrap:wrap}
  .pred-item .label{font-size:.7rem;color:#64748b;text-transform:uppercase}
  .pred-item .val{font-size:1.2rem;font-weight:700;color:#38bdf8}
  .pred-item .conf{font-size:.75rem;color:#94a3b8}
</style>
</head>
<body>
<p><a href="/">← Dashboard</a></p>
<h1>Session <code>{{ session_id }}</code></h1>
<div class="meta">
  <span>IP: <strong>{{ session.source_ip }}</strong></span>
  <span>Protocol: <strong>{{ session.protocol }}</strong></span>
  <span>User: <strong>{{ session.username }}</strong></span>
  <span>Started: <strong>{{ session.started_at[:19] }}</strong></span>
  <span>Commands: <strong>{{ session.request_count }}</strong></span>
</div>

<h2>ML prediction</h2>
<div class="prediction-box">
  <div class="pred-item">
    <div class="label">Attack stage</div>
    <div class="val">{{ prediction.stage or 'unknown' }}</div>
    <div class="conf">confidence {{ '%.0f%%' % (prediction.confidence * 100) }}</div>
  </div>
  <div class="pred-item">
    <div class="label">Intent</div>
    <div class="val">{{ prediction.intent or 'unknown' }}</div>
  </div>
  <div class="pred-item">
    <div class="label">Likely next actions</div>
    <div class="val" style="font-size:.9rem">{{ prediction.next_cats | join(', ') or '—' }}</div>
  </div>
</div>

<h2>Attack progression ({{ progress.nodes_unlocked }}/{{ progress.nodes_total }} nodes)</h2>
<div class="node-grid">
{% for node in progress.nodes %}
  <div class="node {{ 'unlocked' if node.unlocked else 'locked' }}">
    <div>{{ '✓' if node.unlocked else '·' }} {{ node.id }}</div>
    <div style="font-size:.7rem;margin-top:.2rem">{{ node.description }}</div>
    <div class="mitre">{{ node.mitre }}</div>
  </div>
{% endfor %}
</div>

<h2>Events</h2>
<table>
  <tr><th>Time</th><th>Action</th><th>Response</th><th>Status</th></tr>
  {% for ev in events %}
  <tr>
    <td style="white-space:nowrap">{{ ev.timestamp[11:19] }}</td>
    <td>{{ ev.action }}</td>
    <td><span class="badge b-{{ ev.response_type }}">{{ ev.response_type }}</span></td>
    <td>{{ ev.status }}</td>
  </tr>
  {% endfor %}
</table>
</body></html>
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _duration_str(started_at: str | None, closed_at: str | None) -> str:
    if not started_at:
        return "—"
    try:
        s = datetime.fromisoformat(started_at)
        e = datetime.fromisoformat(closed_at) if closed_at else datetime.now(timezone.utc)
        secs = int((e - s).total_seconds())
        if secs < 60:
            return f"{secs}s"
        if secs < 3600:
            return f"{secs // 60}m {secs % 60}s"
        return f"{secs // 3600}h {(secs % 3600) // 60}m"
    except Exception:
        return "—"


@app.route("/")
def index():
    store = get_storage()

    all_sessions = store.fetch_all(
        "SELECT * FROM sessions ORDER BY COALESCE(last_seen, started_at) DESC LIMIT 50"
    )

    # Annotate with ML predictions and graph progress
    active_sessions = []
    for s in all_sessions:
        if s.get("closed_at"):
            continue
        stage, intent, conf = predict_stage_intent(s["session_id"])
        prog = session_progress(s["session_id"])
        s["stage"] = stage
        s["intent"] = intent
        s["nodes_unlocked"] = prog["nodes_unlocked"]
        s["nodes_total"] = prog["nodes_total"]
        active_sessions.append(s)

    recent_sessions = []
    for s in all_sessions:
        stage, _, _ = predict_stage_intent(s["session_id"])
        s["stage"] = stage
        s["duration"] = _duration_str(s.get("started_at"), s.get("closed_at"))
        recent_sessions.append(s)

    total_events = store.count("events")
    distinct_ips = store.fetch_one("SELECT COUNT(DISTINCT source_ip) as n FROM sessions")
    top_actions = store.fetch_all(
        "SELECT action, COUNT(*) as count FROM events GROUP BY action ORDER BY count DESC LIMIT 10"
    )

    stats = {
        "total_sessions": len(all_sessions),
        "active_sessions": len(active_sessions),
        "total_events": total_events,
        "total_ips": (distinct_ips or {}).get("n", 0),
    }

    return render_template_string(
        _INDEX_HTML,
        stats=stats,
        active_sessions=active_sessions,
        recent_sessions=recent_sessions,
        top_actions=top_actions,
    )


@app.route("/session/<session_id>")
def session_detail(session_id: str):
    store = get_storage()
    session = store.fetch_one("SELECT * FROM sessions WHERE session_id=?", (session_id,))
    if not session:
        return "Session not found", 404

    events = store.fetch_all(
        "SELECT timestamp, action, response_type, status FROM events "
        "WHERE session_id=? ORDER BY timestamp ASC",
        (session_id,),
    )
    stage, intent, conf = predict_stage_intent(session_id)
    next_cats = predict_next_categories(session_id, top_k=3)
    progress = session_progress(session_id)

    return render_template_string(
        _SESSION_HTML,
        session_id=session_id,
        session=session,
        events=events,
        prediction={"stage": stage, "intent": intent, "confidence": conf, "next_cats": next_cats},
        progress=progress,
    )


@app.route("/api/sessions")
def api_sessions():
    store = get_storage()
    sessions = store.fetch_all(
        "SELECT session_id, source_ip, protocol, started_at, closed_at, "
        "request_count, username FROM sessions ORDER BY COALESCE(last_seen, started_at) DESC LIMIT 100"
    )
    return jsonify(sessions)


@app.route("/api/session/<session_id>")
def api_session(session_id: str):
    store = get_storage()
    session = store.fetch_one("SELECT * FROM sessions WHERE session_id=?", (session_id,))
    if not session:
        return jsonify({"error": "not found"}), 404
    events = store.fetch_all(
        "SELECT * FROM events WHERE session_id=? ORDER BY timestamp ASC", (session_id,)
    )
    stage, intent, conf = predict_stage_intent(session_id)
    progress = session_progress(session_id)
    return jsonify({
        "session": session,
        "events": events,
        "ml": {"stage": stage, "intent": intent, "confidence": conf},
        "graph": progress,
    })


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    print(f"Dashboard at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
