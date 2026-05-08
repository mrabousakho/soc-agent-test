# ============================================================
# PHASE 5 — LESSON 13: SOC Agent Dashboard
# Mentor: Claude | Student: Sakho Aboubacar
# Goal: Generate a live HTML dashboard from run history
#       and alert logs. Visual campaign tracker over time.
#       This is what you demo to a hiring manager.
# ============================================================

import os
import json
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR       = Path(__file__).parent.absolute()
RUN_LOG_FILE   = BASE_DIR / "scheduled_run_log.json"
ALERT_LOG_FILE = BASE_DIR / "alert_log_scheduled.json"
LIVE_LOG_FILE  = BASE_DIR / "alert_log_live.json"
DASHBOARD_FILE = BASE_DIR / "soc_dashboard.html"


# ============================================================
# DATA LOADERS
# ============================================================

def load_run_log() -> list:
    if not RUN_LOG_FILE.exists():
        return []
    with open(RUN_LOG_FILE) as f:
        return json.load(f)


def load_live_alerts() -> list:
    alerts = []
    for path in [LIVE_LOG_FILE,
                 BASE_DIR / "alert_log.json",
                 BASE_DIR / "alert_log_live.json"]:
        if path.exists():
            try:
                with open(path) as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        alerts.extend(data)
            except Exception:
                pass
    # Deduplicate by alert_id
    seen = set()
    unique = []
    for a in alerts:
        aid = a.get("alert_id", "")
        if aid and aid not in seen:
            seen.add(aid)
            unique.append(a)
    return unique


# ============================================================
# DASHBOARD GENERATOR
# Produces a self-contained HTML file with:
# - Live stats cards
# - Severity distribution chart
# - Run history timeline
# - Alert feed with MITRE tags
# - Cost tracker
# ============================================================

def generate_dashboard():
    now        = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    run_log    = load_run_log()
    all_alerts = load_live_alerts()

    # ── Compute stats ─────────────────────────────────────────
    total_runs      = len(run_log)
    total_alerts    = sum(r.get("new_alerts", 0) for r in run_log)
    total_critical  = sum(r.get("critical", 0)   for r in run_log)
    total_high      = sum(r.get("high", 0)        for r in run_log)
    total_cost      = sum(r.get("cost", 0)        for r in run_log)
    clean_runs      = sum(1 for r in run_log if r.get("status") == "clean")

    # Severity counts from alert log
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in all_alerts:
        s = a.get("severity", "Low")
        if s in sev_counts:
            sev_counts[s] += 1

    # Last 10 runs for timeline
    recent_runs = run_log[-10:] if run_log else []

    # Recent alerts sorted by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_alerts = sorted(
        all_alerts,
        key=lambda x: (sev_order.get(x.get("severity", "Low"), 3),
                       x.get("timestamp", ""))
    )[:20]

    # Build run timeline bars
    def run_bar(run):
        status = run.get("status", "normal")
        cost   = run.get("cost", 0)
        alerts = run.get("new_alerts", 0)
        crit   = run.get("critical", 0)
        ts     = run.get("timestamp", "")[:16].replace("T", " ")
        color  = ("#da3633" if crit > 0
                  else "#e3b341" if alerts > 0
                  else "#3fb950")
        label  = (f"🔴 {crit} Critical" if crit > 0
                  else f"🟠 {alerts} alerts" if alerts > 0
                  else "✅ Clean")
        return (f'<div class="run-bar" style="border-left:3px solid {color}">'
                f'<span class="run-ts">{ts}</span>'
                f'<span class="run-label" style="color:{color}">{label}</span>'
                f'<span class="run-cost">${cost:.4f}</span>'
                f'</div>')

    run_bars_html = "\n".join(run_bar(r) for r in reversed(recent_runs))
    if not run_bars_html:
        run_bars_html = '<div class="empty">No runs recorded yet.</div>'

    # Build alert rows
    def alert_row(a):
        sev     = a.get("severity", "Low")
        mid     = a.get("mitre_id", "")
        machine = a.get("machine", a.get("alert_id", "Unknown"))
        summary = a.get("summary", "")[:90]
        ts      = str(a.get("timestamp", ""))[:16].replace("T", " ")
        colors  = {"Critical": "#da3633", "High": "#e3b341",
                   "Medium":   "#58a6ff", "Low":  "#3fb950"}
        color   = colors.get(sev, "#8b949e")
        return (f'<tr>'
                f'<td><span class="sev-badge" '
                f'style="background:{color}20;color:{color};'
                f'border:1px solid {color}40">{sev}</span></td>'
                f'<td class="machine">{machine}</td>'
                f'<td><code class="mitre">{mid}</code></td>'
                f'<td class="summary">{summary}</td>'
                f'<td class="ts">{ts}</td>'
                f'</tr>')

    alert_rows_html = "\n".join(alert_row(a) for a in sorted_alerts)
    if not alert_rows_html:
        alert_rows_html = ('<tr><td colspan="5" class="empty">'
                           'No alerts in log yet. Run the agent first.'
                           '</td></tr>')

    # Chart bars
    max_sev = max(sev_counts.values()) or 1
    def chart_bar(label, count, color):
        pct = int((count / max_sev) * 100)
        return (f'<div class="chart-row">'
                f'<span class="chart-label">{label}</span>'
                f'<div class="chart-track">'
                f'<div class="chart-fill" '
                f'style="width:{pct}%;background:{color}" '
                f'data-count="{count}"></div>'
                f'</div>'
                f'<span class="chart-count">{count}</span>'
                f'</div>')

    chart_html = (
        chart_bar("Critical", sev_counts["Critical"], "#da3633") +
        chart_bar("High",     sev_counts["High"],     "#e3b341") +
        chart_bar("Medium",   sev_counts["Medium"],   "#58a6ff") +
        chart_bar("Low",      sev_counts["Low"],      "#3fb950")
    )

    # ── HTML ──────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Agent — Threat Hunting Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:        #0a0d12;
  --surface:   #0f1419;
  --card:      #141b24;
  --border:    #1e2d3d;
  --accent:    #00d4ff;
  --red:       #da3633;
  --orange:    #e3b341;
  --green:     #3fb950;
  --blue:      #58a6ff;
  --text:      #e6edf3;
  --muted:     #7d8590;
  --mono:      'JetBrains Mono', monospace;
  --sans:      'Syne', sans-serif;
}}
body{{
  background:var(--bg);
  color:var(--text);
  font-family:var(--mono);
  min-height:100vh;
  background-image:
    radial-gradient(ellipse 80% 50% at 50% -20%,
      rgba(0,212,255,0.08) 0%, transparent 60%);
}}

/* HEADER */
.header{{
  padding:2rem 2.5rem 1.5rem;
  border-bottom:1px solid var(--border);
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:1rem;
}}
.header-left{{display:flex;align-items:center;gap:1rem}}
.pulse{{
  width:10px;height:10px;border-radius:50%;
  background:var(--green);
  box-shadow:0 0 0 0 rgba(63,185,80,0.4);
  animation:pulse 2s infinite;
  flex-shrink:0;
}}
@keyframes pulse{{
  0%{{box-shadow:0 0 0 0 rgba(63,185,80,0.4)}}
  70%{{box-shadow:0 0 0 8px rgba(63,185,80,0)}}
  100%{{box-shadow:0 0 0 0 rgba(63,185,80,0)}}
}}
.logo{{
  font-family:var(--sans);
  font-size:1.3rem;
  font-weight:800;
  letter-spacing:-0.02em;
}}
.logo span{{color:var(--accent)}}
.header-meta{{
  font-size:0.72rem;
  color:var(--muted);
  text-align:right;
  line-height:1.6;
}}
.header-meta strong{{color:var(--accent)}}

/* MAIN LAYOUT */
.main{{padding:2rem 2.5rem;max-width:1400px;margin:0 auto}}

/* STAT CARDS */
.stats-grid{{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:1rem;
  margin-bottom:2rem;
}}
.stat-card{{
  background:var(--card);
  border:1px solid var(--border);
  border-radius:8px;
  padding:1.25rem 1.5rem;
  position:relative;
  overflow:hidden;
  transition:border-color 0.2s;
}}
.stat-card::before{{
  content:'';
  position:absolute;
  top:0;left:0;right:0;
  height:2px;
  background:var(--accent-color, var(--accent));
}}
.stat-card:hover{{border-color:var(--accent);}}
.stat-label{{
  font-size:0.65rem;
  color:var(--muted);
  text-transform:uppercase;
  letter-spacing:0.1em;
  margin-bottom:0.5rem;
}}
.stat-value{{
  font-family:var(--sans);
  font-size:2rem;
  font-weight:800;
  color:var(--accent-color, var(--accent));
  line-height:1;
}}
.stat-sub{{
  font-size:0.65rem;
  color:var(--muted);
  margin-top:0.4rem;
}}

/* GRID */
.grid-2{{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:1.5rem;
  margin-bottom:1.5rem;
}}
@media(max-width:900px){{.grid-2{{grid-template-columns:1fr}}}}

/* PANELS */
.panel{{
  background:var(--card);
  border:1px solid var(--border);
  border-radius:8px;
  overflow:hidden;
}}
.panel-header{{
  padding:1rem 1.5rem;
  border-bottom:1px solid var(--border);
  display:flex;
  align-items:center;
  justify-content:space-between;
}}
.panel-title{{
  font-family:var(--sans);
  font-size:0.85rem;
  font-weight:700;
  letter-spacing:0.05em;
  text-transform:uppercase;
  color:var(--text);
}}
.panel-badge{{
  font-size:0.65rem;
  padding:0.2rem 0.6rem;
  border-radius:999px;
  background:rgba(0,212,255,0.1);
  color:var(--accent);
  border:1px solid rgba(0,212,255,0.2);
}}
.panel-body{{padding:1.25rem 1.5rem}}

/* RUN HISTORY */
.run-bar{{
  display:flex;
  align-items:center;
  gap:1rem;
  padding:0.6rem 0.75rem;
  margin-bottom:0.4rem;
  border-radius:4px;
  background:var(--surface);
  font-size:0.75rem;
  transition:background 0.15s;
}}
.run-bar:hover{{background:var(--border)}}
.run-ts{{color:var(--muted);flex-shrink:0;width:10rem}}
.run-label{{flex:1;font-weight:600}}
.run-cost{{color:var(--muted);flex-shrink:0}}

/* CHART */
.chart-row{{
  display:flex;
  align-items:center;
  gap:1rem;
  margin-bottom:0.75rem;
  font-size:0.8rem;
}}
.chart-label{{width:5rem;color:var(--muted)}}
.chart-track{{
  flex:1;height:8px;
  background:var(--surface);
  border-radius:4px;
  overflow:hidden;
}}
.chart-fill{{
  height:100%;border-radius:4px;
  transition:width 1s cubic-bezier(0.4,0,0.2,1);
}}
.chart-count{{width:2.5rem;text-align:right;color:var(--text);font-weight:600}}

/* ALERT TABLE */
.alert-table-wrap{{
  overflow-x:auto;
  margin-bottom:1.5rem;
}}
table{{width:100%;border-collapse:collapse;font-size:0.75rem}}
th{{
  text-align:left;
  padding:0.6rem 1rem;
  font-size:0.65rem;
  text-transform:uppercase;
  letter-spacing:0.08em;
  color:var(--muted);
  border-bottom:1px solid var(--border);
  font-weight:600;
}}
td{{
  padding:0.7rem 1rem;
  border-bottom:1px solid rgba(30,45,61,0.5);
  vertical-align:middle;
}}
tr:hover td{{background:rgba(0,212,255,0.02)}}
.sev-badge{{
  display:inline-block;
  padding:0.15rem 0.5rem;
  border-radius:4px;
  font-size:0.65rem;
  font-weight:700;
  white-space:nowrap;
}}
.machine{{color:var(--accent);font-weight:600}}
.mitre{{
  background:rgba(88,166,255,0.1);
  color:var(--blue);
  padding:0.1rem 0.4rem;
  border-radius:3px;
  font-size:0.7rem;
}}
.summary{{color:var(--muted);max-width:340px}}
.ts{{color:var(--muted);white-space:nowrap;font-size:0.7rem}}
.empty{{
  text-align:center;
  color:var(--muted);
  padding:2rem;
  font-size:0.8rem;
}}

/* FOOTER */
.footer{{
  text-align:center;
  padding:2rem;
  color:var(--muted);
  font-size:0.7rem;
  border-top:1px solid var(--border);
  margin-top:2rem;
}}
.footer a{{color:var(--accent);text-decoration:none}}
</style>
</head>
<body>

<header class="header">
  <div class="header-left">
    <div class="pulse"></div>
    <div>
      <div class="logo">SOC<span>Agent</span></div>
      <div style="font-size:0.65rem;color:var(--muted);margin-top:2px">
        Autonomous Threat Hunter — Azure Sentinel
      </div>
    </div>
  </div>
  <div class="header-meta">
    <strong>LIVE</strong> — refreshed {now}<br>
    Analyst: Sakho Aboubacar &nbsp;|&nbsp;
    Cyber Range — lognpacific.com
  </div>
</header>

<main class="main">

  <!-- STATS -->
  <div class="stats-grid">
    <div class="stat-card" style="--accent-color:#da3633">
      <div class="stat-label">Critical Findings</div>
      <div class="stat-value">{total_critical}</div>
      <div class="stat-sub">across all runs</div>
    </div>
    <div class="stat-card" style="--accent-color:#e3b341">
      <div class="stat-label">High Severity</div>
      <div class="stat-value">{total_high}</div>
      <div class="stat-sub">requires escalation</div>
    </div>
    <div class="stat-card" style="--accent-color:#00d4ff">
      <div class="stat-label">Total Alerts</div>
      <div class="stat-value">{total_alerts}</div>
      <div class="stat-sub">processed by agent</div>
    </div>
    <div class="stat-card" style="--accent-color:#3fb950">
      <div class="stat-label">Agent Runs</div>
      <div class="stat-value">{total_runs}</div>
      <div class="stat-sub">{clean_runs} clean runs</div>
    </div>
    <div class="stat-card" style="--accent-color:#8b949e">
      <div class="stat-label">Total Cost</div>
      <div class="stat-value">${total_cost:.3f}</div>
      <div class="stat-sub">OpenAI API spend</div>
    </div>
    <div class="stat-card" style="--accent-color:#3fb950">
      <div class="stat-label">Schedule</div>
      <div class="stat-value" style="font-size:1.2rem;padding-top:0.3rem">15 min</div>
      <div class="stat-sub">automated hunting</div>
    </div>
  </div>

  <!-- RUN HISTORY + CHART -->
  <div class="grid-2">

    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Recent Runs</span>
        <span class="panel-badge">{total_runs} total</span>
      </div>
      <div class="panel-body">
        {run_bars_html}
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Severity Distribution</span>
        <span class="panel-badge">{len(all_alerts)} alerts</span>
      </div>
      <div class="panel-body">
        {chart_html}
        <div style="margin-top:1.5rem;padding-top:1rem;
                    border-top:1px solid var(--border);
                    font-size:0.7rem;color:var(--muted)">
          <strong style="color:var(--text)">Machines investigated:</strong>
          {len(set(a.get('machine','') or a.get('alert_id','')
                   for a in all_alerts))}
          unique endpoints
        </div>
      </div>
    </div>

  </div>

  <!-- ALERT FEED -->
  <div class="panel alert-table-wrap">
    <div class="panel-header">
      <span class="panel-title">Alert Intelligence Feed</span>
      <span class="panel-badge">Top {len(sorted_alerts)} by severity</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Machine</th>
          <th>MITRE</th>
          <th>Finding</th>
          <th>Timestamp</th>
        </tr>
      </thead>
      <tbody>
        {alert_rows_html}
      </tbody>
    </table>
  </div>

</main>

<footer class="footer">
  SOC Agent — Built by <strong>Sakho Aboubacar</strong> &nbsp;|&nbsp;
  Python + GPT-4o + Azure Sentinel &nbsp;|&nbsp;
  <a href="#">GitHub Portfolio</a>
  &nbsp;|&nbsp; Generated {now}
</footer>

<script>
  // Animate chart bars on load
  document.querySelectorAll('.chart-fill').forEach(bar => {{
    const w = bar.style.width;
    bar.style.width = '0';
    setTimeout(() => {{ bar.style.width = w; }}, 100);
  }});

  // Auto-refresh every 5 minutes
  setTimeout(() => location.reload(), 5 * 60 * 1000);
</script>
</body>
</html>"""

    with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"  ✅ Dashboard saved to {DASHBOARD_FILE}")
    print(f"  Open in browser: file:///{DASHBOARD_FILE}")
    return str(DASHBOARD_FILE)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 55)
    print("  SOC AGENT — DASHBOARD GENERATOR")
    print(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 55)
    print()

    run_log    = load_run_log()
    all_alerts = load_live_alerts()

    print(f"  Run log entries:  {len(run_log)}")
    print(f"  Alerts in log:    {len(all_alerts)}")
    print()

    path = generate_dashboard()

    print()
    print("  Stats:")
    total_cost = sum(r.get("cost", 0) for r in run_log)
    total_crit = sum(r.get("critical", 0) for r in run_log)
    print(f"  Total cost:     ${total_cost:.4f}")
    print(f"  Total critical: {total_crit}")
    print(f"  Total alerts:   {len(all_alerts)}")
    print()
    print("  To open the dashboard:")
    print(f"  Start {path}")
    print()
    print("  To add to scheduled task (auto-refresh dashboard):")
    print("  Add this line to run_soc_agent.bat:")
    print("  py phase5_lesson13.py")

# ============================================================
# WHAT YOU JUST BUILT:
# A self-contained HTML dashboard that reads your run logs
# and alert data and renders a live SOC operations view.
#
# Features:
# - 6 live stat cards (Critical, High, Total, Runs, Cost)
# - Run history timeline (last 10 runs with color coding)
# - Severity distribution chart with animations
# - Alert intelligence feed sorted by severity
# - Auto-refreshes every 5 minutes
# - Pulsing green dot = agent is alive
#
# HOW TO USE:
# 1. Run this script to generate the dashboard
# 2. Open soc_dashboard.html in any browser
# 3. Add to batch file to regenerate after every run
#
# HIRING MANAGER DEMO:
# Open this dashboard and say:
# "This updates automatically every 15 minutes.
#  Every alert is triaged by AI. Critical findings
#  trigger a Slack notification immediately.
#  Total cost for 24 hours of hunting: under $1."
#
# NEXT LESSON — Lesson 14:
# Deploy as Azure Function — agent moves to the cloud.
# Runs 24/7 without your VM being on.
# ============================================================