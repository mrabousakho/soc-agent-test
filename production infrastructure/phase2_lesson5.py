# ============================================================
# PHASE 2 — LESSON 5: File I/O + Persistent Alert Log
# Mentor: Claude | Student: Sakho Aboubacar
# Goal: Agent reads alerts from a JSON file (like a SIEM
#       export) and saves every result to a persistent log.
#       This is how agents build memory across sessions.
# ============================================================

import os
import json
import time
import re
from datetime import datetime, timezone
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise EnvironmentError("OPENAI_API_KEY not found in .env file.")

client = OpenAI(api_key=api_key)

# ============================================================
# FILE PATHS
# Everything the agent reads from and writes to is defined
# here at the top. In production these become config values.
# ============================================================
ALERTS_INPUT_FILE = "alerts_input.json"       # Agent reads FROM here
ALERT_LOG_FILE    = "alert_log.json"          # Agent writes TO here
SUMMARY_FILE      = "triage_summary.txt"      # Human-readable report

# ============================================================
# HELPER FUNCTIONS (carried over from Phase 1)
# ============================================================

def clean_json_response(raw: str) -> str:
    raw = re.sub(r"```(?:json)?", "", raw).strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"No JSON object found: {raw[:100]}")
    return raw[start:end + 1]


def analyze_alert(alert_id: str, alert_raw: str) -> dict:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": """You are a senior SOC analyst AI with deep knowledge of the MITRE ATT&CK framework.
Analyze the security alert and return ONLY a JSON object.
No explanation. No markdown. No extra text. Just raw JSON.

Use exactly this structure:
{
    "severity": "Critical" or "High" or "Medium" or "Low",
    "mitre_id": "T1059.003",
    "mitre_name": "Command and Scripting Interpreter: Windows Command Shell",
    "confidence": 0.95,
    "recommended_action": "one sentence action",
    "escalate": true or false,
    "block_ip": true or false,
    "summary": "one sentence summary of what happened"
}

MITRE classification rules:
- Repeated failed logins from external IP = T1110.001 Brute Force, severity HIGH
- CMD or PowerShell spawned by Office app = T1059 Command Execution, severity HIGH
- Scheduled task created with PowerShell bypass = T1053.005 Scheduled Task, severity CRITICAL
- Sensitive file accessed (passwords, credentials) = T1083 File Discovery, severity HIGH
- Internal network logon during business hours = T1078 Valid Accounts, severity LOW

Rules:
- escalate = true if severity is Critical or High
- block_ip = true only if there is a confirmed malicious external IP
- confidence is a float between 0 and 1"""
            },
            {
                "role": "user",
                "content": f"Analyze this alert:\n{alert_raw}"
            }
        ],
        temperature=0
    )

    raw = response.choices[0].message.content
    tokens = response.usage.total_tokens

    try:
        cleaned = clean_json_response(raw)
        result = json.loads(cleaned)
        result["alert_id"] = alert_id
        result["tokens"] = tokens
        result["parse_error"] = False
        return result
    except Exception as e:
        return {
            "alert_id": alert_id,
            "severity": "High",
            "mitre_id": "UNKNOWN",
            "mitre_name": "Parse error — manual review",
            "confidence": 0.0,
            "recommended_action": "Manual review required",
            "escalate": True,
            "block_ip": False,
            "summary": "Agent parse error — escalating for safety",
            "tokens": tokens,
            "parse_error": True
        }


# ============================================================
# STEP 1: READ ALERTS FROM FILE
# In Phase 3 this function gets replaced with a live
# Azure Sentinel API call. The rest of the code stays
# exactly the same — that is good agent architecture.
# ============================================================

def load_alerts(filepath: str) -> list:
    """Load alerts from a JSON file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"Alert input file not found: {filepath}\n"
            f"Make sure alerts_input.json is in the same folder."
        )

    with open(filepath, "r") as f:
        alerts = json.load(f)

    print(f"  Loaded {len(alerts)} alerts from {filepath}")
    return alerts


# ============================================================
# STEP 2: LOAD EXISTING LOG (agent memory)
# If the log file exists, load it. Otherwise start fresh.
# This is how the agent remembers what it has seen before.
# ============================================================

def load_existing_log(filepath: str) -> list:
    """Load previously processed alerts from the log file."""
    if not os.path.exists(filepath):
        return []   # First run — no history yet

    with open(filepath, "r") as f:
        return json.load(f)


# ============================================================
# STEP 3: SAVE RESULTS TO LOG
# Every analyzed alert gets saved with a timestamp.
# This builds the agent's persistent memory.
# ============================================================

def save_log(filepath: str, log: list) -> None:
    """Save the full alert log to disk."""
    with open(filepath, "w") as f:
        json.dump(log, f, indent=2)


# ============================================================
# STEP 4: GENERATE HUMAN-READABLE SUMMARY REPORT
# This is what you hand to a Tier 2 analyst or manager.
# In Phase 5 this gets emailed automatically.
# ============================================================

def generate_summary(results: list, filepath: str) -> None:
    """Write a plain-text triage report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_tokens = sum(r.get("tokens", 0) for r in results)

    lines = []
    lines.append("=" * 55)
    lines.append("  SOC AGENT — TRIAGE REPORT")
    lines.append(f"  Generated: {now}")
    lines.append(f"  Alerts processed: {len(results)}")
    lines.append("=" * 55)
    lines.append("")

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_results = sorted(
        results,
        key=lambda x: severity_order.get(x["severity"], 99)
    )

    for i, r in enumerate(sorted_results, 1):
        lines.append(f"[{i}] {r['alert_id']} — {r['severity'].upper()}")
        lines.append(f"    Time:    {r.get('timestamp', 'Unknown')}")
        lines.append(f"    MITRE:   {r['mitre_id']} {r['mitre_name']}")
        lines.append(f"    Summary: {r['summary']}")
        lines.append(f"    Action:  {r['recommended_action']}")

        actions = []
        if r.get("escalate"):
            actions.append("ESCALATE to Tier 2")
        if r.get("block_ip"):
            actions.append("BLOCK IP")
        if not actions:
            actions.append("Log and monitor")
        lines.append(f"    Agent:   {' | '.join(actions)}")
        lines.append("")

    lines.append("=" * 55)
    lines.append("  SUMMARY STATS")
    lines.append("=" * 55)

    for sev in ["Critical", "High", "Medium", "Low"]:
        count = sum(1 for r in results if r["severity"] == sev)
        if count:
            lines.append(f"  {sev:<10} {count} alert(s)")

    lines.append(f"  Total tokens:  {total_tokens}")
    lines.append(f"  Est. cost:     ${total_tokens * 0.000005:.4f}")
    lines.append("")
    lines.append("  End of report.")
    lines.append("=" * 55)

    with open(filepath, "w") as f:
        f.write("\n".join(lines))

    print(f"  Summary report saved to {filepath}")


# ============================================================
# MAIN — putting it all together
# ============================================================

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

print("=" * 55)
print("  SOC AGENT — PHASE 2 SESSION START")
print("=" * 55)
print()

# Step 1: Load alerts from file
print("[1/4] Loading alerts from file...")
alerts = load_alerts(ALERTS_INPUT_FILE)
print()

# Step 2: Load existing log
print("[2/4] Loading existing alert log...")
existing_log = load_existing_log(ALERT_LOG_FILE)
already_seen = {entry["alert_id"] for entry in existing_log}
print(f"  Previously processed: {len(already_seen)} alerts")
print(f"  Already seen IDs: {already_seen if already_seen else 'None — first run'}")
print()

# Step 3: Analyze only NEW alerts
print("[3/4] Analyzing new alerts...")
new_results = []
skipped = 0

for alert in alerts:
    alert_id = alert["id"]

    if alert_id in already_seen:
        print(f"  SKIP {alert_id} — already in log")
        skipped += 1
        continue

    print(f"  Analyzing {alert_id}...", end=" ", flush=True)
    result = analyze_alert(alert_id, alert["raw"])

    # Add metadata from the input file
    result["timestamp"] = alert.get("timestamp", "Unknown")
    result["source"] = alert.get("source", "Unknown")
    result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
    result["raw"] = alert.get("raw", "")

    new_results.append(result)

    indicator = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
    print(f"{indicator.get(result['severity'], '⚪')} {result['severity']}")

    time.sleep(1)

print()
print(f"  New alerts analyzed: {len(new_results)}")
print(f"  Alerts skipped (already processed): {skipped}")
print()

# Step 4: Save updated log
print("[4/4] Saving results...")
updated_log = existing_log + new_results
save_log(ALERT_LOG_FILE, updated_log)
print(f"  Alert log saved to {ALERT_LOG_FILE}")
print(f"  Total alerts in log: {len(updated_log)}")

# Generate summary report
generate_summary(new_results if new_results else updated_log, SUMMARY_FILE)
print()

# Step 5: Print priority queue to screen
if new_results:
    new_results.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    print("=" * 55)
    print("  PRIORITY QUEUE — NEW ALERTS")
    print("=" * 55)
    for i, r in enumerate(new_results, 1):
        indicator = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        print(f"\n  [{i}] {indicator.get(r['severity'],'⚪')} {r['alert_id']} — {r['severity'].upper()}")
        print(f"       {r['mitre_id']} {r['mitre_name']}")
        print(f"       {r['summary']}")
else:
    print("  No new alerts to display — all already processed.")

print()
print("=" * 55)
print("  SESSION COMPLETE")
print(f"  Run again to test deduplication — agent will skip")
print(f"  all {len(updated_log)} alerts already in the log.")
print("=" * 55)

# ============================================================
# WHAT YOU JUST BUILT:
# - load_alerts(): reads from file (replaces with API in Ph3)
# - load_existing_log(): agent memory across sessions
# - save_log(): persistent storage of every result
# - generate_summary(): human-readable report for analysts
# - Deduplication: skips alerts already in the log
#
# KEY TEST: Run this script TWICE.
# First run: analyzes all 5 alerts, saves to log
# Second run: skips all 5 (already processed), costs $0.00
# That is production-grade efficiency.
#
# NEXT LESSON — Lesson 6:
# Pattern detection across sessions.
# Agent notices: same user, multiple alerts = attack chain.
# ============================================================