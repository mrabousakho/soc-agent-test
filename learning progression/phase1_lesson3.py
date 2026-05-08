# ============================================================
# PHASE 1 — LESSON 3: Multiple Alerts + Priority Queue
# Mentor: Claude | Student: Sakho Aboubacar
# Goal: Process a batch of alerts, sort by severity,
#       handle Critical first — real SOC triage logic
# ============================================================

import os
import json
import time
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise EnvironmentError("OPENAI_API_KEY not found in .env file.")

client = OpenAI(api_key=api_key)

# --- MULTIPLE ALERTS (simulating a real alert queue) ---
# These mirror real events you would see in Azure Sentinel
# Notice they come in random order — just like in real life
ALERTS = [
    {
        "id": "ALT-001",
        "raw": """
        EventID: 4625
        Source IP: 49.147.192.56
        Target Account: g4bri3lintern
        Failure Count: 47 in 3 minutes
        Logon Type: 10 (RemoteInteractive)
        """
    },
    {
        "id": "ALT-002",
        "raw": """
        EventID: 4688
        Process: cmd.exe
        Parent Process: winword.exe
        User: g4bri3lintern
        Command: cmd.exe /c whoami && ipconfig && net user
        Machine: gab-intern-vm
        """
    },
    {
        "id": "ALT-003",
        "raw": """
        EventID: 4698
        Task Name: SupportToolUpdater
        Command: powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\g4bri3lintern\\Downloads\\SupportTool.ps1
        Created By: g4bri3lintern
        Machine: gab-intern-vm
        """
    },
    {
        "id": "ALT-004",
        "raw": """
        EventID: 4663
        File Accessed: C:\\Users\\g4bri3lintern\\Documents\\passwords.txt
        Process: notepad.exe
        User: g4bri3lintern
        Access Type: ReadData
        """
    },
    {
        "id": "ALT-005",
        "raw": """
        EventID: 4624
        Source IP: 192.168.1.105
        Account: helpdesk_admin
        Logon Type: 3 (Network)
        Machine: gab-intern-vm
        Time: Business hours
        """
    }
]

# --- SEVERITY PRIORITY MAP ---
# This is how the agent knows which order to handle alerts
SEVERITY_ORDER = {
    "Critical": 0,
    "High":     1,
    "Medium":   2,
    "Low":      3
}

# --- FUNCTION: Analyze a single alert ---
# We wrap this in a function so we can call it in a loop
def analyze_alert(alert_id, alert_raw):
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

MITRE classification rules — read carefully:
- Repeated failed logins from external IP = T1110.001 Brute Force
- CMD or PowerShell spawned by Office app (Word, Excel) = T1059 Command Execution, severity HIGH
- Scheduled task created with PowerShell bypass = T1053.005 Scheduled Task, severity CRITICAL
- Sensitive file accessed (passwords, credentials) = T1083 File Discovery, severity HIGH
- Internal network logon during business hours, known account = T1078 Valid Accounts, severity LOW

Severity rules:
- Critical: persistence mechanisms, credential dumping, lateral movement
- High: execution from suspicious parent, sensitive file access, external brute force
- Medium: reconnaissance commands, unusual but explainable activity
- Low: normal activity with minor anomalies

Escalation and blocking rules:
- escalate = true if severity is Critical or High
- block_ip = true only if there is a confirmed malicious external IP
- confidence is a float between 0 and 1

Always assign the most specific MITRE technique that matches the alert.
Never assign the same technique to different attack patterns."""
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
        result = json.loads(raw)
        result["alert_id"] = alert_id
        result["tokens"] = tokens
        return result
    except json.JSONDecodeError:
        # If JSON parsing fails, return a safe default
        return {
            "alert_id": alert_id,
            "severity": "Medium",
            "mitre_id": "Unknown",
            "mitre_name": "Parse error",
            "confidence": 0.0,
            "recommended_action": "Manual review required",
            "escalate": True,
            "block_ip": False,
            "summary": "Agent failed to parse this alert — needs manual review",
            "tokens": tokens
        }

# ============================================================
# MAIN LOOP: Process all alerts
# ============================================================
print("=" * 55)
print("  SOC AGENT — BATCH TRIAGE STARTING")
print(f"  Processing {len(ALERTS)} alerts...")
print("=" * 55)
print()

results = []
total_tokens = 0

for alert in ALERTS:
    print(f"Analyzing {alert['id']}...", end=" ", flush=True)

    analysis = analyze_alert(alert["id"], alert["raw"])
    results.append(analysis)
    total_tokens += analysis["tokens"]

    print(f"{analysis['severity']} ({analysis['confidence']*100:.0f}% confidence)")

    # Small delay between API calls — good practice to avoid rate limits
    time.sleep(1)

# --- SORT BY PRIORITY: Critical first, Low last ---
results.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

# ============================================================
# PRIORITY QUEUE OUTPUT
# ============================================================
print()
print("=" * 55)
print("  PRIORITY QUEUE — HANDLE IN THIS ORDER")
print("=" * 55)

for i, r in enumerate(results, 1):
    print()
    print(f"  [{i}] {r['alert_id']} — {r['severity'].upper()}")
    print(f"      MITRE:   {r['mitre_id']} {r['mitre_name']}")
    print(f"      Summary: {r['summary']}")
    print(f"      Action:  {r['recommended_action']}")

    # Decision engine
    actions = []
    if r["escalate"]:
        actions.append("ESCALATE to Tier 2")
    if r["block_ip"]:
        actions.append("BLOCK IP at firewall")
    if not actions:
        actions.append("Log and monitor")

    print(f"      Agent:   {' | '.join(actions)}")

# ============================================================
# SUMMARY STATS
# ============================================================
print()
print("=" * 55)
print("  TRIAGE SUMMARY")
print("=" * 55)

severity_counts = {}
for r in results:
    s = r["severity"]
    severity_counts[s] = severity_counts.get(s, 0) + 1

for severity in ["Critical", "High", "Medium", "Low"]:
    count = severity_counts.get(severity, 0)
    if count > 0:
        print(f"  {severity:<10} {count} alert(s)")

escalate_count = sum(1 for r in results if r["escalate"])
block_count = sum(1 for r in results if r["block_ip"])

print()
print(f"  Alerts requiring escalation: {escalate_count}/{len(results)}")
print(f"  IPs flagged for blocking:    {block_count}/{len(results)}")
print(f"  Total tokens used:           {total_tokens}")
print(f"  Est. cost (GPT-4o):          ${total_tokens * 0.000005:.4f}")
print()
print("  Batch triage complete.")
print("=" * 55)

# ============================================================
# WHAT YOU JUST BUILT:
# - Alert ingestion loop (foundation of any SIEM integration)
# - Per-alert AI analysis with error handling
# - Automatic priority sorting (Critical → Low)
# - Decision engine running on every alert
# - Cost tracking per batch
#
# LOOK AT ALERT ALT-003 CAREFULLY:
# That is the exact SupportToolUpdater scheduled task from
# your real threat hunt. Your agent should classify it as
# Critical or High. If it does, that confirms the agent
# understands real attacker persistence techniques.
#
# NEXT LESSON:
# - Save results to a JSON file (alert log)
# - Load previous results and compare (drift detection)
# - This is how agents build memory across sessions
# ============================================================