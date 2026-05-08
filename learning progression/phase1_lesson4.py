# ============================================================
# PHASE 1 — LESSON 4: Response Cleaning + Robust JSON Parsing
# Mentor: Claude | Student: Sakho Aboubacar
# Goal: Make the agent handle 100% of alerts without
#       falling back to manual review due to parse errors.
#       This is production-grade reliability.
# ============================================================

import os
import json
import time
import re
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise EnvironmentError("OPENAI_API_KEY not found in .env file.")

client = OpenAI(api_key=api_key)

# ============================================================
# THE CLEANER FUNCTION
# This is the most important function in this lesson.
# The model sometimes wraps JSON in markdown like this:
#
#   ```json
#   { "severity": "High" ... }
#   ```
#
# Or adds text before/after:
#   "Here is the analysis: { ... }"
#
# This function strips all of that and extracts pure JSON.
# ============================================================

def clean_json_response(raw: str) -> str:
    """
    Strip markdown fences, leading/trailing text,
    and extract the first valid JSON object from a string.
    """
    # Step 1: Remove markdown code fences
    # Handles ```json ... ``` and ``` ... ```
    raw = re.sub(r"```(?:json)?", "", raw).strip()

    # Step 2: Find the first { and last } — extract only that
    start = raw.find("{")
    end = raw.rfind("}")

    if start == -1 or end == -1:
        # No JSON object found at all
        raise ValueError(f"No JSON object found in response: {raw[:100]}")

    return raw[start:end + 1]


def analyze_alert(alert_id: str, alert_raw: str) -> dict:
    """
    Send a single alert to the model and return a clean dict.
    Includes response cleaning and two-stage error handling.
    """
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
- Repeated failed logins from external IP = T1110.001 Brute Force
- CMD or PowerShell spawned by Office app = T1059 Command Execution, severity HIGH
- Scheduled task created with PowerShell bypass = T1053.005 Scheduled Task, severity CRITICAL
- Sensitive file accessed (passwords, credentials) = T1083 File Discovery, severity HIGH
- Internal network logon during business hours = T1078 Valid Accounts, severity LOW

Severity rules:
- Critical: persistence mechanisms, credential dumping, lateral movement
- High: execution from suspicious parent, sensitive file access, external brute force
- Medium: reconnaissance, unusual but explainable activity
- Low: normal activity with minor anomalies

Rules:
- escalate = true if severity is Critical or High
- block_ip = true only if there is a confirmed malicious external IP
- confidence is a float between 0 and 1
- Always assign the most specific MITRE technique that matches"""
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

    # Stage 1: Clean the response
    try:
        cleaned = clean_json_response(raw)
    except ValueError as e:
        print(f"\n  [WARN] Cleaning failed for {alert_id}: {e}")
        return _fallback(alert_id, tokens)

    # Stage 2: Parse the cleaned JSON
    try:
        result = json.loads(cleaned)
        result["alert_id"] = alert_id
        result["tokens"] = tokens
        result["parse_error"] = False
        return result
    except json.JSONDecodeError as e:
        print(f"\n  [WARN] JSON parse failed for {alert_id}: {e}")
        print(f"  Cleaned output was: {cleaned[:100]}")
        return _fallback(alert_id, tokens)


def _fallback(alert_id: str, tokens: int) -> dict:
    """
    Safe fallback when all parsing fails.
    Always escalates — when in doubt, a human should look.
    """
    return {
        "alert_id": alert_id,
        "severity": "High",
        "mitre_id": "UNKNOWN",
        "mitre_name": "Parse error — manual review",
        "confidence": 0.0,
        "recommended_action": "Manual review required — agent could not parse response",
        "escalate": True,
        "block_ip": False,
        "summary": "Agent parse error — escalating for safety",
        "tokens": tokens,
        "parse_error": True
    }


# ============================================================
# ALERTS — same 5 from Lesson 3
# ============================================================
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

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# ============================================================
# MAIN LOOP
# ============================================================
print("=" * 55)
print("  SOC AGENT — BATCH TRIAGE v2 (Robust Parser)")
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

    # Flag parse errors in the live output
    if analysis.get("parse_error"):
        print(f"PARSE ERROR — escalated for manual review")
    else:
        print(f"{analysis['severity']} ({analysis['confidence']*100:.0f}% confidence)")

    time.sleep(1)

# Sort by priority
results.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

# ============================================================
# PRIORITY QUEUE OUTPUT
# ============================================================
print()
print("=" * 55)
print("  PRIORITY QUEUE — HANDLE IN THIS ORDER")
print("=" * 55)

for i, r in enumerate(results, 1):
    # Visual severity indicator
    indicator = {
        "Critical": "🔴",
        "High":     "🟠",
        "Medium":   "🟡",
        "Low":      "🟢"
    }.get(r["severity"], "⚪")

    print()
    print(f"  [{i}] {indicator} {r['alert_id']} — {r['severity'].upper()}")
    print(f"      MITRE:   {r['mitre_id']} {r['mitre_name']}")
    print(f"      Summary: {r['summary']}")
    print(f"      Action:  {r['recommended_action']}")

    actions = []
    if r["escalate"]:
        actions.append("ESCALATE to Tier 2")
    if r["block_ip"]:
        actions.append("BLOCK IP at firewall")
    if not actions:
        actions.append("Log and monitor")

    print(f"      Agent:   {' | '.join(actions)}")

    if r.get("parse_error"):
        print(f"      ⚠️  PARSE ERROR — confidence unavailable")

# ============================================================
# SUMMARY
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
        bar = "█" * count
        print(f"  {severity:<10} {bar} {count}")

parse_errors = sum(1 for r in results if r.get("parse_error"))
escalate_count = sum(1 for r in results if r["escalate"])
block_count = sum(1 for r in results if r["block_ip"])

print()
print(f"  Alerts processed:            {len(results)}")
print(f"  Parse errors:                {parse_errors}")
print(f"  Requiring escalation:        {escalate_count}/{len(results)}")
print(f"  IPs flagged for blocking:    {block_count}/{len(results)}")
print(f"  Total tokens used:           {total_tokens}")
print(f"  Est. cost (GPT-4o):          ${total_tokens * 0.000005:.4f}")
print()
print("  Batch triage complete.")
print("=" * 55)

# ============================================================
# WHAT YOU JUST BUILT:
# - clean_json_response(): strips markdown, extracts pure JSON
# - Two-stage error handling: clean first, parse second
# - Safe fallback that always escalates on failure
# - Parse error tracking in summary stats
# - Production reliability: agent never crashes on bad output
#
# KEY INSIGHT:
# The cleaner function uses regex to find { ... } boundaries.
# This works regardless of what the model wraps around the JSON.
# Every production LLM pipeline needs this pattern.
#
# NEXT LESSON — Lesson 5:
# Save results to a JSON file (persistent alert log)
# This gives your agent MEMORY across sessions.
# ============================================================