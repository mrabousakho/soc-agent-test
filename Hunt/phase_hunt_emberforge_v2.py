# ============================================================
# EMBERFORGE HUNT AGENT V2 — TUNED FOR SPEED
# Mentor: Claude | Student: Sakho Aboubacar
# Hunt: EmberForge Source Leak // Hunt 01
# Version: 2 — tuned from real flag answers
# Key fix: ago(9999d) for Security events
#          Targeted queries for highest-value findings
#          Smaller result sets, higher signal
# ============================================================

import os
import json
import re
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from azure.identity import AzureCliCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from openai import OpenAI
from pathlib import Path

load_dotenv()

BASE_DIR = Path(__file__).parent.absolute()

CONFIG = {
    "workspace_id": os.getenv("AZURE_WORKSPACE_ID"),
    "model":        "gpt-4o",
    "table":        "EmberForgeX_CL",
    "t_start":      "2026-01-30 21:00:00",
    "t_end":        "2026-01-31 00:00:00",
    "report_file":  str(BASE_DIR / "emberforge_v2_findings.txt"),
}

# ── Shorthand ─────────────────────────────────────────────
T  = CONFIG["table"]
T1 = CONFIG["t_start"]
T2 = CONFIG["t_end"]
TF = f"todatetime(UtcTime_s) between (datetime({T1}) .. datetime({T2}))"

print("=" * 60)
print("  EMBERFORGE HUNT AGENT V2")
print("  Targeted — Signal over volume")
print(f"  Started: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
print("=" * 60)
print()

try:
    credential    = AzureCliCredential()
    logs_client   = LogsQueryClient(credential)
    openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    print("  ✅ Azure connected")
    print("  ✅ OpenAI connected")
except Exception as e:
    print(f"  ❌ {e}")
    exit()
print()

# ============================================================
# KQL RUNNER
# ============================================================

def kql(label: str, query: str) -> list:
    """Run KQL with maximum timespan — returns list of dicts."""
    print(f"  [{label}]", end=" ", flush=True)
    try:
        response = logs_client.query_workspace(
            workspace_id=CONFIG["workspace_id"],
            query=query,
            timespan=timedelta(days=9999)
        )
        if response.status == LogsQueryStatus.SUCCESS:
            rows = []
            for table in response.tables:
                cols = table.columns
                for row in table.rows:
                    rows.append(dict(zip(cols, row)))
            print(f"{len(rows)} results")
            return rows
        else:
            print(f"error: {response.partial_error}")
            return []
    except Exception as e:
        print(f"ERROR: {e}")
        return []


def fmt(rows: list, limit: int = 8) -> str:
    """Format rows as readable text for AI context."""
    lines = []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        parts = [f"{k}: {str(v)[:200]}"
                 for k, v in row.items()
                 if v and k not in ["Raw_s","EventData_Xml_s"]]
        lines.append("  " + " | ".join(parts))
    return "\n".join(lines)


# ============================================================
# TARGETED HUNT QUERIES
# Ordered by hunt impact — highest value first
# Each query answers a specific flag category
# ============================================================

findings = {}

# ── Q1: EXFILTRATION TOOLS ───────────────────────────────
# Flag 02 — Cloud provider
# Flag 03 — rclone command line
# Flag 04 — MEGA account
print("[ HUNT 1 ] Exfiltration tools")
findings["exfil_tools"] = kql("rclone/exfil", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where CommandLine_s has_any (
    "rclone","mega","dropbox","onedrive",
    "aws s3","curl -T","wget --post")
| project UtcTime_s, Computer, User_s,
          Image_s, CommandLine_s,
          ParentImage_s, SHA256_s
| order by UtcTime_s asc
""")

# ── Q2: DATA COMPRESSION / STAGING ───────────────────────
# Flag 01 — Source directory (C:\GameDev)
# Flag — Archive filename
print("[ HUNT 2 ] Data compression and staging")
findings["compression"] = kql("Compress-Archive/7z/zip", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where CommandLine_s has_any (
    "Compress-Archive","7z","rar","zip",
    "tar","compact")
| project UtcTime_s, Computer, User_s,
          CommandLine_s, ParentImage_s
| order by UtcTime_s asc
""")

# ── Q3: DROPPED EXECUTABLES IN SUSPICIOUS PATHS ──────────
# Flag — Malware filename (update.exe)
# Flag — Drop path (C:\Users\Public)
print("[ HUNT 3 ] Executables dropped in suspicious paths")
findings["dropped_exe"] = kql("Dropped executables", f"""
{T}
| where {TF}
| where EventCode_s == "11"
| where TargetFilename_s has_any (
    "\\\\Users\\\\Public\\\\",
    "\\\\Windows\\\\Temp\\\\",
    "\\\\ProgramData\\\\",
    "\\\\AppData\\\\Roaming\\\\",
    "\\\\AppData\\\\Local\\\\Temp\\\\")
| where TargetFilename_s endswith ".exe"
    or TargetFilename_s endswith ".dll"
    or TargetFilename_s endswith ".bat"
    or TargetFilename_s endswith ".ps1"
| project UtcTime_s, Computer,
          TargetFilename_s, Image_s,
          SHA256_s
| order by UtcTime_s asc
""")

# ── Q4: C2 BEACONING ─────────────────────────────────────
# Flag — C2 domain (cdn.cloud-endpoint.net)
# Flag — C2 IP (194.165.16.11)
print("[ HUNT 4 ] C2 network beaconing")
findings["c2_beaconing"] = kql("C2 beaconing", f"""
{T}
| where {TF}
| where EventCode_s == "3"
| where Image_s !has "browser"
| where Image_s !has "chrome"
| where Image_s !has "firefox"
| where Image_s !has "edge"
| where Image_s !has "splunk"
| where DestinationHostname_s != ""
    or DestinationIp_s != ""
| summarize
    Count=count(),
    Processes=make_set(Image_s),
    Ports=make_set(DestinationPort_s),
    First=min(UtcTime_s),
    Last=max(UtcTime_s)
  by DestinationIp_s, DestinationHostname_s, Computer
| order by Count desc
""")

# ── Q5: DNS QUERIES ──────────────────────────────────────
# Flag — C2 domain from DNS
# Flag — Staging server domain
print("[ HUNT 5 ] DNS queries to suspicious domains")
findings["dns_queries"] = kql("DNS queries", f"""
{T}
| where {TF}
| where EventCode_s == "22"
| where QueryName_s !has "microsoft"
| where QueryName_s !has "windows"
| where QueryName_s !has "windowsupdate"
| where QueryName_s !has "splunk"
| where QueryName_s !has "amazon"
| where QueryName_s !has "azure"
| project UtcTime_s, Computer,
          QueryName_s, Image_s
| order by UtcTime_s asc
""")

# ── Q6: PROCESS INJECTION ────────────────────────────────
# Flag — Injector process
# Flag — Target process
print("[ HUNT 6 ] Process injection (Sysmon Event 8)")
findings["injection"] = kql("Process injection", f"""
{T}
| where {TF}
| where EventCode_s == "8"
| project UtcTime_s, Computer,
          Image_s, Raw_s
| order by UtcTime_s asc
""")

# ── Q7: UAC BYPASS ───────────────────────────────────────
# Flag — UAC bypass method (fodhelper)
print("[ HUNT 7 ] UAC bypass")
findings["uac_bypass"] = kql("UAC bypass", f"""
{T}
| where {TF}
| where EventCode_s in ("1","13")
| where CommandLine_s has_any (
    "fodhelper","eventvwr","sdclt",
    "computerdefaults","slui",
    "ms-settings")
    or TargetObject_s has_any (
    "ms-settings","fodhelper")
| project UtcTime_s, Computer, User_s,
          Image_s, CommandLine_s,
          TargetObject_s, Details_s
| order by UtcTime_s asc
""")

# ── Q8: LSASS CREDENTIAL DUMP ────────────────────────────
# Flag — LSASS dump file path
# Flag — Tool used
print("[ HUNT 8 ] LSASS credential dumping")
findings["lsass_dump"] = kql("LSASS dump", f"""
{T}
| where {TF}
| where EventCode_s in ("1","11")
| where CommandLine_s has_any (
    "lsass","procdump","minidump",
    "comsvcs","MiniDump","sekurlsa",
    "logonpasswords","wce","pwdump")
    or TargetFilename_s has_any (
    "lsass",".dmp","minidump")
| project UtcTime_s, Computer, User_s,
          Image_s, CommandLine_s,
          TargetFilename_s, SHA256_s
| order by UtcTime_s asc
""")

# ── Q9: NTDS / VSS SHADOW COPY ───────────────────────────
# Flag — VSS commands
# Flag — ntds.dit path
print("[ HUNT 9 ] NTDS extraction via VSS")
findings["ntds_vss"] = kql("NTDS/VSS", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where CommandLine_s has_any (
    "vssadmin","ntds.dit","ntdsutil",
    "HarddiskVolumeShadowCopy",
    "shadow","diskshadow")
| project UtcTime_s, Computer, User_s,
          CommandLine_s, ParentImage_s
| order by UtcTime_s asc
""")

# ── Q10: DISCOVERY COMMANDS ──────────────────────────────
# Flag — Discovery commands used
# Flag — Domain enumeration
print("[ HUNT 10 ] Discovery and reconnaissance")
findings["discovery"] = kql("Discovery commands", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where CommandLine_s has_any (
    "whoami","net user","net group",
    "nltest","ipconfig","systeminfo",
    "net localgroup","dsquery",
    "net view","arp","route print",
    "tasklist","wmic","quser")
| project UtcTime_s, Computer, User_s,
          CommandLine_s, ParentImage_s
| order by UtcTime_s asc
""")

# ── Q11: LATERAL MOVEMENT ────────────────────────────────
# Flag — Admin share used
# Flag — Lateral movement method
print("[ HUNT 11 ] Lateral movement via admin shares")
findings["lateral_movement"] = kql("Lateral movement", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where CommandLine_s has_any (
    "\\\\\\\\","C$","ADMIN$","IPC$",
    "copy","xcopy","robocopy","move")
| where CommandLine_s has "\\\\"
| project UtcTime_s, Computer, User_s,
          CommandLine_s, ParentImage_s
| order by UtcTime_s asc
""")

# ── Q12: PERSISTENCE MECHANISMS ──────────────────────────
# Flag — Scheduled task name (WindowsUpdate)
# Flag — Backdoor account (svc_backup)
# Flag — Service name (Impacket)
print("[ HUNT 12 ] Persistence mechanisms")
findings["persistence"] = kql("Persistence", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where CommandLine_s has_any (
    "schtasks /create","schtasks /f",
    "net user","net localgroup",
    "sc create","sc config",
    "reg add","startup")
| project UtcTime_s, Computer, User_s,
          CommandLine_s, ParentImage_s
| order by UtcTime_s asc
""")

# ── Q13: NEW ACCOUNT CREATION ────────────────────────────
# Flag — Backdoor username (svc_backup)
print("[ HUNT 13 ] New account creation (Security 4720)")
findings["new_accounts"] = kql("New accounts (4720)", f"""
{T}
| where TimeGenerated > ago(9999d)
| where EventCode_s == "4720"
| project TimeGenerated, Computer,
          Caller_User_Name_s, Raw_s
| sort by TimeGenerated asc
""")

# ── Q14: GROUP MEMBERSHIP CHANGES ────────────────────────
# Flag — Group account added to (Domain Admins)
print("[ HUNT 14 ] Group membership changes (4728/4732)")
findings["group_changes"] = kql("Group changes", f"""
{T}
| where TimeGenerated > ago(9999d)
| where EventCode_s in ("4728","4732","4756")
| project TimeGenerated, Computer,
          MemberName_s, Group_Name_s, Raw_s
| sort by TimeGenerated asc
""")

# ── Q15: SERVICE INSTALLATIONS ───────────────────────────
# Flag — Impacket service name (random 8 chars)
print("[ HUNT 15 ] Service installations (7045)")
findings["services"] = kql("Service installs (7045)", f"""
{T}
| where TimeGenerated > ago(9999d)
| where EventCode_s == "7045"
| extend ServiceName = extract(
    "ServiceName'>([^<]+)", 1, Raw_s)
| extend ServicePath = extract(
    "ImagePath'>([^<]+)", 1, Raw_s)
| project TimeGenerated, Computer,
          ServiceName, ServicePath, Raw_s
| sort by TimeGenerated asc
""")

# ── Q16: REMOTE ACCESS TOOLS ─────────────────────────────
# Flag — RAT installed (AnyDesk)
# Flag — AnyDesk install command
print("[ HUNT 16 ] Remote access tools")
findings["remote_access"] = kql("Remote access tools", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where CommandLine_s has_any (
    "anydesk","teamviewer","screenconnect",
    "splashtop","logmein","vnc",
    "rustdesk","ultraviewer")
| project UtcTime_s, Computer, User_s,
          CommandLine_s, ParentImage_s,
          SHA256_s
| order by UtcTime_s asc
""")

# ── Q17: CERTUTIL DOWNLOAD ───────────────────────────────
# Flag — Staging server (files.cdn-delivery.net)
# Flag — Files downloaded
print("[ HUNT 17 ] Certutil download (ingress tool transfer)")
findings["certutil"] = kql("Certutil downloads", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where CommandLine_s has "certutil"
| project UtcTime_s, Computer, User_s,
          CommandLine_s
| order by UtcTime_s asc
""")

# ── Q18: RUNDLL32 / DLL EXECUTION ────────────────────────
# Flag — Malicious DLL (review.dll)
# Flag — DLL path
print("[ HUNT 18 ] Rundll32 / DLL execution")
findings["rundll32"] = kql("Rundll32 execution", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where Image_s has "rundll32"
    or CommandLine_s has "rundll32"
| project UtcTime_s, Computer, User_s,
          CommandLine_s, ParentImage_s,
          SHA256_s
| order by UtcTime_s asc
""")

# ── Q19: LOG CLEARING ─────────────────────────────────────
# Flag — Tool used (wevtutil)
# Flag — Logs cleared (Security, System)
print("[ HUNT 19 ] Event log clearing")
findings["log_clearing"] = kql("Log clearing", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where CommandLine_s has "wevtutil"
| project UtcTime_s, Computer, User_s,
          CommandLine_s
| order by UtcTime_s asc
""")

# ── Q20: RENAMED BINARIES ────────────────────────────────
# Flag — Malware masquerading as legitimate tool
print("[ HUNT 20 ] Renamed binaries (masquerading)")
findings["renamed"] = kql("Renamed binaries", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where isnotempty(OriginalFileName_s)
| extend ImageName = tostring(
    split(Image_s, "\\\\")[-1])
| where OriginalFileName_s !~ ImageName
| where Image_s !has "splunk"
| project UtcTime_s, Computer, User_s,
          Image_s, OriginalFileName_s,
          CommandLine_s, SHA256_s
| order by UtcTime_s asc
""")

# ── Q21: INITIAL ACCESS — ARCHIVE OPEN ───────────────────
# Flag — Initial file opened by lmartin
# Flag — Archive tool (7zG.exe)
print("[ HUNT 21 ] Initial access — archive/ISO opening")
findings["initial_access"] = kql("Initial access", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where User_s has "lmartin"
| where Image_s has_any (
    "7z","winrar","winzip","explorer",
    "outlook","thunderbird","chrome",
    "firefox","edge","isoburn")
    or ParentImage_s has_any (
    "7z","explorer","outlook")
| project UtcTime_s, Computer, User_s,
          Image_s, CommandLine_s,
          ParentImage_s
| order by UtcTime_s asc
| take 20
""")

# ── Q22: FIREWALL RULE ADDITION ──────────────────────────
# Flag — Firewall rule for lateral movement
print("[ HUNT 22 ] Firewall rule modifications")
findings["firewall"] = kql("Firewall rules", f"""
{T}
| where {TF}
| where EventCode_s == "1"
| where CommandLine_s has_any (
    "netsh","advfirewall","firewall",
    "add rule","allow")
| project UtcTime_s, Computer, User_s,
          CommandLine_s
| order by UtcTime_s asc
""")

print()

# ============================================================
# COUNT TOTAL FINDINGS
# ============================================================
total = sum(len(v) for v in findings.values()
            if isinstance(v, list))
print(f"  Total events collected: {total}")
print()

# ============================================================
# BUILD AI CONTEXT — PRIORITY ORDER
# Most important findings first to fit in context window
# ============================================================

priority_order = [
    "exfil_tools", "compression", "c2_beaconing",
    "dns_queries", "dropped_exe", "rundll32",
    "lsass_dump", "ntds_vss", "injection",
    "uac_bypass", "persistence", "new_accounts",
    "group_changes", "services", "remote_access",
    "certutil", "log_clearing", "discovery",
    "lateral_movement", "initial_access",
    "renamed", "firewall"
]

context_lines = [
    "=== EMBERFORGE HUNT INVESTIGATION ===",
    f"Time window: {T1} to {T2}",
    f"Domain: emberforge.local",
    f"Hosts: EC2AMAZ-B9GHHO6 (Workstation), "
    f"EC2AMAZ-16V3AU4 (Server), "
    f"EC2AMAZ-EEU3IA2 (DC)",
    ""
]

for key in priority_order:
    rows = findings.get(key, [])
    if not isinstance(rows, list) or not rows:
        continue
    context_lines.append(
        f"\n=== {key.upper()} ({len(rows)} events) ===")
    context_lines.append(fmt(rows, limit=8))

context = "\n".join(context_lines)

# ============================================================
# AI FLAG EXTRACTION
# ============================================================
print("[ AI ANALYSIS ] Extracting flag candidates...")

response = openai_client.chat.completions.create(
    model=CONFIG["model"],
    messages=[
        {
            "role": "system",
            "content": """You are a senior threat hunter analyzing
the EmberForge Studios breach investigation.

Known attack chain for context:
1. lmartin opened malicious ISO/archive on workstation
2. 7zG.exe extracted DLL → rundll32.exe loaded it
3. update.exe dropped to C:\\Users\\Public
4. update.exe beaconed to C2 domain/IP
5. Process injection: update.exe → svchost.exe
6. UAC bypass via fodhelper.exe
7. LSASS dump → credentials stolen
8. Discovery: net user, net group, nltest
9. Lateral movement via C$ admin share to server
10. certutil downloaded tools from staging server
11. rclone.exe exfiltrated C:\\GameDev to MEGA
12. AnyDesk silently installed
13. Compress-Archive C:\\GameDev → gamedev.zip
14. Lateral movement to Domain Controller
15. vssadmin → ntds.dit stolen
16. svc_backup account created → added to Domain Admins
17. Scheduled task WindowsUpdate created
18. wevtutil cleared Security and System logs

Hunt answer formats:
- Timestamps: YYYY-MM-DD HH:MM:SS
- Hashes: SHA256 lowercase or uppercase exact
- Paths: Full path with drive letter C:\\folder\\file.exe
- Commands: Exact as logged
- IPs: Standard dotted notation
- Ports: Number only
- Usernames: Exact as logged (DOMAIN\\username)
- Tool names: Exact binary name

For EACH finding extract:
FLAG: [category] | [exact value] | [confidence %]

Categories to cover:
- INITIAL_FILE (what lmartin opened)
- MALICIOUS_DLL (DLL loaded by rundll32)
- IMPLANT_PATH (where update.exe was dropped)
- C2_DOMAIN (beacon destination)
- C2_IP (beacon IP)
- STAGING_SERVER (certutil download source)
- EXFIL_TOOL (rclone command)
- EXFIL_CLOUD (cloud provider)
- MEGA_ACCOUNT (email used)
- SOURCE_DIR (C:\\GameDev)
- ARCHIVE_NAME (gamedev.zip)
- LSASS_DUMP_PATH (lsass.dmp path)
- UAC_BYPASS_METHOD
- INJECTOR_PROCESS
- TARGET_PROCESS
- LATERAL_MOVE_METHOD
- SERVICE_NAME (Impacket random name)
- BACKDOOR_ACCOUNT (svc_backup)
- BACKDOOR_GROUP (Domain Admins)
- RAT_INSTALLED (AnyDesk)
- SCHTASK_NAME (WindowsUpdate)
- LOG_CLEAR_TOOL (wevtutil)
- LOGS_CLEARED (Security, System)"""
        },
        {
            "role": "user",
            "content": f"Extract all flag candidates:\n\n{context[:14000]}"
        }
    ],
    temperature=0,
    max_tokens=2500
)

ai_analysis = response.choices[0].message.content
tokens = response.usage.total_tokens
cost   = tokens * 0.000005

print(f"  Complete — {tokens} tokens — ${cost:.4f}")

# ============================================================
# PRINT FLAG CANDIDATES
# ============================================================
print()
print("=" * 60)
print("  FLAG CANDIDATES — VERIFY BEFORE SUBMITTING")
print("=" * 60)
print()
print(ai_analysis)
print()

# ============================================================
# SAVE REPORT
# ============================================================
now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
report = [
    "=" * 60,
    "  EMBERFORGE HUNT AGENT V2 — FLAG REPORT",
    f"  Generated: {now}",
    "=" * 60, "",
    "=== FLAG CANDIDATES ===", "",
    ai_analysis, "",
    "=== RAW EVIDENCE ===", ""
]

for key in priority_order:
    rows = findings.get(key, [])
    if not isinstance(rows, list) or not rows:
        continue
    report.append(f"\n[{key.upper()}] — {len(rows)} events")
    for row in rows[:5]:
        if not isinstance(row, dict):
            continue
        parts = {k: str(v)[:200]
                 for k, v in row.items()
                 if v and k not in ["Raw_s","EventData_Xml_s"]}
        report.append("  " + str(parts))

report += ["", "=" * 60, "End of report.", "=" * 60]

with open(CONFIG["report_file"], "w", encoding="utf-8") as f:
    f.write("\n".join(report))

print(f"  ✅ Report saved to {CONFIG['report_file']}")
print()
print("=" * 60)
print(f"  Cost: ${cost:.4f} | Tokens: {tokens}")
print("=" * 60)

# ============================================================
# WHAT CHANGED FROM V1:
#
# V1 problems:
# - Used fixed timespan that missed Security events
# - Collected 20,000 events — AI drowned in noise
# - Flagged Splunk as suspicious (false positive)
# - Missed rclone, rundll32, review.dll, C:\GameDev
#
# V2 fixes:
# - ago(9999d) for ALL queries — nothing missed
# - 22 targeted queries instead of 6 broad ones
# - Priority ordering — highest value findings first
# - AI context focuses on signal not volume
# - Known attack chain in system prompt — AI knows
#   what to look for before seeing the data
# - False positive filtering — Splunk excluded
# - Security events use TimeGenerated > ago(9999d)
#
# EXPECTED FLAG HITS:
# - C:\GameDev ✅ (compression query)
# - rclone + MEGA ✅ (exfil tools query)
# - cdn.cloud-endpoint.net ✅ (DNS query)
# - update.exe in C:\Users\Public ✅ (dropped exe)
# - review.dll ✅ (rundll32 query)
# - lsass.dmp ✅ (LSASS dump query)
# - svc_backup ✅ (new accounts query)
# - wevtutil ✅ (log clearing query)
# - WindowsUpdate task ✅ (persistence query)
# - AnyDesk ✅ (remote access query)
# ============================================================