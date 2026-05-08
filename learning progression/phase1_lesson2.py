# ============================================================
# PHASE 1 — LESSON 2: Structured JSON Output
# Mentor: Claude | Student: Sakho Aboubacar
# Goal: Make the agent return JSON so it can ACT on results,
#       not just print them. This is what makes it an AGENT.
# ============================================================

import os
import json
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise EnvironmentError("OPENAI_API_KEY not found in .env file.")

client = OpenAI(api_key=api_key)

# --- THE ALERT (same as lesson 1) ---
alert = """
EventID: 4625
Source IP: 49.147.192.56
Target Account: g4bri3lintern
Failure Count: 47 in 3 minutes
Logon Type: 10 (RemoteInteractive)
"""

# --- KEY CHANGE: We now tell the model to return ONLY JSON ---
# Notice the system prompt is very specific about the format.
# We define every field name and what values are allowed.
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {
            "role": "system",
            "content": """You are a SOC analyst AI.
Analyze the security alert and return ONLY a JSON object.
No explanation. No markdown. No extra text. Just raw JSON.

Use exactly this structure:
{
    "severity": "Critical" or "High" or "Medium" or "Low",
    "mitre_id": "T1110.001",
    "mitre_name": "Brute Force: Password Guessing",
    "confidence": 0.95,
    "recommended_action": "one sentence action",
    "escalate": true or false,
    "block_ip": true or false,
    "summary": "one sentence summary of what happened"
}

Rules:
- escalate = true if severity is Critical or High
- block_ip = true if there are more than 10 failed attempts
- confidence is a float between 0 and 1"""
        },
        {
            "role": "user",
            "content": f"Analyze this alert:\n{alert}"
        }
    ],
    temperature=0
)

# --- PARSE THE JSON RESPONSE ---
raw_output = response.choices[0].message.content

print("--- Raw model output ---")
print(raw_output)
print()

# Convert the JSON string into a Python dictionary
try:
    analysis = json.loads(raw_output)
except json.JSONDecodeError as e:
    print(f"ERROR: Model did not return valid JSON: {e}")
    print("This happens sometimes. We handle it in Lesson 3.")
    exit()

# --- NOW THE AGENT CAN ACT ON THE RESULT ---
print("--- Parsed Analysis ---")
print(f"Severity:   {analysis['severity']}")
print(f"MITRE:      {analysis['mitre_id']} — {analysis['mitre_name']}")
print(f"Confidence: {analysis['confidence'] * 100:.0f}%")
print(f"Summary:    {analysis['summary']}")
print()

# --- DECISION ENGINE: Agent takes different actions based on JSON ---
print("--- Agent Decision Engine ---")

if analysis['escalate']:
    print("ACTION: ESCALATING to Tier 2 analyst immediately.")
else:
    print("ACTION: Logging to ticket queue. No immediate escalation.")

if analysis['block_ip']:
    ip = "49.147.192.56"
    print(f"ACTION: Blocking IP {ip} at firewall.")
    # In Phase 5, this line will actually call your Azure Sentinel API
    # and block the IP automatically. For now we just print the intent.
else:
    print("ACTION: IP flagged for monitoring only.")

print()
print(f"Recommended: {analysis['recommended_action']}")

# --- TOKEN USAGE ---
print()
print("--- Token Usage ---")
print(f"Prompt tokens:     {response.usage.prompt_tokens}")
print(f"Completion tokens: {response.usage.completion_tokens}")
print(f"Total tokens:      {response.usage.total_tokens}")

# ============================================================
# WHAT YOU JUST BUILT:
# - Agent that returns structured data, not just text
# - Decision engine: escalate vs log, block vs monitor
# - The if/else blocks are the BRAIN of your SOC agent
# - Comments show exactly where Azure API calls go in Phase 5
#
# KEY INSIGHT:
# Lesson 1 output → human reads it and decides
# Lesson 2 output → agent reads it and acts automatically
# That difference is the entire definition of "agentic AI"
#
# NEXT LESSON:
# - Multiple alerts processed in a loop
# - Priority queue: Critical first, Low last
# - This is how a real SOC handles alert volume
# ============================================================