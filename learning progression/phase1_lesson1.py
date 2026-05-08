# ============================================================
# PHASE 1 — LESSON 1: API Key Safety & Environment Variables
# Mentor: Claude | Student: Sakho Aboubacar
# Goal: Never hardcode secrets. Load them from the environment.
# ============================================================

# --- STEP 1: Install required library (run once in terminal) ---
# pip install openai python-dotenv

# --- STEP 2: Create a .env file in the same folder ---
# Contents of your .env file (do NOT commit this to GitHub):
#
#   OPENAI_API_KEY=sk-proj-your-real-key-here
#
# Then add .env to your .gitignore:
#   echo ".env" >> .gitignore

import os
from dotenv import load_dotenv
from openai import OpenAI

# Load all variables from .env into the environment
load_dotenv()

# Pull the key from the environment — never from the code
api_key = os.getenv("OPENAI_API_KEY")

# Safety check — always validate before proceeding
if not api_key:
    raise EnvironmentError(
        "OPENAI_API_KEY not found. "
        "Did you create a .env file with the key inside?"
    )

print(f"Key loaded successfully. Starts with: {api_key[:8]}...")

# --- STEP 3: Initialize the client ---
client = OpenAI(api_key=api_key)

# --- STEP 4: Your first API call — a simple SOC use case ---
# We ask the model to classify an alert. This is the foundation
# of every SOC agent you will build.

alert = """
EventID: 4625
Source IP: 49.147.192.56
Target Account: g4bri3lintern
Failure Count: 47 in 3 minutes
Logon Type: 10 (RemoteInteractive)
"""

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {
            "role": "system",
            "content": (
                "You are a SOC analyst AI. "
                "Analyze the security alert and return: "
                "1) Severity (Critical/High/Medium/Low) "
                "2) MITRE technique "
                "3) Recommended action in one sentence."
            )
        },
        {
            "role": "user",
            "content": f"Analyze this alert:\n{alert}"
        }
    ],
    temperature=0   # Always use 0 for security analysis — no creativity needed
)

# --- STEP 5: Parse and print the result ---
result = response.choices[0].message.content
print("\n--- AI SOC Analysis ---")
print(result)
print("\n--- Token Usage ---")
print(f"Prompt tokens:     {response.usage.prompt_tokens}")
print(f"Completion tokens: {response.usage.completion_tokens}")
print(f"Total tokens:      {response.usage.total_tokens}")

# ============================================================
# WHAT YOU JUST BUILT:
# - Secure key loading from environment (production pattern)
# - Your first LLM API call
# - A real SOC use case: alert triage
# - Token tracking (critical for production cost management)
#
# NEXT LESSON:
# - Structured JSON output from the model
# - So your agent can ACT on the result, not just print it
# ============================================================