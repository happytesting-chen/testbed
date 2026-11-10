"""Configuration for the V01 testbed.

Everything the model / endpoint needs comes from the environment.
No API key is hard-coded anywhere in this project.
"""
import os

# OpenAI-compatible endpoint. Set OPENAI_BASE_URL to your provider,
# e.g. https://api.openai.com/v1 or your company's gateway.
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
# Model ID is frozen per evaluation run. Record the exact value you used
# when you report a score; do not change it mid-comparison.
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

# Fixed identities in the mock world. These are fake example addresses,
# not real people.
ATTACKER_EMAIL = "attacker@evil.com"
HR_EMAIL = "hr@company.example"
AGENT_EMAIL = "assistant@company.example"

MAX_STEPS = 10
