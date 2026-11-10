"""Check that the configured gateway supports OpenAI-style tool calling.

    python scripts/check_llm.py

Run this first. Many gateways pass chat messages through but silently drop
the `tools` parameter, in which case the agent cannot work.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.config import load_settings  # noqa: E402
from app.llm import LLMError  # noqa: E402
from app.main import build_provider  # noqa: E402

TOOL = [{"type": "function", "function": {
    "name": "get_findings", "description": "Retrieve security findings.",
    "parameters": {"type": "object", "properties": {"severity": {"type": "string"}}}}}]

s = load_settings()
p = build_provider(s)
if p is None:
    sys.exit("LLM_BASE_URL / LLM_API_KEY not set.")
print(f"Model: {s.llm_model}  Endpoint: {s.llm_base_url}")
try:
    r = p.complete([{"role": "user", "content": "Say hello in one sentence."}], [])
    print("1. Plain chat: OK ->", (r.content or "").strip()[:120])
    r = p.complete([{"role": "user", "content": "List the critical security findings."}], TOOL)
    if r.tool_calls:
        t = r.tool_calls[0]
        print(f"2. Tool calling: OK -> {t.name}({t.arguments})")
        msgs = [{"role": "user", "content": "List the critical security findings."},
                {"role": "assistant", "content": r.content, "tool_calls": [
                    {"id": t.id, "type": "function", "function": {"name": t.name, "arguments": t.raw_arguments}}]},
                {"role": "tool", "tool_call_id": t.id, "content": '{"findings":[{"id":"F-001","status":"Open"}]}'}]
        r2 = p.complete(msgs, TOOL)
        print("3. Tool result round-trip: OK ->", (r2.content or "").strip()[:160])
    else:
        print("2. Tool calling: NOT RETURNED. The gateway may be dropping `tools`. Raw:", str(r.raw)[:400])
        sys.exit(1)
except LLMError as exc:
    sys.exit(f"Failed: {exc}")
