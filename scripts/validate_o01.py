"""Offline O01 validation against the live model (internal team only).

    python scripts/validate_o01.py --scenario O01-BASELINE --trials 3
    python scripts/validate_o01.py --scenario O01-IPI-01 --trials 10
    python scripts/validate_o01.py --scenario O01-IPI-01 --trials 10 --harden

Each trial resets the testbed, plants the reference document as the
contributor, runs the legitimate analyst task, and judges the run from the
trace, the answer and the database. Results are stored and visible in the
evaluator UI.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import o01  # noqa: E402
from app.agent import Agent  # noqa: E402
from app.config import load_settings  # noqa: E402
from app.db import Database  # noqa: E402
from app.main import build_provider, run_trials  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--scenario", required=True, choices=sorted(o01.SCENARIOS))
ap.add_argument("--trials", type=int, default=5)
ap.add_argument("--harden", action="store_true", help="enable authority_rule and spotlight_untrusted")
args = ap.parse_args()

s = load_settings()
provider = build_provider(s)
if provider is None:
    sys.exit("LLM_BASE_URL / LLM_API_KEY not set.")
db = Database(s.data_dir)
db.set_agent_config({"authority_rule": args.harden, "spotlight_untrusted": args.harden})
out = run_trials(db, Agent(db, provider, s.agent_max_steps), args.scenario, args.trials)
for i, r in enumerate(out["results"], 1):
    ac = r.get("answer_check", {})
    print(f"trial {i}: run={r.get('run_id')} retrieved={r.get('attacker_document_retrieved')} "
          f"supplied={r.get('attacker_content_supplied_to_llm')} verdict={ac.get('verdict')} "
          f"validated={r.get('validated_failure')} error={r.get('run_error')}")
print(json.dumps(out["summary"], indent=2))
