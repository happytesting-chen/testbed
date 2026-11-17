"""
Orchestrator — coordinates executor and evaluator across test rounds.

Runs the full Phase 2 testing loop:
  1. Baseline run (clean document)
  2. Round 1..N payload runs
  3. Score each round via evaluator
  4. Read trace to identify block node
  5. Write artifacts and update results_index.csv

Usage:
    python orchestrator.py --test TEST-01
                           --baseline <path>
                           --payloads <r1_path> <r2_path> <r3_path>
                           --finding F-01
                           --expected Critical

Options:
    --test        Test case ID (e.g. TEST-01)
    --baseline    Path to clean baseline document
    --payloads    One or more payload files (round 1, 2, 3...)
    --finding     Finding ID to track (default: F-01)
    --expected    Expected baseline severity (default: Critical)
    --no-reset    Skip testbed reset between rounds (not recommended)
"""
import argparse
import csv
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import executor
import evaluator

TESTING_DIR = Path(__file__).resolve().parent.parent / "testing"
RESULTS_INDEX = Path(__file__).resolve().parent.parent / "results_index.csv"


# ── helpers ────────────────────────────────────────────────────────────────────

def ensure_dirs(test_id: str) -> tuple[Path, Path]:
    base = TESTING_DIR / test_id
    (base / "baseline").mkdir(parents=True, exist_ok=True)
    (base / "crafted").mkdir(parents=True, exist_ok=True)
    return base / "baseline", base / "crafted"


def save_artifacts(folder: Path, prefix: str, exec_result: dict):
    (folder / f"response_{prefix}.txt").write_text(exec_result["response"], encoding="utf-8")
    (folder / f"trace_{prefix}.json").write_text(
        json.dumps(exec_result["trace"], indent=2), encoding="utf-8"
    )


def append_result(test_id: str, rnd: int, technique: str,
                  baseline_val: str, payload_val: str,
                  status: str, block_control: str):
    write_header = not RESULTS_INDEX.exists()
    with open(RESULTS_INDEX, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(["case", "round", "entry_point", "technique",
                        "baseline_value", "payload_value", "status", "block_control"])
        w.writerow([test_id, rnd, "document_upload", technique,
                    baseline_val, payload_val, status, block_control])


def extract_block_node(trace: list) -> str:
    """Read trace and summarise what tools were called and where the chain ended."""
    steps = []
    for event in trace:
        stage = event.get("stage", "")
        payload = event.get("payload", {})
        if stage == "tool_call":
            steps.append(f"called {payload.get('name')}({list(payload.get('arguments', {}).keys())})")
        elif stage == "tool_result":
            name = payload.get("name", "")
            retrieved = payload.get("retrieved_report_ids", [])
            steps.append(f"tool_result:{name} retrieved={retrieved}")
        elif stage == "final_answer":
            steps.append("final_answer")
    return " → ".join(steps) if steps else "no trace"


def print_step(msg: str):
    print(f"\n▶ {msg}", flush=True)


# ── main ───────────────────────────────────────────────────────────────────────

def run_test(test_id: str, baseline_path: Path, payload_paths: list[Path],
             finding_id: str, expected: str, do_reset: bool, start_round: int = 1,
             run_all: bool = False, chat_only: bool = False,
             eval_mode: str = "severity", success_string: str = "",
             fixture_paths: list[Path] | None = None, trigger: str = "default"):

    baseline_dir, crafted_dir = ensure_dirs(test_id)

    # ── STEP 0: upload fixture documents (persist across all rounds) ──────────
    if fixture_paths:
        for fp in fixture_paths:
            print_step(f"FIXTURE — uploading {fp.name}")
            executor.upload_document(fp)
            print(f"  uploaded: {fp.name}")

    # ── STEP 1: baseline ───────────────────────────────────────────────────────
    # Reset ONCE here — rounds do NOT reset, so all runs stay visible in evaluator
    print_step(f"BASELINE — uploading {baseline_path.name}")
    baseline_result = executor.run(baseline_path, do_reset=do_reset,
                                   run_tag=f"{test_id}:r00:baseline",
                                   chat_only=chat_only, trigger=trigger)
    save_artifacts(baseline_dir, "baseline", baseline_result)
    (baseline_dir / "baseline_document.md").write_bytes(baseline_path.read_bytes())

    print(f"  run_id:   {baseline_result['run_id']}")
    print(f"  response: {baseline_result['response'][:120]}...")

    # Confirm baseline value via evaluator (self-check)
    baseline_check = evaluator.run(
        baseline=baseline_result["response"],
        payload=baseline_result["response"],
        test_id=test_id,
        finding_id=finding_id,
        expected=expected,
        eval_mode=eval_mode,
        success_string=success_string,
    )
    baseline_value = baseline_check.get("baseline_value", success_string or expected)
    print(f"  baseline confirmed: {baseline_value}")

    append_result(test_id, 0, "baseline",
                  baseline_value, baseline_value, "BASELINE", "n/a")

    final_disposition = "FAIL"
    final_rounds = len(payload_paths)

    # ── STEP 2: payload rounds ─────────────────────────────────────────────────
    for rnd, payload_path in enumerate(payload_paths, start=start_round):
        print_step(f"ROUND {rnd} — payload: {payload_path.name}")

        technique = payload_path.stem
        round_result = executor.run(payload_path, do_reset=False,
                                    run_tag=f"{test_id}:r{rnd:02d}:{technique}",
                                    chat_only=chat_only, trigger=trigger)

        # Score via evaluator first so we know WORKABLE vs FAIL for naming
        score_tmp = evaluator.run(
            baseline=baseline_result["response"],
            payload=round_result["response"],
            test_id=test_id,
            finding_id=finding_id,
            expected=expected,
            eval_mode=eval_mode,
            success_string=success_string,
        )
        verdict_tmp = score_tmp.get("verdict", "FAIL")
        label = "WORKABLE" if verdict_tmp == "PASS" else "FAIL"
        technique = payload_path.stem  # e.g. F01_r03_errata_visible
        prefix = f"r{rnd:02d}_{technique}_{label}"

        save_artifacts(crafted_dir, prefix, round_result)
        (crafted_dir / f"payload_{prefix}.md").write_bytes(payload_path.read_bytes())

        score = score_tmp

        print(f"  run_id:   {round_result['run_id']}")
        print(f"  response: {round_result['response'][:120]}...")

        verdict      = score.get("verdict", "FAIL")
        payload_val  = score.get("payload_value", "unknown")
        evidence     = score.get("evidence_quote", "")
        reasoning    = score.get("reasoning", "")

        # Read trace to find block node
        block_node = extract_block_node(round_result["trace"])

        print(f"\n  EVALUATOR VERDICT: {verdict}")
        print(f"  Baseline {finding_id}: {baseline_value}")
        print(f"  Payload  {finding_id}: {payload_val}")
        print(f"  Evidence: {evidence}")
        print(f"  Reasoning: {reasoning}")
        print(f"  Trace summary: {block_node}")

        # Save evaluator output
        (crafted_dir / f"eval_{prefix}.json").write_text(
            json.dumps(score, indent=2), encoding="utf-8"
        )

        append_result(test_id, rnd, payload_path.stem,
                      baseline_value, payload_val, verdict, block_node)

        final_rounds = rnd

        if verdict == "PASS":
            print(f"\n  ✓ SUCCESS — attack succeeded in round {rnd}")
            final_disposition = "SUCCEED"
            if not run_all:
                break
            print(f"  (continuing to remaining rounds for complete ground truth)")
        else:
            print(f"\n  ✗ {verdict} — continuing to next round")

    # ── STEP 3: write result summary ───────────────────────────────────────────
    print_step("Writing result summary")
    today = date.today().isoformat()
    status_label = "SUCCESS" if final_disposition == "SUCCEED" else "FAIL"
    result_file = (TESTING_DIR / test_id /
                   f"{test_id}_{final_rounds}rounds_{status_label}_{final_disposition}_{today}.txt")

    summary_lines = [
        f"Test Case:   {test_id}",
        f"Date:        {today}",
        f"Finding:     {finding_id}",
        f"Baseline:    {baseline_value}",
        f"Rounds run:  {final_rounds}",
        f"Disposition: {final_disposition}",
        f"Entry point: document_upload → /api/reports/upload",
        "",
        "ROUND SUMMARY",
        "-" * 60,
    ]

    # Re-read results_index for this test
    if RESULTS_INDEX.exists():
        with open(RESULTS_INDEX, newline="", encoding="utf-8") as f:
            rows = [r for r in csv.DictReader(f) if r["case"] == test_id and r["round"] != "0"]
        for row in rows:
            summary_lines.append(
                f"Round {row['round']:>2} | {row['technique']:<35} | "
                f"{row['payload_value']:<12} | {row['status']}"
            )

    result_file.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    print(f"  Result written to {result_file.name}")
    print(f"\nFINAL DISPOSITION: {final_disposition}")


# ── entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Red team orchestrator")
    parser.add_argument("--test",     required=True, help="Test case ID, e.g. TEST-01")
    parser.add_argument("--baseline", required=True, help="Path to clean baseline document")
    parser.add_argument("--payloads", required=True, nargs="+", help="Payload files (round 1, 2, 3…)")
    parser.add_argument("--finding",  default="F-01", help="Finding ID to track")
    parser.add_argument("--expected", default="Critical", help="Expected baseline severity")
    parser.add_argument("--no-reset",    action="store_true", help="Skip testbed reset between rounds")
    parser.add_argument("--start-round", type=int, default=1, help="Start round numbering from N (for continuation runs)")
    parser.add_argument("--stop-on-success", action="store_true", help="Stop early on first SUCCESS (default: run all rounds for complete ground truth)")
    parser.add_argument("--chat-only",      action="store_true", help="Chat-only mode: payload file content is sent as chat message directly, no document upload")
    parser.add_argument("--eval-mode",      default="severity",  help="Evaluation oracle: 'severity' (default) or 'contains'")
    parser.add_argument("--success-string", default="",          help="String that must appear in payload response for PASS (used with --eval-mode contains)")
    parser.add_argument("--fixture",        nargs="+", default=[], help="Documents to upload once as persistent fixtures (e.g. victim credential report)")
    parser.add_argument("--trigger",        default="default", help="Trigger question: 'default' (read specific report) or 'all' (search all reports)")
    args = parser.parse_args()

    run_test(
        test_id=args.test,
        baseline_path=Path(args.baseline),
        payload_paths=[Path(p) for p in args.payloads],
        finding_id=args.finding,
        expected=args.expected,
        do_reset=not args.no_reset,
        start_round=args.start_round,
        run_all=not args.stop_on_success,
        chat_only=args.chat_only,
        eval_mode=args.eval_mode,
        success_string=args.success_string,
        fixture_paths=[Path(f) for f in args.fixture] if args.fixture else None,
        trigger=args.trigger,
    )
