"""
Reviewer Agent — Verifies UI changes in index.html and evaluator.html

Catches the specific bugs that have recurred in this project:
1. Variable used before definition (or defined locally, used globally)
2. DOM element referenced that no longer exists
3. Duplicate const declarations
4. data-atk / data-multiturn buttons with no matching JS handler
5. TEST pattern arrays missing from detectTest()
6. TEST_OBJECTIVES missing entries for registered tests

Run after any change to either HTML file:
    python red_teaming_internal/scripts/reviewer.py

Returns exit code 0 if clean, 1 if issues found.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
INDEX = ROOT / "app" / "static" / "index_internal.html"
EVAL  = ROOT / "app" / "static" / "evaluator.html"

ISSUES = []

def issue(file: str, msg: str):
    ISSUES.append(f"  [{file}] {msg}")

def extract_js(html: str) -> str:
    """Extract all JavaScript from <script> tags."""
    return "\n".join(re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL))

def check_undefined_vars(js: str, file: str):
    """Check for variables used but never defined at any scope level."""
    # Find all const/let/var/function declarations
    declared = set()
    for m in re.finditer(r'\b(?:const|let|var)\s+([A-Z_][A-Z0-9_]*)\b', js):
        declared.add(m.group(1))
    for m in re.finditer(r'\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', js):
        declared.add(m.group(1))

    # Known globals (browser + our codebase)
    browser_globals = {
        'document','window','console','fetch','JSON','Math','Array','Object',
        'String','Number','Boolean','Promise','setTimeout','clearTimeout',
        'parseInt','parseFloat','encodeURIComponent','decodeURIComponent',
        'HTMLElement','Event','FormData','URL','URLSearchParams',
    }

    # Check for specific known-risky variables we've had bugs with
    risky = ['TEST03_SECRETS','TEST03_PROMPTS','TEST02_SUCCESS_STRINGS',
             'TEST03_S1_PROMPTS','TEST03_S2_PROMPTS','TEST02_PROMPTS',
             'TEST_OBJECTIVES','RECEIVER_URL','HYPERLINK_SECRET']
    for var in risky:
        uses = len(re.findall(rf'\b{var}\b', js))
        defs = len(re.findall(rf'\bconst\s+{var}\b|\blet\s+{var}\b|\bvar\s+{var}\b', js))
        if uses > 0 and defs == 0:
            issue(file, f"UNDEFINED: '{var}' used {uses}× but never declared (global scope needed)")
        if defs > 1:
            issue(file, f"DUPLICATE: '{var}' declared {defs}× — may shadow or conflict")

def check_dom_references(js: str, html: str, file: str):
    """Check that getElementById references match actual element IDs in the HTML."""
    # Elements referenced via $() or getElementById
    referenced = set(re.findall(r'\$\("([^"]+)"\)', js))
    referenced |= set(re.findall(r'getElementById\("([^"]+)"\)', js))

    # Elements actually in the HTML
    present = set(re.findall(r'\bid="([^"]+)"', html))

    missing = referenced - present
    for m in missing:
        # Skip dynamic IDs
        if any(c in m for c in ['+', '$', '{', ' ']):
            continue
        issue(file, f"MISSING DOM: $(\"{m}\") referenced but no element with id=\"{m}\" found")

def check_multiturn_class_conflict(html: str, js: str, file: str):
    """Check data-multiturn buttons with atk-btn class are dispatched correctly.

    Setting onclick twice means the second assignment wins. The correct fix is to
    dispatch from inside the generic handler, not register a separate handler.
    Guard pattern: if(b.dataset.multiturn==='X'){runX();return;}
    Separate-handler pattern (WRONG): querySelectorAll("[data-multiturn]").forEach(b=>b.onclick=...)
    followed by querySelectorAll(".atk-btn").forEach(b=>b.onclick=...) overwrites it.
    """
    multiturn_btns = re.findall(r'<button[^>]*data-multiturn="([^"]*)"[^>]*class="[^"]*atk-btn[^"]*"', html)
    multiturn_btns += re.findall(r'<button[^>]*class="[^"]*atk-btn[^"]*"[^>]*data-multiturn="([^"]*)"', html)
    for mt in multiturn_btns:
        # Correct: dispatched from inside .atk-btn handler
        dispatched = f"dataset.multiturn==='{mt}'" in js or f'dataset.multiturn==="{mt}"' in js
        # Wrong: separate handler that gets overwritten
        separate = f"data-multiturn='{mt}']" in js or f'data-multiturn="{mt}"]' in js
        if separate and not dispatched:
            issue(file, f"data-multiturn='{mt}' registered as separate onclick — will be overwritten by .atk-btn forEach. Use dispatch inside the .atk-btn handler instead.")


def check_onclick_handlers(js: str, html: str, file: str):
    """Check data-atk buttons have .atk-btn handler, data-multiturn have matching handler."""
    # data-atk buttons need querySelectorAll(".atk-btn") and data-atk reference in handler
    has_atk_buttons = 'data-atk=' in html
    has_atk_handler = 'querySelectorAll(".atk-btn")' in js or "querySelectorAll('.atk-btn')" in js
    if has_atk_buttons and not has_atk_handler:
        issue(file, "data-atk buttons present but querySelectorAll('.atk-btn') handler not found")

    # data-multiturn buttons need matching handler — either separate querySelectorAll OR dispatch inside .atk-btn
    multiturn_types = set(re.findall(r'data-multiturn="([^"]+)"', html))
    for mt in multiturn_types:
        separate = f"data-multiturn='{mt}'" in js or f'data-multiturn="{mt}"' in js
        dispatched = f"dataset.multiturn==='{mt}'" in js or f'dataset.multiturn==="{mt}"' in js
        if not separate and not dispatched:
            issue(file, f"data-multiturn=\"{mt}\" button has no matching JS handler (add dispatch inside .atk-btn forEach or a separate querySelectorAll)")

def check_test_registry(js: str, file: str):
    """Check TEST pattern arrays are registered in detectTest() and TEST_OBJECTIVES."""
    # Find all TEST_XX_PROMPTS arrays defined
    prompt_arrays = set(re.findall(r'\bconst\s+(TEST\d+[A-Z_]*PROMPTS)\b', js))

    # Check each is used in detectTest
    detect_fn = re.search(r'function detectTest.*?^}', js, re.DOTALL | re.MULTILINE)
    if detect_fn:
        detect_body = detect_fn.group(0)
        for arr in prompt_arrays:
            if arr not in detect_body:
                issue(file, f"'{arr}' defined but not used in detectTest() — test won't be detected")

    # Check TEST_OBJECTIVES has entries for all TEST-XX patterns
    objectives_match = re.search(r'const TEST_OBJECTIVES\s*=\s*\{([^}]+)\}', js)
    if objectives_match:
        obj_body = objectives_match.group(1)
        # Find all TEST-XX keys
        obj_keys = set(re.findall(r"'(TEST-\d+[^']*)'", obj_body))
        # Warn if TEST-03 exists but no stage split
        if 'TEST-03' in obj_keys and 'TEST-03-S1' not in obj_keys:
            issue(file, "TEST_OBJECTIVES has 'TEST-03' but Stage 1/2 split uses 'TEST-03-S1'/'TEST-03-S2' — objective may show wrong label")

def check_test03_in_reports_table(js: str, file: str):
    """Check TEST-03 rows are skipped in loadReports to avoid appearing under wrong group."""
    # Accept either grp.num===3 alone or grp.num===3||grp.num===4 combined
    has_t3_skip = ('grp.num === 3' in js or 'grp&&grp.num===3' in js or
                   'grp.num===3||grp.num===4' in js or 'grp.num===4' in js)
    if not has_t3_skip:
        if 'loadReports' in js and 'testGroup' in js:
            issue(file, "TEST-03 skip not found in loadReports() — TEST-03 files may appear under Test 1 header")

def check_evaluator_secrets(js: str, file: str):
    """Check TEST03_SECRETS is defined at global scope in evaluator."""
    if 'TEST03_SECRETS' in js:
        # Must be at global scope (not inside a function)
        # Simple heuristic: check if it's declared before any function definition
        global_match = re.search(r'^const TEST03_SECRETS\s*=', js, re.MULTILINE)
        if not global_match:
            # Check if inside a function
            fn_local = re.search(r'function.*?const TEST03_SECRETS', js, re.DOTALL)
            if fn_local:
                issue(file, "TEST03_SECRETS declared inside a function — will be undefined in showTrace(). Move to global scope.")

def run():
    print("Reviewer Agent — checking UI files\n")
    ok = True

    for path, label in [(INDEX, "index.html"), (EVAL, "evaluator.html")]:
        if not path.exists():
            issue(label, f"File not found: {path}")
            continue
        html = path.read_text(encoding="utf-8")
        js   = extract_js(html)

        check_undefined_vars(js, label)
        check_dom_references(js, html, label)
        check_multiturn_class_conflict(html, js, label)
        check_onclick_handlers(js, html, label)
        check_test_registry(js, label)
        check_test03_in_reports_table(js, label)
        check_evaluator_secrets(js, label)

    if ISSUES:
        print(f"Found {len(ISSUES)} issue(s):\n")
        for i in ISSUES:
            print(i)
        print()
        ok = False
    else:
        print("✓ All checks passed — no issues found.")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())
