"""Risk analysis and residual risk assessment functions.

Generic — no application-specific dependencies.
"""
import copy
from typing import Any


EXPLOITATION_STATUSES = {"confirmed", "not_observed", "inconclusive", "not_tested"}
RESIDUAL_STATUSES = {
    "pending_implementation", "pending_verification", "pending_assessment",
    "assessed_reduced", "assessed_unchanged", "assessed_accepted",
    "assessed_transferred", "not_applicable",
}
DISPOSITION_STATUSES = {"open", "mitigated", "accepted", "transferred", "closed"}

RISK_MATRIX = {
    ("Unlikely", "Low"): "Low", ("Unlikely", "Medium"): "Low",
    ("Unlikely", "High"): "Medium", ("Unlikely", "Critical"): "High",
    ("Possible", "Low"): "Low", ("Possible", "Medium"): "Medium",
    ("Possible", "High"): "High", ("Possible", "Critical"): "High",
    ("Likely", "Low"): "Medium", ("Likely", "Medium"): "High",
    ("Likely", "High"): "High", ("Likely", "Critical"): "Critical",
    ("Almost certain", "Low"): "Medium", ("Almost certain", "Medium"): "High",
    ("Almost certain", "High"): "Critical", ("Almost certain", "Critical"): "Critical",
}


def analyze_risk(risk_entry: dict, test_results: list[dict]) -> dict:
    """Analyze a single risk against its test results.

    Args:
        risk_entry: one entry from the TRA risk_register
        test_results: list of red-team records for related scenarios

    Returns:
        dict with exploitation_status, contributing_evidence, and analysis
    """
    rid = risk_entry["risk_id"]

    if not test_results:
        return {
            "risk_id": rid,
            "exploitation_status": "not_tested",
            "contributing_evidence": [],
            "analysis": "No test results available for this risk.",
        }

    succeeded = [r for r in test_results if r.get("verdict") == "SUCCEEDED"]
    failed = [r for r in test_results if r.get("verdict") == "FAILED"]
    inconclusive = [r for r in test_results if r.get("verdict") == "INCONCLUSIVE"]

    if succeeded:
        status = "confirmed"
        analysis = (f"Exploitation confirmed in {len(succeeded)} of {len(test_results)} "
                    f"test attempts. First success: attempt {succeeded[0].get('attempt', '?')}.")
    elif inconclusive:
        status = "inconclusive"
        analysis = (f"No confirmed exploitation in {len(test_results)} attempts, "
                    f"but {len(inconclusive)} were inconclusive.")
    else:
        status = "not_observed"
        analysis = f"No exploitation observed in {len(test_results)} attempts."

    evidence = []
    for r in succeeded:
        evidence.append({
            "scenario_id": r.get("scenario_id"),
            "attempt": r.get("attempt"),
            "technique_id": r.get("technique_id"),
            "verdict": r.get("verdict"),
            "evidence": r.get("evidence", []),
        })

    return {
        "risk_id": rid,
        "exploitation_status": status,
        "contributing_evidence": evidence,
        "analysis": analysis,
    }


def assess_residual_risk(risk_entry: dict,
                         mitigations: list[dict],
                         retest_results: list[dict] | None = None,
                         risk_matrix: dict | None = None) -> dict:
    """Assess residual risk for a single Risk ID.

    Args:
        risk_entry: one TRA risk register entry
        mitigations: list of mitigation records for this risk
        retest_results: list of retest records (None if not retested)
        risk_matrix: optional override for the risk matrix

    Returns:
        dict with residual assessment fields
    """
    matrix = risk_matrix or RISK_MATRIX
    rid = risk_entry["risk_id"]

    implemented = [m for m in mitigations if m.get("status") == "implemented"]
    proposed = [m for m in mitigations if m.get("status") != "implemented"]

    if not mitigations:
        return {
            "risk_id": rid,
            "status": "pending_implementation",
            "likelihood": None, "impact": None,
            "risk_rating": None, "risk_level": None,
            "rationale": "No mitigations recommended or implemented yet.",
            "limitations": [],
        }

    if not implemented:
        return {
            "risk_id": rid,
            "status": "pending_implementation",
            "likelihood": None, "impact": None,
            "risk_rating": None, "risk_level": None,
            "rationale": f"{len(proposed)} mitigation(s) proposed but none implemented.",
            "limitations": [],
        }

    if retest_results is None:
        return {
            "risk_id": rid,
            "status": "pending_verification",
            "likelihood": None, "impact": None,
            "risk_rating": None, "risk_level": None,
            "rationale": f"{len(implemented)} mitigation(s) implemented but not yet retested.",
            "limitations": ["Mitigation effectiveness not verified"],
        }

    # Analyze retest results
    succeeded = sum(1 for r in retest_results if r.get("verdict") == "SUCCEEDED")
    total = len(retest_results)
    blocked = sum(1 for r in retest_results if r.get("verdict") == "FAILED")

    if total == 0:
        return {
            "risk_id": rid,
            "status": "pending_verification",
            "likelihood": None, "impact": None,
            "risk_rating": None, "risk_level": None,
            "rationale": "No retest results available.",
            "limitations": ["Retesting not performed"],
        }

    if succeeded == 0 and blocked > 0:
        # All retests blocked — reduced but not eliminated
        orig_likelihood = risk_entry.get("preliminary_likelihood", "Possible")
        orig_impact_str = risk_entry.get("impact", "")
        orig_impact = _extract_impact(orig_impact_str)

        new_likelihood = _reduce_likelihood(orig_likelihood)
        new_level = matrix.get((new_likelihood, orig_impact), "Medium")

        return {
            "risk_id": rid,
            "status": "assessed_reduced",
            "likelihood": new_likelihood,
            "impact": orig_impact,
            "risk_rating": f"{new_likelihood} × {orig_impact}",
            "risk_level": new_level,
            "rationale": (f"All {blocked} retest attempts blocked after {len(implemented)} "
                          f"mitigation(s) implemented. Likelihood reduced from {orig_likelihood} "
                          f"to {new_likelihood}."),
            "limitations": [
                "Retesting used previously known payloads — novel attacks may succeed",
                f"Retest coverage: {total} attempts with {len(implemented)} controls",
            ],
        }

    if succeeded > 0:
        return {
            "risk_id": rid,
            "status": "assessed_unchanged",
            "likelihood": risk_entry.get("preliminary_likelihood"),
            "impact": _extract_impact(risk_entry.get("impact", "")),
            "risk_rating": risk_entry.get("risk_rating"),
            "risk_level": risk_entry.get("risk_level"),
            "rationale": (f"{succeeded} of {total} retest attempts still succeeded "
                          f"despite {len(implemented)} mitigation(s). Risk unchanged."),
            "limitations": [],
        }

    return {
        "risk_id": rid,
        "status": "pending_assessment",
        "likelihood": None, "impact": None,
        "risk_rating": None, "risk_level": None,
        "rationale": "Retest results inconclusive.",
        "limitations": ["Insufficient evidence for residual assessment"],
    }


def update_tra_entry(risk_entry: dict,
                     analysis: dict | None = None,
                     mitigations: list[dict] | None = None,
                     residual: dict | None = None) -> dict:
    """Update a TRA risk entry with Phase B and Phase C fields.

    Preserves all original fields and adds testing, mitigation,
    and residual_assessment sections.
    """
    updated = copy.deepcopy(risk_entry)

    if analysis:
        updated["testing"] = {
            "exploitation_status": analysis.get("exploitation_status", "not_tested"),
            "contributing_evidence": analysis.get("contributing_evidence", []),
            "analysis": analysis.get("analysis", ""),
        }

    if mitigations is not None:
        implemented = [m for m in mitigations if m.get("status") == "implemented"]
        proposed = [m for m in mitigations if m.get("status") != "implemented"]
        updated["mitigation"] = {
            "recommended_controls": [m.get("description", "") for m in proposed],
            "implemented_controls": [m.get("description", "") for m in implemented],
            "implementation_status": "implemented" if implemented else "proposed",
        }

    if residual:
        updated["residual_assessment"] = {
            "status": residual.get("status", "pending_assessment"),
            "likelihood": residual.get("likelihood"),
            "impact": residual.get("impact"),
            "risk_rating": residual.get("risk_rating"),
            "risk_level": residual.get("risk_level"),
            "rationale": residual.get("rationale"),
            "limitations": residual.get("limitations", []),
        }
        # Set disposition
        if residual.get("status") == "assessed_reduced":
            updated["risk_disposition"] = {"status": "mitigated"}
        elif residual.get("status") == "assessed_accepted":
            updated["risk_disposition"] = {"status": "accepted"}
        else:
            updated["risk_disposition"] = {"status": "open"}

    return updated


def _extract_impact(impact_str: str) -> str:
    """Extract impact level (Low/Medium/High/Critical) from impact text."""
    for level in ("Critical", "High", "Medium", "Low"):
        if level.lower() in impact_str.lower():
            return level
    return "Medium"


def _reduce_likelihood(current: str) -> str:
    """Reduce likelihood by one step after successful mitigation."""
    steps = ["Almost certain", "Likely", "Possible", "Unlikely"]
    try:
        idx = steps.index(current)
        return steps[min(idx + 1, len(steps) - 1)]
    except ValueError:
        return current
