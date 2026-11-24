"""Tests for the Mitigation Skill (Phase C)."""
import sys
import yaml
from pathlib import Path

# Add the skill scripts to path
_scripts = str(Path(__file__).resolve().parent.parent / ".claude" / "skills" / "mitigation" / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from risk_assessment import (
    analyze_risk, assess_residual_risk, update_tra_entry,
    EXPLOITATION_STATUSES, RESIDUAL_STATUSES, RISK_MATRIX,
)

SKILL_DIR = Path(__file__).parent.parent / ".claude" / "skills" / "mitigation"


# ── Skill structure ───────────────────────────────────────────────────────────

def test_skill_files_exist():
    assert (SKILL_DIR / "SKILL.md").exists()
    assert (SKILL_DIR / "references" / "mitigation_guidance.yaml").exists()
    assert (SKILL_DIR / "references" / "residual_risk_schema.yaml").exists()
    assert (SKILL_DIR / "scripts" / "risk_assessment.py").exists()


def test_skill_is_generic():
    text = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    assert "Document Assistant" not in text
    assert "coordinator.py" not in text
    assert "app/agents/" not in text


def test_mitigation_guidance_valid():
    data = yaml.safe_load(
        (SKILL_DIR / "references" / "mitigation_guidance.yaml").read_text())
    assert "categories" in data
    assert len(data["categories"]) >= 5
    for cat in data["categories"]:
        assert "id" in cat
        assert "name" in cat
        assert "controls" in cat
        assert len(cat["controls"]) >= 1


def test_residual_risk_schema_valid():
    data = yaml.safe_load(
        (SKILL_DIR / "references" / "residual_risk_schema.yaml").read_text())
    assert "residual_assessment_statuses" in data
    assert "exploitation_statuses" in data
    assert "tra_update_template" in data


# ── analyze_risk ──────────────────────────────────────────────────────────────

def test_analyze_risk_no_results():
    risk = {"risk_id": "RISK-001", "threat_category": "RP.1"}
    result = analyze_risk(risk, [])
    assert result["exploitation_status"] == "not_tested"
    assert result["risk_id"] == "RISK-001"


def test_analyze_risk_confirmed():
    risk = {"risk_id": "RISK-001"}
    results = [
        {"verdict": "FAILED", "attempt": 1},
        {"verdict": "SUCCEEDED", "attempt": 2, "technique_id": "PI-001",
         "scenario_id": "S1", "evidence": [{"type": "state_change"}]},
    ]
    result = analyze_risk(risk, results)
    assert result["exploitation_status"] == "confirmed"
    assert len(result["contributing_evidence"]) == 1
    assert "2 of 2" in result["analysis"] or "1 of 2" in result["analysis"]


def test_analyze_risk_not_observed():
    risk = {"risk_id": "RISK-002"}
    results = [{"verdict": "FAILED"}, {"verdict": "FAILED"}]
    result = analyze_risk(risk, results)
    assert result["exploitation_status"] == "not_observed"


def test_analyze_risk_inconclusive():
    risk = {"risk_id": "RISK-003"}
    results = [{"verdict": "INCONCLUSIVE"}]
    result = analyze_risk(risk, results)
    assert result["exploitation_status"] == "inconclusive"


# ── assess_residual_risk ──────────────────────────────────────────────────────

def test_residual_no_mitigations():
    risk = {"risk_id": "R1", "preliminary_likelihood": "Possible", "impact": "High"}
    result = assess_residual_risk(risk, [])
    assert result["status"] == "pending_implementation"
    assert result["risk_level"] is None


def test_residual_proposed_only():
    risk = {"risk_id": "R1"}
    mitigations = [{"description": "Add input validation", "status": "proposed"}]
    result = assess_residual_risk(risk, mitigations)
    assert result["status"] == "pending_implementation"


def test_residual_implemented_no_retest():
    risk = {"risk_id": "R1"}
    mitigations = [{"description": "Added wrapping", "status": "implemented"}]
    result = assess_residual_risk(risk, mitigations, retest_results=None)
    assert result["status"] == "pending_verification"


def test_residual_all_blocked():
    risk = {"risk_id": "R1", "preliminary_likelihood": "Possible",
            "impact": "High — unauthorized modification"}
    mitigations = [{"description": "Added wrapping", "status": "implemented"}]
    retests = [{"verdict": "FAILED"}, {"verdict": "FAILED"}, {"verdict": "FAILED"}]
    result = assess_residual_risk(risk, mitigations, retests)
    assert result["status"] == "assessed_reduced"
    assert result["likelihood"] == "Unlikely"  # one step down from Possible
    assert result["risk_level"] is not None
    assert "blocked" in result["rationale"].lower()


def test_residual_still_succeeding():
    risk = {"risk_id": "R1", "preliminary_likelihood": "Possible",
            "risk_rating": "Possible × High", "risk_level": "High",
            "impact": "High"}
    mitigations = [{"description": "Partial fix", "status": "implemented"}]
    retests = [{"verdict": "SUCCEEDED"}, {"verdict": "FAILED"}]
    result = assess_residual_risk(risk, mitigations, retests)
    assert result["status"] == "assessed_unchanged"
    assert result["risk_level"] == "High"


# ── update_tra_entry ──────────────────────────────────────────────────────────

def test_update_tra_preserves_original():
    original = {
        "risk_id": "RISK-001", "threat_category": "RP.1",
        "risk_scenario": "Test scenario",
        "preliminary_likelihood": "Possible", "risk_level": "High",
    }
    updated = update_tra_entry(original)
    assert updated["risk_id"] == "RISK-001"
    assert updated["threat_category"] == "RP.1"
    assert updated["preliminary_likelihood"] == "Possible"


def test_update_tra_adds_testing():
    original = {"risk_id": "RISK-001"}
    analysis = {"exploitation_status": "confirmed",
                "contributing_evidence": [{"attempt": 2}],
                "analysis": "Exploitation confirmed."}
    updated = update_tra_entry(original, analysis=analysis)
    assert "testing" in updated
    assert updated["testing"]["exploitation_status"] == "confirmed"


def test_update_tra_adds_mitigation():
    original = {"risk_id": "RISK-001"}
    mitigations = [
        {"description": "Add wrapping", "status": "implemented"},
        {"description": "Add hierarchy", "status": "proposed"},
    ]
    updated = update_tra_entry(original, mitigations=mitigations)
    assert "mitigation" in updated
    assert len(updated["mitigation"]["implemented_controls"]) == 1
    assert len(updated["mitigation"]["recommended_controls"]) == 1
    assert updated["mitigation"]["implementation_status"] == "implemented"


def test_update_tra_adds_residual():
    original = {"risk_id": "RISK-001"}
    residual = {"status": "assessed_reduced", "likelihood": "Unlikely",
                "impact": "High", "risk_rating": "Unlikely × High",
                "risk_level": "Medium", "rationale": "Mitigated.",
                "limitations": []}
    updated = update_tra_entry(original, residual=residual)
    assert "residual_assessment" in updated
    assert updated["residual_assessment"]["status"] == "assessed_reduced"
    assert updated["risk_disposition"]["status"] == "mitigated"


def test_update_tra_does_not_modify_original():
    original = {"risk_id": "RISK-001", "risk_level": "High"}
    updated = update_tra_entry(original, residual={"status": "assessed_reduced"})
    assert "residual_assessment" not in original  # original unchanged
    assert "residual_assessment" in updated
