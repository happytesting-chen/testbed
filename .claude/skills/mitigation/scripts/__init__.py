"""Mitigation Skill scripts — risk analysis and TRA update functions."""
try:
    from .risk_assessment import analyze_risk, assess_residual_risk, update_tra_entry
except ImportError:
    from risk_assessment import analyze_risk, assess_residual_risk, update_tra_entry
