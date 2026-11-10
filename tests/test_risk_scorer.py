"""
Unit tests for AegisAudit AI RiskScorer and Mathematical Metrics.
"""

import pytest
from models.audit_schema import AuditFinding, ComplianceStatus, RiskLevel
from utils.risk_scorer import RiskScorer

def test_risk_scorer_empty_findings():
    metrics = RiskScorer.calculate_metrics([])
    assert metrics["score"] == 0.0
    assert metrics["total_risk_exposure"] == 0.0

def test_risk_scorer_all_compliant():
    findings = [
        AuditFinding(
            clause_id="ISO-1",
            clause_title="Access Control",
            requirement_summary="Requirement",
            status=ComplianceStatus.COMPLIANT,
            risk_level=RiskLevel.LOW,
            evidence_found="Enforced MFA",
            gap_analysis="No gap",
            remediation_recommendation="Maintain status quo"
        ),
        AuditFinding(
            clause_id="ISO-2",
            clause_title="Cryptography",
            requirement_summary="Requirement",
            status=ComplianceStatus.COMPLIANT,
            risk_level=RiskLevel.LOW,
            evidence_found="AES-256",
            gap_analysis="No gap",
            remediation_recommendation="Maintain status quo"
        )
    ]
    metrics = RiskScorer.calculate_metrics(findings)
    assert metrics["score"] == 100.0
    assert metrics["total_risk_exposure"] == 0.0

def test_risk_scorer_partially_compliant_weighting():
    # 1 compliant (1.0), 1 partially compliant (0.5), 1 non-compliant (0.0)
    # Total points = 1.5 out of 3.0 = 50.0%
    findings = [
        AuditFinding(
            clause_id="ISO-1",
            clause_title="Clause 1",
            requirement_summary="Req",
            status=ComplianceStatus.COMPLIANT,
            risk_level=RiskLevel.LOW,
            evidence_found="Evidence 1",
            gap_analysis="None",
            remediation_recommendation="None"
        ),
        AuditFinding(
            clause_id="ISO-2",
            clause_title="Clause 2",
            requirement_summary="Req",
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            risk_level=RiskLevel.MEDIUM,
            evidence_found="Partial evidence",
            gap_analysis="Minor gap",
            remediation_recommendation="Update docs"
        ),
        AuditFinding(
            clause_id="ISO-3",
            clause_title="Clause 3",
            requirement_summary="Req",
            status=ComplianceStatus.NON_COMPLIANT,
            risk_level=RiskLevel.CRITICAL,
            evidence_found="Missing MFA",
            gap_analysis="Critical gap",
            remediation_recommendation="Enforce FIDO2"
        )
    ]
    metrics = RiskScorer.calculate_metrics(findings)
    assert metrics["score"] == 50.0
    # Exposure: Medium (2) + Critical (8) = 10
    assert metrics["total_risk_exposure"] == 10
