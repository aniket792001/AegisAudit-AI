"""
Risk Scorer Utility for AegisAudit AI.
Calculates quantitative risk vectors and weighted compliance scores.
"""

from typing import List, Dict
from models.audit_schema import AuditFinding, ComplianceStatus, RiskLevel

class RiskScorer:
    WEIGHTS = {
        ComplianceStatus.COMPLIANT: 1.0,
        ComplianceStatus.PARTIALLY_COMPLIANT: 0.5,
        ComplianceStatus.NON_COMPLIANT: 0.0,
        ComplianceStatus.NOT_APPLICABLE: 1.0
    }

    RISK_SEVERITY_WEIGHT = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 4,
        RiskLevel.CRITICAL: 8
    }

    @classmethod
    def calculate_metrics(cls, findings: List[AuditFinding]) -> Dict[str, float]:
        if not findings:
            return {"score": 0.0, "total_risk_exposure": 0.0}

        total_points = sum(cls.WEIGHTS.get(f.status, 0.0) for f in findings)
        max_points = float(len(findings))
        score = (total_points / max_points) * 100.0

        total_risk = sum(cls.RISK_SEVERITY_WEIGHT.get(f.risk_level, 1) for f in findings if f.status != ComplianceStatus.COMPLIANT)
        
        return {
            "score": round(score, 1),
            "total_risk_exposure": total_risk
        }
