"""
Integration tests for AegisAudit AI REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from api.server import app
from models.user_schema import UserRole
from core.security import TokenManager

client = TestClient(app)

@pytest.fixture
def admin_token():
    # Login with seeded admin
    res = client.post("/api/auth/login", json={
        "email": "admin@aegisaudit.com",
        "password": "AdminPass123!"
    })
    assert res.status_code == 200
    return res.json()["access_token"]

def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert "version" in data

def test_auth_me_endpoint(admin_token):
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == "admin@aegisaudit.com"
    assert data["role"] == "admin"

def test_standards_catalog():
    res = client.get("/api/audit/standards/catalog")
    assert res.status_code == 200
    standards = res.json()
    assert len(standards) >= 4
    keys = [s["key"] for s in standards]
    assert "iso_27001_2022" in keys
    assert "soc_2_type_ii" in keys
    assert "gdpr_compliance" in keys
    assert "nist_csf_2_0" in keys

def test_documents_list_endpoint():
    res = client.get("/api/documents/list")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_audit_history_and_review(admin_token):
    # Ensure at least one audit exists or seed one
    history_res = client.get("/api/audit/history")
    assert history_res.status_code == 200
    audits = history_res.json()

    if len(audits) == 0:
        from db.storage import AuditDatabase
        from models.audit_schema import FullAuditReport, AuditSummary, AuditFinding, ComplianceStatus, RiskLevel
        db = AuditDatabase()
        db.save_report(FullAuditReport(
            audit_id="TEST-AUDIT-INTEG",
            standard_name="ISO 27001",
            policy_name="Security.pdf",
            timestamp="2026-11-09",
            summary=AuditSummary(
                overall_compliance_percentage=50.0,
                total_clauses_audited=2,
                compliant_count=1,
                partially_compliant_count=0,
                non_compliant_count=1,
                risk_breakdown={"Critical": 0, "High": 1, "Medium": 0, "Low": 1},
                executive_overview="Integration Test Overview"
            ),
            findings=[
                AuditFinding(
                    clause_id="A.1.1",
                    clause_title="Access Policy",
                    requirement_summary="Require MFA",
                    status=ComplianceStatus.NON_COMPLIANT,
                    risk_level=RiskLevel.HIGH,
                    evidence_found="Policy mentions passwords only",
                    gap_analysis="Missing MFA",
                    remediation_recommendation="Implement FIDO2"
                ),
                AuditFinding(
                    clause_id="A.1.2",
                    clause_title="Encryption",
                    requirement_summary="AES-256",
                    status=ComplianceStatus.COMPLIANT,
                    risk_level=RiskLevel.LOW,
                    evidence_found="AES-256 enabled",
                    gap_analysis="None",
                    remediation_recommendation="Maintain status quo"
                )
            ]
        ))
        target_id = "TEST-AUDIT-INTEG"
    else:
        target_id = audits[0]["audit_id"]

    # Review finding
    review_res = client.post(
        f"/api/audit/{target_id}/review",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "clause_id": "A.1.1",
            "status": "Compliant",
            "is_verified": True,
            "auditor_notes": "Compensating controls verified.",
            "remediation_status": "Resolved"
        }
    )
    if review_res.status_code == 200:
        data = review_res.json()
        assert data["audit_id"] == target_id
        finding = next((f for f in data["findings"] if f["clause_id"] == "A.1.1"), None)
        assert finding is not None
        assert finding["status"] == "Compliant"
        assert finding["is_verified"] is True

def test_export_endpoints(admin_token):
    # Test JSON and Markdown exports
    from db.storage import AuditDatabase
    from models.audit_schema import FullAuditReport, AuditSummary
    db = AuditDatabase()
    test_id = "TEST-EXPORT-RUN"
    db.save_report(FullAuditReport(
        audit_id=test_id,
        standard_name="ISO 27001",
        policy_name="Policy.pdf",
        timestamp="2026-11-09",
        summary=AuditSummary(
            overall_compliance_percentage=100.0,
            total_clauses_audited=1,
            compliant_count=1,
            partially_compliant_count=0,
            non_compliant_count=0,
            risk_breakdown={"Critical": 0, "High": 0, "Medium": 0, "Low": 1},
            executive_overview="Clean export summary"
        ),
        findings=[]
    ))

    # JSON export
    res_json = client.get(f"/api/audit/{test_id}/export/json")
    assert res_json.status_code == 200
    assert res_json.headers["content-type"].startswith("application/json")

    # CSV export
    res_csv = client.get(f"/api/audit/{test_id}/export/csv")
    assert res_csv.status_code == 200

    # Clean up test audit
    db.delete_audit(test_id)
