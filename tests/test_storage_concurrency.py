"""
Unit tests for SQLite Storage Concurrency, WAL Mode, and Persistence.
"""

import threading
from pathlib import Path
from core.config import settings
from db.storage import AuditDatabase
from models.audit_schema import FullAuditReport, AuditSummary, AuditFinding, ComplianceStatus, RiskLevel

def test_database_initialization_and_wal_mode():
    db_path = settings.DB_DIR / "test_wal_init.db"
    try:
        db = AuditDatabase(db_path=db_path)
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            mode = cursor.fetchone()[0]
            assert mode.lower() == "wal"
    finally:
        # Clean up
        try:
            if db_path.exists():
                db_path.unlink(missing_ok=True)
            wal = db_path.with_name(db_path.name + "-wal")
            shm = db_path.with_name(db_path.name + "-shm")
            if wal.exists(): wal.unlink(missing_ok=True)
            if shm.exists(): shm.unlink(missing_ok=True)
        except Exception:
            pass

def test_save_and_retrieve_report():
    db_path = settings.DB_DIR / "test_save_retrieve.db"
    try:
        db = AuditDatabase(db_path=db_path)

        report = FullAuditReport(
            audit_id="TEST-AUDIT-001",
            standard_name="ISO_27001",
            policy_name="Security_Policy.pdf",
            timestamp="2026-11-09 12:00:00",
            summary=AuditSummary(
                overall_compliance_percentage=85.0,
                total_clauses_audited=2,
                compliant_count=1,
                partially_compliant_count=1,
                non_compliant_count=0,
                risk_breakdown={"Critical": 0, "High": 0, "Medium": 1, "Low": 1},
                executive_overview="Test Overview"
            ),
            findings=[
                AuditFinding(
                    clause_id="A.1",
                    clause_title="Title 1",
                    requirement_summary="Summary",
                    status=ComplianceStatus.COMPLIANT,
                    risk_level=RiskLevel.LOW,
                    evidence_found="Evidence text",
                    gap_analysis="No gap",
                    remediation_recommendation="Maintain status quo"
                )
            ]
        )

        db.save_report(report)

        # Retrieve
        fetched = db.get_report("TEST-AUDIT-001")
        assert fetched is not None
        assert fetched.audit_id == "TEST-AUDIT-001"
        assert fetched.summary.overall_compliance_percentage == 85.0

        # List
        audits = db.list_audits()
        assert len(audits) == 1
        assert audits[0]["audit_id"] == "TEST-AUDIT-001"

        # Delete
        success = db.delete_audit("TEST-AUDIT-001")
        assert success is True
        assert db.get_report("TEST-AUDIT-001") is None
    finally:
        try:
            if db_path.exists(): db_path.unlink(missing_ok=True)
        except Exception:
            pass

def test_concurrent_read_writes():
    db_path = settings.DB_DIR / "test_concurrent_rw.db"
    try:
        db = AuditDatabase(db_path=db_path)
        errors = []

        def worker(idx):
            try:
                rep = FullAuditReport(
                    audit_id=f"CONCURRENT-{idx}",
                    standard_name="ISO",
                    policy_name="Policy.pdf",
                    timestamp="2026-11-09",
                    summary=AuditSummary(
                        overall_compliance_percentage=70.0,
                        total_clauses_audited=1,
                        compliant_count=1,
                        partially_compliant_count=0,
                        non_compliant_count=0,
                        risk_breakdown={"Critical": 0, "High": 0, "Medium": 0, "Low": 1},
                        executive_overview="Concurrent test"
                    ),
                    findings=[]
                )
                db.save_report(rep)
                fetched = db.get_report(f"CONCURRENT-{idx}")
                assert fetched is not None
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(db.list_audits()) == 10
    finally:
        try:
            if db_path.exists(): db_path.unlink(missing_ok=True)
        except Exception:
            pass
