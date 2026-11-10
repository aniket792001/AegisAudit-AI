"""
Database Persistence Layer for AegisAudit AI.
Stores audit run history and reports using SQLite.
"""

import sqlite3
import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from core.config import settings
from core.logger import logger
from models.audit_schema import FullAuditReport

class AuditDatabase:
    def __init__(self, db_path: Path = None):
        self.db_path = db_path or (settings.DB_DIR / "aegisaudit.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns hardened SQLite connection with WAL mode and concurrency resilience."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_runs (
                    audit_id TEXT PRIMARY KEY,
                    standard_name TEXT,
                    policy_name TEXT,
                    timestamp TEXT,
                    compliance_pct REAL,
                    total_clauses INTEGER,
                    compliant_count INTEGER,
                    non_compliant_count INTEGER,
                    report_json TEXT
                )
            """)
            # Migration check for older SQLite databases
            for col, col_type in [("compliant_count", "INTEGER DEFAULT 0"), ("non_compliant_count", "INTEGER DEFAULT 0")]:
                try:
                    cursor.execute(f"ALTER TABLE audit_runs ADD COLUMN {col} {col_type}")
                except Exception:
                    pass
            conn.commit()

    def save_report(self, report: FullAuditReport):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO audit_runs (
                    audit_id, standard_name, policy_name, timestamp,
                    compliance_pct, total_clauses, compliant_count, non_compliant_count, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.audit_id,
                report.standard_name,
                report.policy_name,
                report.timestamp,
                report.summary.overall_compliance_percentage,
                report.summary.total_clauses_audited,
                report.summary.compliant_count,
                report.summary.non_compliant_count,
                report.model_dump_json()
            ))
            conn.commit()
            logger.info(f"AuditDatabase: Saved audit report {report.audit_id}")

    def list_audits(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT audit_id, standard_name, policy_name, timestamp, compliance_pct, total_clauses,
                       COALESCE(compliant_count, 0), COALESCE(non_compliant_count, 0)
                FROM audit_runs ORDER BY timestamp DESC
            """)
            rows = cursor.fetchall()
            return [
                {
                    "audit_id": r[0],
                    "standard_name": r[1],
                    "policy_name": r[2],
                    "timestamp": r[3],
                    "compliance_pct": r[4],
                    "total_clauses": r[5],
                    "compliant_count": r[6],
                    "non_compliant_count": r[7]
                }
                for r in rows
            ]

    def get_report(self, audit_id: str) -> Optional[FullAuditReport]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT report_json FROM audit_runs WHERE audit_id = ?", (audit_id,))
            row = cursor.fetchone()
            if row:
                data = json.loads(row[0])
                return FullAuditReport.model_validate(data)
        return None

    def delete_audit(self, audit_id: str) -> bool:
        """Deletes an audit report by ID from SQLite database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM audit_runs WHERE audit_id = ?", (audit_id,))
            conn.commit()
            deleted = cursor.rowcount > 0
            if deleted:
                logger.info(f"AuditDatabase: Deleted audit run {audit_id}")
            return deleted

