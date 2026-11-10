"""
Audit REST API routes for AegisAudit AI.
Includes RBAC, Async Job Execution, SSE Event Streaming, Standards Catalog,
Findings Governance Review, Compliance Diff Analysis, and Multi-Format Exports.
"""

import io
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from pathlib import Path
from typing import Optional, List, Dict, Any

from models.audit_schema import FullAuditReport, ComplianceStatus
from models.user_schema import UserResponse, UserRole
from models.job_schema import AuditJobResponse
from agents.orchestrator import AuditOrchestrator
from db.storage import AuditDatabase
from core.config import settings
from core.job_manager import job_manager
from api.deps import get_current_user, get_optional_user, require_roles
from rag.standards_catalog import StandardsCatalogService
from utils.report_exporter import ReportExporter
from utils.risk_scorer import RiskScorer

router = APIRouter(prefix="/api/audit", tags=["Audit"])
db = AuditDatabase()

class RunAuditRequest(BaseModel):
    standard_filename: Optional[str] = "sample.pdf"
    standard_key: Optional[str] = None
    policy_filename: Optional[str] = "sample.pdf"
    policy_filenames: Optional[List[str]] = None
    max_clauses: Optional[int] = 10

class FindingReviewRequest(BaseModel):
    clause_id: str
    status: Optional[str] = None
    is_verified: Optional[bool] = None
    auditor_notes: Optional[str] = None
    remediation_owner: Optional[str] = None
    remediation_status: Optional[str] = None

class CompareAuditsRequest(BaseModel):
    audit_id_1: str
    audit_id_2: str

# --- STANDARDS CATALOG ---
@router.get("/standards/catalog", response_model=List[Dict[str, Any]])
def get_standards_catalog():
    """Returns pre-seeded regulatory compliance frameworks (ISO 27001, SOC 2, GDPR, NIST CSF)."""
    return StandardsCatalogService.list_standards()

# --- SYNCHRONOUS RUN (Direct execution) ---
@router.post("/run", response_model=FullAuditReport)
def run_compliance_audit_sync(
    req: RunAuditRequest,
    current_user: UserResponse = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR]))
):
    """
    Executes a multi-agent audit synchronously.
    Requires 'admin' or 'auditor' role.
    """
    if req.standard_key:
        standard_path = StandardsCatalogService.get_standard_file_path(req.standard_key)
    else:
        standard_path = settings.DATA_DIR / (req.standard_filename or "sample.pdf")

    if req.policy_filenames and len(req.policy_filenames) > 1:
        policy_path = [settings.DATA_DIR / f for f in req.policy_filenames]
    else:
        fn = req.policy_filenames[0] if req.policy_filenames else (req.policy_filename or "sample.pdf")
        policy_path = settings.DATA_DIR / fn

    if not standard_path.exists():
        raise HTTPException(status_code=404, detail=f"Standard file not found: {standard_path.name}")

    orchestrator = AuditOrchestrator()
    try:
        report = orchestrator.run_audit(
            standard_path=standard_path,
            policy_path=policy_path,
            max_clauses=req.max_clauses or 10
        )
        db.save_report(report)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")

# --- ASYNC JOB QUEUE (Real-time SSE Streaming) ---
@router.post("/jobs/submit", response_model=AuditJobResponse, status_code=status.HTTP_202_ACCEPTED)
def submit_async_audit_job(
    req: RunAuditRequest,
    current_user: UserResponse = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR]))
):
    """
    Submits a background audit job. Returns 202 Accepted with job_id.
    """
    if req.standard_key:
        standard_file = StandardsCatalogService.get_standard_file_path(req.standard_key)
        std_name = standard_file.name
    else:
        std_name = req.standard_filename or "sample.pdf"
        standard_path = settings.DATA_DIR / std_name
        if not standard_path.exists():
            raise HTTPException(status_code=404, detail=f"Standard file not found: {std_name}")

    if req.policy_filenames and len(req.policy_filenames) > 0:
        pol_name = ", ".join(req.policy_filenames)
    else:
        pol_name = req.policy_filename or "sample.pdf"

    job_id = job_manager.create_job(
        standard_filename=std_name,
        policy_filename=pol_name,
        standard_key=req.standard_key,
        policy_filenames=req.policy_filenames
    )
    job_manager.start_job(job_id, max_clauses=req.max_clauses or 10)
    return job_manager.get_job(job_id)

@router.get("/jobs/{job_id}/status", response_model=AuditJobResponse)
def get_job_status(job_id: str, current_user: Optional[UserResponse] = Depends(get_optional_user)):
    """Polls the progress status of an asynchronous audit job."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job

@router.get("/jobs/{job_id}/stream")
def stream_job_agent_events(job_id: str):
    """Streams live Agent execution logs via Server-Sent Events (SSE)."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    return StreamingResponse(
        job_manager.stream_job_events(job_id),
        media_type="text/event-stream"
    )

# --- AUDIT HISTORY & REPORTS ---
@router.get("/history", response_model=List[Dict[str, Any]])
def get_audit_history(current_user: Optional[UserResponse] = Depends(get_optional_user)):
    """Retrieves metadata of all past compliance audits."""
    return db.list_audits()

@router.get("/{audit_id}", response_model=FullAuditReport)
def get_audit_report(audit_id: str, current_user: Optional[UserResponse] = Depends(get_optional_user)):
    """Retrieves a full audit report by ID."""
    report = db.get_report(audit_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")
    return report

@router.delete("/{audit_id}")
def delete_audit_run(
    audit_id: str,
    current_user: UserResponse = Depends(require_roles([UserRole.ADMIN]))
):
    """Deletes an audit report. Requires admin role."""
    success = db.delete_audit(audit_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")
    return {"status": "success", "message": f"Audit {audit_id} deleted successfully"}

# --- AUDITOR GOVERNANCE & REVIEW ---
@router.post("/{audit_id}/review", response_model=FullAuditReport)
def review_audit_finding(
    audit_id: str,
    req: FindingReviewRequest,
    current_user: UserResponse = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR]))
):
    """Updates auditor annotations, verification status, and remediation ownership."""
    report = db.get_report(audit_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")

    found = False
    for f in report.findings:
        if f.clause_id == req.clause_id:
            found = True
            if req.status:
                try:
                    f.status = ComplianceStatus(req.status)
                except Exception:
                    f.status = req.status
            if req.is_verified is not None:
                f.is_verified = req.is_verified
            if req.auditor_notes is not None:
                f.auditor_notes = req.auditor_notes
            if req.remediation_owner is not None:
                f.remediation_owner = req.remediation_owner
            if req.remediation_status is not None:
                f.remediation_status = req.remediation_status
            break

    if not found:
        raise HTTPException(status_code=404, detail=f"Clause {req.clause_id} not found in audit {audit_id}")

    # Recalculate summary metrics with mathematically sound weighting
    total = len(report.findings)
    compliant = sum(1 for f in report.findings if getattr(f.status, "value", f.status) == "Compliant")
    partial = sum(1 for f in report.findings if getattr(f.status, "value", f.status) == "Partially Compliant")
    non_compliant = sum(1 for f in report.findings if getattr(f.status, "value", f.status) == "Non-Compliant")

    metrics = RiskScorer.calculate_metrics(report.findings)

    report.summary.total_clauses_audited = total
    report.summary.compliant_count = compliant
    report.summary.partially_compliant_count = partial
    report.summary.non_compliant_count = non_compliant
    report.summary.overall_compliance_percentage = metrics["score"]

    # Update risk breakdown
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in report.findings:
        rl = getattr(f.risk_level, "value", f.risk_level)
        if rl in risk_counts:
            risk_counts[rl] += 1
    report.summary.risk_breakdown = risk_counts

    db.save_report(report)
    return report

# --- COMPLIANCE DIFF & BENCHMARKING ---
@router.post("/compare")
def compare_audits(req: CompareAuditsRequest, current_user: Optional[UserResponse] = Depends(get_optional_user)):
    """Computes delta and gap transitions between two audit runs."""
    r1 = db.get_report(req.audit_id_1)
    r2 = db.get_report(req.audit_id_2)
    if not r1 or not r2:
        raise HTTPException(status_code=404, detail="One or both audit reports not found")

    score_delta = round(r2.summary.overall_compliance_percentage - r1.summary.overall_compliance_percentage, 1)
    map1 = {f.clause_id: f for f in r1.findings}
    map2 = {f.clause_id: f for f in r2.findings}

    resolved_gaps = []
    new_gaps = []
    regressed = []
    unchanged = []

    for cid, f2 in map2.items():
        s2 = getattr(f2.status, "value", f2.status)
        if cid in map1:
            f1 = map1[cid]
            s1 = getattr(f1.status, "value", f1.status)
            if s1 == "Non-Compliant" and s2 in ["Compliant", "Partially Compliant"]:
                resolved_gaps.append({"clause_id": cid, "title": f2.clause_title, "old_status": s1, "new_status": s2})
            elif s1 in ["Compliant", "Partially Compliant"] and s2 == "Non-Compliant":
                new_gaps.append({"clause_id": cid, "title": f2.clause_title, "old_status": s1, "new_status": s2})
            elif s1 == s2:
                unchanged.append(cid)
            else:
                regressed.append({"clause_id": cid, "title": f2.clause_title, "old_status": s1, "new_status": s2})
        else:
            if s2 == "Non-Compliant":
                new_gaps.append({"clause_id": cid, "title": f2.clause_title, "old_status": "Not Audited", "new_status": s2})

    return {
        "baseline_id": r1.audit_id,
        "baseline_standard": r1.standard_name,
        "baseline_score": r1.summary.overall_compliance_percentage,
        "target_id": r2.audit_id,
        "target_standard": r2.standard_name,
        "target_score": r2.summary.overall_compliance_percentage,
        "score_delta": score_delta,
        "resolved_gaps_count": len(resolved_gaps),
        "new_gaps_count": len(new_gaps),
        "resolved_gaps": resolved_gaps,
        "new_gaps": new_gaps,
        "regressed": regressed,
        "unchanged_count": len(unchanged)
    }

# --- MULTI-FORMAT EXPORTS ---
@router.get("/{audit_id}/export/{format}")
def export_audit_report(audit_id: str, format: str):
    """Exports an audit report in PDF, CSV, Jira Tasks, Markdown, or JSON."""
    report = db.get_report(audit_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")

    fmt = format.lower()
    if fmt == "pdf":
        pdf_bytes = ReportExporter.to_pdf(report)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="AegisAudit_{audit_id}.pdf"'}
        )
    elif fmt == "csv":
        csv_str = ReportExporter.to_csv(report)
        return StreamingResponse(
            io.BytesIO(csv_str.encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="AegisAudit_{audit_id}_Matrix.csv"'}
        )
    elif fmt in ["tasks", "jira"]:
        tasks_csv = ReportExporter.to_remediation_csv(report)
        return StreamingResponse(
            io.BytesIO(tasks_csv.encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="AegisAudit_{audit_id}_Jira_Tasks.csv"'}
        )
    elif fmt in ["md", "markdown"]:
        md_str = ReportExporter.to_markdown(report)
        return StreamingResponse(
            io.BytesIO(md_str.encode("utf-8")),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="AegisAudit_{audit_id}.md"'}
        )
    elif fmt == "json":
        json_str = ReportExporter.to_json(report)
        return StreamingResponse(
            io.BytesIO(json_str.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="AegisAudit_{audit_id}.json"'}
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}. Supported: pdf, csv, tasks, markdown, json")
