"""
Asynchronous Job Manager and SSE Event Broker for AegisAudit AI.
Handles background job execution, progress tracking, and real-time agent log streaming.
"""

import uuid
import threading
import queue
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Generator, List, Any
from models.job_schema import AuditJobStatus, AuditJobResponse, AgentLogEvent
from agents.orchestrator import AuditOrchestrator
from db.storage import AuditDatabase
from core.logger import logger
from core.config import settings

class JobManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(JobManager, cls).__new__(cls)
                cls._instance._init_manager()
            return cls._instance

    def _init_manager(self):
        self.jobs: Dict[str, AuditJobResponse] = {}
        self.job_meta: Dict[str, Dict[str, Any]] = {}
        self.event_queues: Dict[str, queue.Queue] = {}
        self.db = AuditDatabase()

    def create_job(
        self,
        standard_filename: str,
        policy_filename: str,
        standard_key: Optional[str] = None,
        policy_filenames: Optional[List[str]] = None
    ) -> str:
        job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        job = AuditJobResponse(
            job_id=job_id,
            status=AuditJobStatus.QUEUED,
            progress_pct=0.0,
            current_step="Job queued for execution",
            created_at=now_str,
            updated_at=now_str,
            standard_filename=standard_filename,
            policy_filename=policy_filename
        )

        self.jobs[job_id] = job
        self.job_meta[job_id] = {
            "standard_key": standard_key,
            "policy_filenames": policy_filenames or ([policy_filename] if policy_filename else [])
        }
        self.event_queues[job_id] = queue.Queue()
        logger.info(f"JobManager: Created async job {job_id}")
        return job_id

    def start_job(self, job_id: str, max_clauses: int = 15):
        """Spawns background worker thread to execute the audit."""
        thread = threading.Thread(
            target=self._run_job_worker,
            args=(job_id, max_clauses),
            daemon=True
        )
        thread.start()

    def _run_job_worker(self, job_id: str, max_clauses: int):
        job = self.jobs.get(job_id)
        if not job:
            return

        job.status = AuditJobStatus.PROCESSING
        job.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        meta = self.job_meta.get(job_id, {})
        standard_key = meta.get("standard_key")
        if standard_key:
            from rag.standards_catalog import StandardsCatalogService
            standard_path = StandardsCatalogService.get_standard_file_path(standard_key)
        else:
            standard_path = settings.DATA_DIR / job.standard_filename

        policy_filenames = meta.get("policy_filenames")
        if policy_filenames and len(policy_filenames) > 1:
            policy_path = [settings.DATA_DIR / fn for fn in policy_filenames]
        elif policy_filenames and len(policy_filenames) == 1:
            policy_path = settings.DATA_DIR / policy_filenames[0]
        else:
            policy_path = settings.DATA_DIR / job.policy_filename

        ev_q = self.event_queues.get(job_id)

        def progress_tracker(message: str, pct: float):
            job.current_step = message
            job.progress_pct = round(pct * 100.0, 1)
            job.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Determine agent name from message
            agent_name = "Orchestrator"
            if "ClauseExtractor" in message:
                agent_name = "ClauseExtractorAgent"
            elif "Auditing Clause" in message or "Evidence" in message:
                agent_name = "EvidenceHunter & Auditor"
            elif "MatrixGenerator" in message:
                agent_name = "MatrixGeneratorAgent"

            event = AgentLogEvent(
                agent_name=agent_name,
                message=message,
                progress_pct=job.progress_pct
            )
            if ev_q:
                ev_q.put(event)

        try:
            orchestrator = AuditOrchestrator()
            report = orchestrator.run_audit(
                standard_path=standard_path,
                policy_path=policy_path,
                max_clauses=max_clauses,
                progress_callback=progress_tracker
            )

            job.status = AuditJobStatus.COMPLETED
            job.result = report
            job.progress_pct = 100.0
            job.current_step = "Audit completed successfully."
            job.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Save in database
            self.db.save_report(report)

            if ev_q:
                ev_q.put(AgentLogEvent(
                    agent_name="System",
                    message="Audit report compiled and finalized.",
                    progress_pct=100.0
                ))
                ev_q.put(None)  # Sentinel to close SSE stream
        except Exception as e:
            logger.error(f"JobManager: Job {job_id} failed: {e}", exc_info=True)
            job.status = AuditJobStatus.FAILED
            job.error = str(e)
            job.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if ev_q:
                ev_q.put(AgentLogEvent(
                    agent_name="System",
                    message=f"Job failed: {str(e)}",
                    progress_pct=job.progress_pct
                ))
                ev_q.put(None)

    def get_job(self, job_id: str) -> Optional[AuditJobResponse]:
        return self.jobs.get(job_id)

    def stream_job_events(self, job_id: str) -> Generator[str, None, None]:
        """Yields Server-Sent Events (SSE) for real-time frontend streaming with reconnect resilience."""
        job = self.jobs.get(job_id)
        if not job:
            yield 'data: {"error": "Job not found"}\n\n'
            return

        ev_q = self.event_queues.get(job_id)
        if not ev_q:
            if job.status == AuditJobStatus.COMPLETED:
                yield 'data: {"agent_name": "System", "message": "Audit completed.", "progress_pct": 100.0}\n\n'
                yield 'event: end\ndata: {"message": "Stream completed"}\n\n'
            elif job.status == AuditJobStatus.FAILED:
                yield f'data: {{"agent_name": "System", "message": "Job failed: {job.error}", "progress_pct": 100.0}}\n\n'
                yield 'event: end\ndata: {"message": "Stream completed"}\n\n'
            else:
                yield 'data: {"error": "Event stream queue not available"}\n\n'
            return

        while True:
            try:
                event: Optional[AgentLogEvent] = ev_q.get(timeout=2)
                if event is None:
                    # Stream complete sentinel
                    yield "event: end\ndata: {\"message\": \"Stream completed\"}\n\n"
                    break
                yield f"data: {event.model_dump_json()}\n\n"
            except queue.Empty:
                if job.status in (AuditJobStatus.COMPLETED, AuditJobStatus.FAILED):
                    yield "event: end\ndata: {\"message\": \"Stream completed\"}\n\n"
                    break
                # Keep-alive heartbeat ping
                yield "event: ping\ndata: {}\n\n"

job_manager = JobManager()
