"""
Unit tests for JobManager and Server-Sent Events (SSE) streaming.
"""

from core.job_manager import JobManager
from models.job_schema import AuditJobStatus

def test_create_and_get_job():
    jm = JobManager()
    job_id = jm.create_job(
        standard_filename="sample.pdf",
        policy_filename="sample.pdf"
    )
    assert job_id.startswith("JOB-")
    job = jm.get_job(job_id)
    assert job is not None
    assert job.status == AuditJobStatus.QUEUED
    assert job.standard_filename == "sample.pdf"

def test_stream_job_events_not_found():
    jm = JobManager()
    generator = jm.stream_job_events("JOB-NONEXISTENT")
    first_chunk = next(generator)
    assert "Job not found" in first_chunk

def test_stream_completed_job_yields_end():
    jm = JobManager()
    job_id = jm.create_job(
        standard_filename="sample.pdf",
        policy_filename="sample.pdf"
    )
    job = jm.get_job(job_id)
    job.status = AuditJobStatus.COMPLETED
    # Clear queue to simulate completed job
    jm.event_queues[job_id] = None

    generator = jm.stream_job_events(job_id)
    events = list(generator)
    joined = "".join(events)
    assert "event: end" in joined

