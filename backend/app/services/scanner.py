"""Scanner orchestration service — runs as RQ job."""
import os
import subprocess
import traceback
from datetime import datetime, timezone
from sqlalchemy.orm import Session as DBSession
from app.database import SessionLocal
from app.models import Job, Finding, JobStatus
from app.services.nuclei import build_command, parse_output_file, stop_process
from app.services.audit import log_action
from app.config import settings


def run_scan_job(job_id: int):
    """
    Execute a nuclei scan for the given job.
    This function is called by the RQ worker.
    """
    db: DBSession = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            return

        # Mark as running
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        job.progress_pct = 5.0
        db.commit()

        log_action(db, "scan_started", user_id=job.user_id,
                   details=f"Scan started for {job.target_url} (job {job_id})")

        # Build command
        cmd, output_file = build_command(job.target_url, job_id)
        job.output_file = output_file
        db.commit()

        # Check if nuclei binary exists
        nuclei_bin = settings.NUCLEI_BIN
        if not os.path.isfile(nuclei_bin):
            # Try to find nuclei in PATH
            import shutil
            nuclei_path = shutil.which("nuclei")
            if nuclei_path:
                cmd[0] = nuclei_path
            else:
                job.status = JobStatus.FAILED
                job.error_message = (
                    f"Nuclei binary not found at '{nuclei_bin}' and not in PATH. "
                    "Please install nuclei and configure NUCLEI_BIN in .env"
                )
                job.finished_at = datetime.now(timezone.utc)
                db.commit()
                log_action(db, "scan_failed", user_id=job.user_id,
                           details=f"Nuclei not found (job {job_id})")
                return

        # Run nuclei
        job.progress_pct = 10.0
        db.commit()

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # Store PID for stop capability
            job.pid = process.pid
            db.commit()

            # Wait for completion
            stdout, stderr = process.communicate(timeout=3600)  # 1 hour max
            returncode = process.returncode

        except subprocess.TimeoutExpired:
            process.kill()
            job.status = JobStatus.FAILED
            job.error_message = "Scan timed out after 1 hour"
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            log_action(db, "scan_timeout", user_id=job.user_id,
                       details=f"Scan timed out (job {job_id})")
            return

        # Check if job was stopped
        job = db.query(Job).filter(Job.id == job_id).first()
        if job.status == JobStatus.STOPPED:
            log_action(db, "scan_stopped", user_id=job.user_id,
                       details=f"Scan was stopped (job {job_id})")
            return

        # Parse results
        job.progress_pct = 80.0
        db.commit()

        findings_data = parse_output_file(output_file)

        # Save findings to DB
        for fdata in findings_data:
            finding = Finding(
                job_id=job_id,
                rule_id=fdata.get("rule_id"),
                name=fdata.get("name", "Unknown"),
                severity=fdata.get("severity", "info"),
                cwe=fdata.get("cwe"),
                owasp_category=fdata.get("owasp_category"),
                owasp_name=fdata.get("owasp_name"),
                description=fdata.get("description"),
                evidence=fdata.get("evidence"),
                matched_url=fdata.get("matched_url"),
                remediation=fdata.get("remediation"),
                raw_json=fdata.get("raw_json"),
            )
            db.add(finding)

        # Update job
        job.status = JobStatus.COMPLETED
        job.progress_pct = 100.0
        job.findings_count = len(findings_data)
        job.finished_at = datetime.now(timezone.utc)
        job.pid = None

        if returncode != 0 and not findings_data:
            job.status = JobStatus.FAILED
            job.error_message = f"Nuclei exited with code {returncode}"
            if stderr:
                job.error_message += f": {stderr[:500]}"

        db.commit()

        log_action(db, "scan_completed", user_id=job.user_id,
                   details=f"Scan completed for {job.target_url}: {len(findings_data)} findings (job {job_id})")

    except Exception as e:
        # Handle unexpected errors
        try:
            job = db.query(Job).filter(Job.id == job_id).first()
            if job:
                job.status = JobStatus.FAILED
                job.error_message = f"Internal error: {str(e)}"
                job.finished_at = datetime.now(timezone.utc)
                job.pid = None
                db.commit()
                log_action(db, "scan_error", user_id=job.user_id,
                           details=f"Error in scan job {job_id}: {traceback.format_exc()[:500]}")
        except Exception:
            pass
    finally:
        db.close()
