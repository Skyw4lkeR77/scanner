"""Scanner orchestration service — runs as RQ job."""
import os
import subprocess
import traceback
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session as DBSession
from app.database import SessionLocal
from app.models import Job, Finding, JobStatus, JAKARTA_TZ
from app.services.nuclei import build_command, parse_output_file, stop_process, get_scan_stats
from app.services.xray import run_xray_scan, parse_xray_output, stop_xray_process, check_xray_binary
from app.services.audit import log_action
from app.config import settings


def jakartanow():
    """Return current time in Asia/Jakarta timezone."""
    return datetime.now(JAKARTA_TZ)


def run_scan_job(job_id: int):
    """
    Execute comprehensive scan for the given job.
    This function is called by the RQ worker.
    Supports: Nuclei, Xray (Chaitin), and Katana crawling
    """
    db: DBSession = SessionLocal()
    start_time = jakartanow()
    
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            print(f"Job {job_id} not found")
            return

        # Mark as running with Jakarta timezone
        job.status = JobStatus.RUNNING
        job.started_at = start_time
        job.progress_pct = 1.0
        db.commit()

        log_action(db, "scan_started", user_id=job.user_id,
                   details=f"Scan started for {job.target_url} (mode: {job.scan_mode}, job {job_id})")

        all_findings = []
        endpoints_file = None
        
        # ============================================================================
        # PHASE 1: Endpoint Discovery (Katana)
        # ============================================================================
        if job.scan_mode in ("deep", "comprehensive"):
            job.progress_pct = 5.0
            db.commit()
            
            try:
                from app.services.katana import run_katana
                
                print(f"[Job {job_id}] Starting Katana crawling...")
                katana_output = run_katana(job.target_url, job_id)
                
                if katana_output and os.path.exists(katana_output):
                    # Count discovered endpoints
                    with open(katana_output, 'r') as f:
                        endpoints = [line.strip() for line in f if line.strip()]
                        job.endpoints_discovered = len(endpoints)
                        job.katana_output_file = katana_output
                        db.commit()
                    
                    endpoints_file = katana_output
                    log_action(db, "katana_completed", user_id=job.user_id, 
                               details=f"Katana found {job.endpoints_discovered} endpoints for {job.target_url}")
                    print(f"[Job {job_id}] Katana found {job.endpoints_discovered} endpoints")
                else:
                    print(f"[Job {job_id}] Katana crawling returned no results")
                    
            except Exception as e:
                print(f"[Job {job_id}] Katana error: {e}")
                log_action(db, "katana_error", user_id=job.user_id, 
                           details=f"Katana error: {str(e)[:200]}")

        # ============================================================================
        # PHASE 2: Nuclei Scan
        # ============================================================================
        job.progress_pct = 10.0
        db.commit()
        
        print(f"[Job {job_id}] Starting Nuclei scan...")
        
        # Build Nuclei command with appropriate mode
        target_argument = endpoints_file if endpoints_file else job.target_url
        is_list = bool(endpoints_file)
        
        cmd, nuclei_output_file = build_command(
            target_argument, job_id, is_list=is_list, scan_mode=job.scan_mode
        )
        job.nuclei_output_file = nuclei_output_file
        db.commit()

        # Check nuclei binary
        nuclei_bin = settings.NUCLEI_BIN
        if not os.path.isfile(nuclei_bin):
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
                job.finished_at = jakartanow()
                job.scan_duration_seconds = int((jakartanow() - start_time).total_seconds())
                db.commit()
                log_action(db, "scan_failed", user_id=job.user_id,
                           details=f"Nuclei not found (job {job_id})")
                return

        # Run Nuclei
        job.progress_pct = 15.0
        db.commit()

        try:
            custom_env = os.environ.copy()
            custom_env["GOMAXPROCS"] = "1"

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=custom_env,
            )
            job.pid = process.pid
            db.commit()

            # Set timeout based on scan mode
            timeout_map = {
                "fast": 1800,
                "deep": 3600,
                "comprehensive": settings.COMPREHENSIVE_SCAN_TIMEOUT,
            }
            timeout = timeout_map.get(job.scan_mode, 3600)
            stdout, stderr = process.communicate(timeout=timeout)
            returncode = process.returncode
            
            print(f"[Job {job_id}] Nuclei completed with return code {returncode}")

        except subprocess.TimeoutExpired:
            process.kill()
            job.status = JobStatus.FAILED
            job.error_message = f"Scan timed out after {timeout} seconds"
            job.finished_at = jakartanow()
            job.scan_duration_seconds = int((jakartanow() - start_time).total_seconds())
            db.commit()
            log_action(db, "scan_timeout", user_id=job.user_id,
                       details=f"Scan timed out (job {job_id})")
            return
        except Exception as e:
            job.error_message = f"Nuclei execution error: {str(e)[:500]}"
            print(f"[Job {job_id}] Nuclei error: {e}")

        # Check if job was stopped
        job = db.query(Job).filter(Job.id == job_id).first()
        if job.status == JobStatus.STOPPED:
            log_action(db, "scan_stopped", user_id=job.user_id,
                       details=f"Scan was stopped (job {job_id})")
            return

        # Parse Nuclei results
        job.progress_pct = 45.0
        db.commit()

        nuclei_findings = parse_output_file(nuclei_output_file)
        nuclei_stats = get_scan_stats(nuclei_output_file)
        
        job.nuclei_findings_count = len(nuclei_findings)
        all_findings.extend(nuclei_findings)
        
        print(f"[Job {job_id}] Nuclei found {len(nuclei_findings)} findings")
        
        log_action(db, "nuclei_completed", user_id=job.user_id,
                   details=f"Nuclei found {len(nuclei_findings)} findings (job {job_id})")

        # ============================================================================
        # PHASE 3: Xray Scan (for comprehensive mode or if enabled)
        # ============================================================================
        xray_available = check_xray_binary() is not None
        xray_findings = []  # Initialize here to avoid UnboundLocalError
        
        if xray_available and job.scan_mode in ("deep", "comprehensive"):
            job.progress_pct = 50.0
            db.commit()
            
            print(f"[Job {job_id}] Starting Xray scan...")
            
            try:
                # Run Xray scan
                xray_output_file, xray_pid = run_xray_scan(
                    job.target_url, 
                    job_id,
                    timeout=settings.XRAY_SCAN_TIMEOUT
                )
                
                if xray_pid:
                    job.xray_pid = xray_pid
                    db.commit()
                
                if xray_output_file and os.path.exists(xray_output_file):
                    job.xray_output_file = xray_output_file
                    db.commit()
                    
                    # Parse Xray results
                    xray_findings = parse_xray_output(xray_output_file)
                    job.xray_findings_count = len(xray_findings)
                    all_findings.extend(xray_findings)
                    
                    print(f"[Job {job_id}] Xray found {len(xray_findings)} findings")
                    
                    log_action(db, "xray_completed", user_id=job.user_id,
                               details=f"Xray found {len(xray_findings)} findings (job {job_id})")
                else:
                    print(f"[Job {job_id}] Xray produced no output")
                    
            except Exception as e:
                print(f"[Job {job_id}] Xray error: {e}")
                log_action(db, "xray_error", user_id=job.user_id,
                           details=f"Xray error: {str(e)[:200]}")
        else:
            if not xray_available:
                print(f"[Job {job_id}] Xray not available, skipping")
            else:
                print(f"[Job {job_id}] Xray skipped for {job.scan_mode} mode")

        # ============================================================================
        # PHASE 4: Save Results
        # ============================================================================
        job.progress_pct = 90.0
        db.commit()

        # Save all findings to database
        for fdata in all_findings:
            finding = Finding(
                job_id=job_id,
                source=fdata.get("source", "nuclei"),
                rule_id=fdata.get("rule_id"),
                name=fdata.get("name", "Unknown"),
                severity=fdata.get("severity", "info"),
                cwe=fdata.get("cwe"),
                owasp_category=fdata.get("owasp_category"),
                owasp_name=fdata.get("owasp_name"),
                description=fdata.get("description"),
                evidence=fdata.get("evidence"),
                matched_url=fdata.get("matched_url"),
                endpoint_path=fdata.get("endpoint_path"),
                http_method=fdata.get("http_method"),
                vulnerable_parameter=fdata.get("vulnerable_parameter"),
                parameter_location=fdata.get("parameter_location"),
                request_data=fdata.get("request_data"),
                response_data=fdata.get("response_data"),
                remediation=fdata.get("remediation"),
                references=fdata.get("references"),
                cvss_score=fdata.get("cvss_score"),
                cvss_vector=fdata.get("cvss_vector"),
                raw_json=fdata.get("raw_json"),
            )
            db.add(finding)

        # Calculate scan duration
        end_time = jakartanow()
        scan_duration = int((end_time - start_time).total_seconds())
        
        # Update job status
        job.status = JobStatus.COMPLETED
        job.progress_pct = 100.0
        job.findings_count = len(all_findings)
        job.finished_at = end_time
        job.scan_duration_seconds = scan_duration
        job.pid = None
        job.xray_pid = None
        
        # Check if nuclei failed but we got findings
        if not nuclei_findings and not xray_findings:
            # Check if there were execution errors
            if job.error_message:
                job.status = JobStatus.FAILED
        
        db.commit()

        # Format duration for log
        duration_str = f"{scan_duration // 60}m {scan_duration % 60}s"
        
        log_action(db, "scan_completed", user_id=job.user_id,
                   details=f"Scan completed for {job.target_url}: {len(all_findings)} findings in {duration_str} (job {job_id})")
        
        print(f"[Job {job_id}] Scan completed: {len(all_findings)} findings in {duration_str}")

    except Exception as e:
        # Handle unexpected errors
        error_trace = traceback.format_exc()
        print(f"[Job {job_id}] Fatal error: {e}\n{error_trace}")
        
        try:
            job = db.query(Job).filter(Job.id == job_id).first()
            if job:
                job.status = JobStatus.FAILED
                job.error_message = f"Internal error: {str(e)[:500]}"
                job.finished_at = jakartanow()
                job.scan_duration_seconds = int((jakartanow() - start_time).total_seconds())
                job.pid = None
                job.xray_pid = None
                db.commit()
                log_action(db, "scan_error", user_id=job.user_id,
                           details=f"Error in scan job {job_id}: {error_trace[:500]}")
        except Exception as inner_e:
            print(f"[Job {job_id}] Error in error handler: {inner_e}")
    finally:
        db.close()


def stop_scan_job(job_id: int, db: DBSession = None):
    """Stop a running scan job."""
    should_close_db = False
    if db is None:
        db = SessionLocal()
        should_close_db = True
    
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            return False
        
        stopped = False
        
        # Stop Nuclei process
        if job.pid:
            stopped = stop_process(job.pid) or stopped
            job.pid = None
        
        # Stop Xray process
        if job.xray_pid:
            stopped = stop_xray_process(job.xray_pid) or stopped
            job.xray_pid = None
        
        if stopped:
            job.status = JobStatus.STOPPED
            job.finished_at = jakartanow()
            db.commit()
            log_action(db, "scan_stopped", user_id=job.user_id,
                       details=f"Scan job {job_id} was stopped by user")
        
        return stopped
        
    finally:
        if should_close_db:
            db.close()
