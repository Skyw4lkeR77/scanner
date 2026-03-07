"""Nuclei command builder, executor, and output parser."""
import json
import os
import subprocess
import signal
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from app.config import settings
from app.services.owasp_mapper import get_owasp_category


# Timezone Asia/Jakarta (WIB - UTC+7)
JAKARTA_TZ = timezone(timedelta(hours=7))


def build_command(target: str, job_id: int, options: dict = None, is_list: bool = False, 
                  scan_mode: str = "fast") -> tuple[List[str], str]:
    """
    Build the nuclei CLI command.
    
    Args:
        target: Target URL or file path
        job_id: Job ID for output file naming
        options: Additional options dict
        is_list: Whether target is a file containing URL list
        scan_mode: 'fast', 'deep', or 'comprehensive'
    """
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"scan-{job_id}.json")

    target_flag = "-l" if is_list else "-u"
    
    # Base command
    cmd = [
        settings.NUCLEI_BIN,
        target_flag, target,
        "-severity", "low,medium,high,critical",
        "-t", os.path.expanduser(settings.NUCLEI_TEMPLATES),
        "-j",  # JSON output
        "-duc",  # Disable update check
        "-stats",
        "-o", output_file,
    ]
    
    # Configure based on scan mode
    if scan_mode == "comprehensive":
        # Thorough but slower scanning
        cmd.extend([
            "-rate-limit", "30",  # Lower rate limit for thoroughness
            "-c", "3",  # Lower concurrency
            "-bs", "1",  # Bulk size
            "-hbs", "1",  # Host bulk size
            "-headc", "1",  # Headless concurrency
            "-timeout", "15",  # Longer timeout
            "-retries", "3",  # More retries
            "-no-interactsh",  # Disable interactsh for stability
        ])
    elif scan_mode == "deep":
        # Balanced deep scan
        cmd.extend([
            "-rate-limit", str(settings.NUCLEI_RATE_LIMIT),
            "-c", str(settings.NUCLEI_CONCURRENCY),
            "-bs", "2",
            "-hbs", "2",
            "-headc", "2",
            "-no-interactsh",
        ])
    else:  # fast mode
        cmd.extend([
            "-rate-limit", str(settings.NUCLEI_RATE_LIMIT * 2),  # Faster rate
            "-c", str(settings.NUCLEI_CONCURRENCY * 2),  # Higher concurrency
            "-bs", "5",
            "-hbs", "3",
            "-headc", "2",
            "-no-interactsh",
        ])

    # Add extra options if provided
    if options:
        if options.get("timeout"):
            cmd.extend(["-timeout", str(options["timeout"])])
        if options.get("retries"):
            cmd.extend(["-retries", str(options["retries"])])
        if options.get("templates"):
            cmd.extend(["-t", options["templates"]])
        if options.get("exclude_templates"):
            cmd.extend(["-exclude-templates", options["exclude_templates"]])

    return cmd, output_file


def parse_nuclei_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single JSON line from nuclei output."""
    try:
        data = json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    if not data:
        return None

    # Extract info block
    info = data.get("info", {})
    tags = info.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]

    # Extract CWE from classification
    classification = info.get("classification", {})
    cwe_list = classification.get("cwe-id", [])
    cwe_id = cwe_list[0] if cwe_list else None
    
    # Extract CVSS info
    cvss_score = None
    cvss_vector = None
    if classification:
        cvss_metrics = classification.get("cvss-metrics", "")
        if cvss_metrics:
            cvss_vector = cvss_metrics
        # Try to extract CVSS score from metrics or other fields
        cvss_score_raw = classification.get("cvss-score")
        if cvss_score_raw:
            try:
                cvss_score = float(cvss_score_raw)
            except (ValueError, TypeError):
                pass

    # Map to OWASP
    owasp_code, owasp_name = get_owasp_category(cwe_id=cwe_id, tags=tags)

    # Extract severity
    severity = info.get("severity", "info").lower()
    if severity not in ("info", "low", "medium", "high", "critical"):
        severity = "info"

    # Extract URL and endpoint details
    matched_at = data.get("matched-at", "")
    host = data.get("host", "")
    url = matched_at or host
    
    # Parse endpoint path from URL
    endpoint_path = ""
    http_method = data.get("method", "GET")
    
    if url:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            endpoint_path = parsed.path or "/"
        except:
            endpoint_path = url

    # Extract request/response if available
    request_data = data.get("request", "")
    response_data = data.get("response", "")
    
    # Extract parameter information
    param_key = ""
    param_location = ""
    
    # Try to extract from extracted-results or other fields
    extracted_results = data.get("extracted-results", [])
    if isinstance(extracted_results, list) and extracted_results:
        param_info = extracted_results[0]
        if isinstance(param_info, dict):
            param_key = param_info.get("param", "")
            param_location = param_info.get("location", "")
    
    # Extract matcher name as evidence
    matcher_name = data.get("matcher-name", "")
    
    # Build evidence string
    evidence_parts = []
    if matcher_name:
        evidence_parts.append(f"Matcher: {matcher_name}")
    if extracted_results:
        if isinstance(extracted_results, list):
            evidence_parts.append(f"Extracted: {', '.join(str(r) for r in extracted_results[:5])}")
        else:
            evidence_parts.append(f"Extracted: {extracted_results}")
    
    evidence = "\n".join(evidence_parts) if evidence_parts else ""

    # Get references
    references = info.get("reference", [])
    if isinstance(references, str):
        references = [r.strip() for r in references.split(",") if r.strip()]

    finding = {
        "source": "nuclei",
        "rule_id": data.get("template-id", data.get("templateID", "")),
        "name": info.get("name", data.get("template-id", "Unknown")),
        "severity": severity,
        "cwe": cwe_id,
        "owasp_category": owasp_code,
        "owasp_name": owasp_name,
        "description": info.get("description", ""),
        "evidence": evidence,
        "matched_url": url,
        "endpoint_path": endpoint_path,
        "http_method": http_method,
        "vulnerable_parameter": param_key,
        "parameter_location": param_location,
        "request_data": request_data,
        "response_data": response_data,
        "remediation": info.get("remediation", ""),
        "references": json.dumps(references) if references else "[]",
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "raw_json": line.strip(),
    }

    return finding


def parse_output_file(filepath: str) -> List[Dict[str, Any]]:
    """Parse the nuclei JSON output file (one JSON object per line)."""
    findings = []
    if not os.path.exists(filepath):
        return findings

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            finding = parse_nuclei_line(line)
            if finding:
                findings.append(finding)

    return findings


def stop_process(pid: int) -> bool:
    """Stop a running nuclei process."""
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=10)
        else:
            os.kill(pid, signal.SIGTERM)
        return True
    except (ProcessLookupError, OSError, subprocess.TimeoutExpired):
        return False


def get_scan_stats(output_file: str) -> Dict[str, Any]:
    """Get statistics from nuclei scan output."""
    stats = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "templates_used": 0,
    }
    
    if not os.path.exists(output_file):
        return stats
    
    templates = set()
    
    with open(output_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                stats["total"] += 1
                
                severity = data.get("info", {}).get("severity", "info").lower()
                if severity in stats:
                    stats[severity] += 1
                
                template_id = data.get("template-id", data.get("templateID", ""))
                if template_id:
                    templates.add(template_id)
                    
            except json.JSONDecodeError:
                continue
    
    stats["templates_used"] = len(templates)
    return stats
