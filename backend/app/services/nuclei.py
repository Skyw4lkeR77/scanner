"""Nuclei command builder, executor, and output parser."""
import json
import os
import subprocess
import signal
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from app.config import settings
from app.services.owasp_mapper import get_owasp_category


def build_command(target: str, job_id: int, options: dict = None) -> list[str]:
    """Build the nuclei CLI command."""
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"scan-{job_id}.json")

    cmd = [
        settings.NUCLEI_BIN,
        "-u", target,
        "-severity", "low,medium,high,critical",
        "-t", os.path.expanduser(settings.NUCLEI_TEMPLATES),
        "-j",
        "-rate-limit", str(settings.NUCLEI_RATE_LIMIT),
        "-c", str(settings.NUCLEI_CONCURRENCY),
        "-stats",
        "-o", output_file,
    ]

    # Add extra options if provided
    if options:
        if options.get("timeout"):
            cmd.extend(["-timeout", str(options["timeout"])])
        if options.get("retries"):
            cmd.extend(["-retries", str(options["retries"])])

    return cmd, output_file


def parse_nuclei_line(line: str) -> Optional[dict]:
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

    # Map to OWASP
    owasp_code, owasp_name = get_owasp_category(cwe_id=cwe_id, tags=tags)

    # Extract severity
    severity = info.get("severity", "info").lower()
    if severity not in ("info", "low", "medium", "high", "critical"):
        severity = "info"

    finding = {
        "rule_id": data.get("template-id", data.get("templateID", "")),
        "name": info.get("name", data.get("template-id", "Unknown")),
        "severity": severity,
        "cwe": cwe_id,
        "owasp_category": owasp_code,
        "owasp_name": owasp_name,
        "description": info.get("description", ""),
        "evidence": data.get("extracted-results", data.get("matcher-name", "")),
        "matched_url": data.get("matched-at", data.get("host", "")),
        "remediation": info.get("remediation", ""),
        "raw_json": line.strip(),
    }

    # Convert evidence to string if it's a list
    if isinstance(finding["evidence"], list):
        finding["evidence"] = "\n".join(str(e) for e in finding["evidence"])

    return finding


def parse_output_file(filepath: str) -> list[dict]:
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
