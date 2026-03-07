"""Xray scanner integration service (Chaitin Xray)."""
import json
import os
import subprocess
import shutil
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from app.config import settings


# Timezone Asia/Jakarta (WIB - UTC+7)
JAKARTA_TZ = timezone(timedelta(hours=7))


def check_xray_binary() -> Optional[str]:
    """Check if Xray binary exists and return the path."""
    xray_bin = settings.XRAY_BIN
    
    if os.path.isfile(xray_bin):
        return xray_bin
    
    # Try to find xray in PATH
    xray_path = shutil.which("xray")
    if xray_path:
        return xray_path
    
    # Try common locations
    common_paths = [
        "/usr/local/bin/xray",
        "/usr/bin/xray",
        os.path.expanduser("~/xray/xray"),
        os.path.expanduser("~/tools/xray/xray"),
        "./xray/xray",
    ]
    for path in common_paths:
        if os.path.isfile(path):
            return path
    
    return None


def build_xray_command(target: str, job_id: int, plugins: str = None) -> tuple[List[str], str]:
    """Build the Xray CLI command for webscan."""
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"xray-scan-{job_id}.json")
    
    xray_bin = check_xray_binary()
    if not xray_bin:
        raise FileNotFoundError("Xray binary not found. Please install Xray from https://docs.xray.cool/")
    
    # Use basic-crawler mode for comprehensive scanning
    cmd = [
        xray_bin,
        "webscan",
        "--basic-crawler", target,
        "--json-output", output_file,
    ]
    
    # Add plugins if specified
    if plugins:
        cmd.extend(["--plugins", plugins])
    elif settings.XRAY_PLUGINS:
        cmd.extend(["--plugins", settings.XRAY_PLUGINS])
    
    return cmd, output_file


def run_xray_scan(target: str, job_id: int, plugins: str = None, timeout: int = None) -> tuple[str, Optional[int]]:
    """
    Run Xray scan on a target.
    
    Returns:
        tuple: (output_file_path, process_pid or None)
    """
    xray_bin = check_xray_binary()
    if not xray_bin:
        print("Xray binary not found. Skipping Xray scan.")
        return None, None
    
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"xray-scan-{job_id}.json")
    html_output = os.path.join(settings.SCAN_OUTPUT_DIR, f"xray-scan-{job_id}.html")
    
    # Build command with multiple output formats
    cmd = [
        xray_bin,
        "webscan",
        "--basic-crawler", target,
        "--json-output", output_file,
        "--html-output", html_output,
    ]
    
    # Add plugins if specified
    if plugins:
        cmd.extend(["--plugins", plugins])
    elif settings.XRAY_PLUGINS:
        cmd.extend(["--plugins", settings.XRAY_PLUGINS])
    
    try:
        # Prevent OS thread panic on VPS
        custom_env = os.environ.copy()
        custom_env["GOMAXPROCS"] = "1"
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=custom_env,
        )
        
        pid = process.pid
        
        # Wait for completion with timeout
        scan_timeout = timeout or settings.XRAY_SCAN_TIMEOUT
        stdout, stderr = process.communicate(timeout=scan_timeout)
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return output_file, pid
        
        return None, pid
        
    except subprocess.TimeoutExpired:
        process.kill()
        print(f"Xray scan timed out after {timeout} seconds")
        return output_file if os.path.exists(output_file) else None, pid if 'pid' in locals() else None
    except Exception as e:
        print(f"Xray execution failed: {e}")
        return None, None


def parse_xray_output(filepath: str) -> List[Dict[str, Any]]:
    """Parse Xray JSON output file."""
    findings = []
    
    if not os.path.exists(filepath):
        return findings
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
            if not content:
                return findings
            
            # Xray outputs one JSON object per line
            for line in content.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    finding = parse_xray_finding(data)
                    if finding:
                        findings.append(finding)
                except json.JSONDecodeError:
                    continue
                    
    except Exception as e:
        print(f"Error parsing Xray output: {e}")
    
    return findings


def parse_xray_finding(data: Dict) -> Optional[Dict[str, Any]]:
    """Parse a single Xray finding from JSON."""
    if not data:
        return None
    
    # Extract vulnerability details
    vuln_type = data.get("vuln_type", "unknown")
    target = data.get("target", {})
    detail = data.get("detail", {})
    
    # Map Xray severity to our severity levels
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium", 
        "low": "low",
        "info": "info",
    }
    xray_severity = data.get("severity", "info").lower()
    severity = severity_map.get(xray_severity, "info")
    
    # Extract URL and endpoint information
    url = target.get("url", "")
    path = target.get("path", "")
    method = target.get("method", "GET")
    
    # Extract parameter information
    param = detail.get("param", {})
    param_key = param.get("key", "") if isinstance(param, dict) else ""
    param_position = param.get("position", "") if isinstance(param, dict) else ""
    
    # Extract request/response
    request_data = detail.get("request", "")
    response_data = detail.get("response", "")
    
    # Extract payload
    payload = detail.get("payload", "")
    
    # Build evidence string
    evidence_parts = []
    if payload:
        evidence_parts.append(f"Payload: {payload}")
    if param_key:
        evidence_parts.append(f"Parameter: {param_key} ({param_position})")
    
    evidence = "\n".join(evidence_parts) if evidence_parts else detail.get("snapshot", "")
    
    # Get plugin/vulnerability name
    plugin = data.get("plugin", vuln_type)
    
    # Build description
    description = detail.get("description", f"Xray detected {vuln_type} vulnerability")
    
    # Map to CWE based on vulnerability type
    cwe_map = {
        "sqldet": "CWE-89",
        "sql-injection": "CWE-89",
        "xss": "CWE-79",
        "cmd-injection": "CWE-78",
        "command-injection": "CWE-78",
        "dirscan": "CWE-548",
        "path-traversal": "CWE-22",
        "xxe": "CWE-611",
        "upload": "CWE-434",
        "ssrf": "CWE-918",
        "jsonp": "CWE-942",
        "redirect": "CWE-601",
        "crlf-injection": "CWE-93",
        "baseline": "CWE-693",
        "brute-force": "CWE-307",
    }
    cwe = cwe_map.get(vuln_type.lower(), "")
    
    # Build finding dictionary
    finding = {
        "source": "xray",
        "rule_id": plugin,
        "name": f"[Xray] {vuln_type}",
        "severity": severity,
        "cwe": cwe,
        "description": description,
        "evidence": evidence,
        "matched_url": url,
        "endpoint_path": path,
        "http_method": method,
        "vulnerable_parameter": param_key,
        "parameter_location": param_position,
        "request_data": request_data,
        "response_data": response_data,
        "remediation": get_remediation(vuln_type),
        "references": get_references(vuln_type),
        "raw_json": json.dumps(data),
    }
    
    return finding


def get_remediation(vuln_type: str) -> str:
    """Get remediation advice for vulnerability type."""
    remediations = {
        "sqldet": "Use parameterized queries/prepared statements. Validate and sanitize all user input. Implement least privilege database access.",
        "sql-injection": "Use parameterized queries/prepared statements. Validate and sanitize all user input.",
        "xss": "Encode all user output based on context. Implement Content Security Policy (CSP). Use modern frameworks that auto-escape.",
        "cmd-injection": "Avoid executing system commands with user input. Use parameterized APIs. Validate input against whitelist.",
        "dirscan": "Remove or restrict access to sensitive files. Implement proper access controls. Use .htaccess or web.config restrictions.",
        "path-traversal": "Validate and sanitize file paths. Use allowlists for acceptable paths. Avoid passing user input to file system APIs.",
        "xxe": "Disable external entities in XML parsers. Use JSON instead of XML when possible. Validate XML input.",
        "upload": "Validate file types by content, not extension. Store uploads outside web root. Rename uploaded files. Scan for malware.",
        "ssrf": "Validate and sanitize URLs. Use allowlists for allowed destinations. Disable unnecessary URL schemas.",
        "jsonp": "Migrate to CORS instead of JSONP. Validate callback function names. Implement proper content-type headers.",
        "redirect": "Validate redirect URLs against allowlist. Use relative URLs. Avoid passing user input to redirect functions.",
        "crlf-injection": "Sanitize input by removing CRLF characters. Validate and encode headers. Use framework-provided redirect methods.",
        "baseline": "Implement security headers (HSTS, CSP, X-Frame-Options, etc.). Disable insecure protocols. Keep software updated.",
        "brute-force": "Implement rate limiting. Use CAPTCHA after failed attempts. Implement account lockout policies. Use strong password requirements.",
    }
    return remediations.get(vuln_type.lower(), "Review and fix according to security best practices.")


def get_references(vuln_type: str) -> str:
    """Get reference URLs for vulnerability type as JSON string."""
    references = {
        "sqldet": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ],
        "sql-injection": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://portswigger.net/web-security/sql-injection"
        ],
        "xss": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ],
        "cmd-injection": [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
        ],
        "path-traversal": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://portswigger.net/web-security/file-path-traversal"
        ],
        "xxe": [
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://portswigger.net/web-security/xxe"
        ],
        "ssrf": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://portswigger.net/web-security/ssrf"
        ],
        "upload": [
            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
        ],
    }
    refs = references.get(vuln_type.lower(), ["https://docs.xray.cool/"])
    return json.dumps(refs)


def stop_xray_process(pid: int) -> bool:
    """Stop a running Xray process."""
    try:
        if os.name == "nt":  # Windows
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                          capture_output=True, timeout=10)
        else:  # Unix/Linux/Mac
            os.kill(pid, 9)  # SIGKILL
        return True
    except (ProcessLookupError, OSError, subprocess.TimeoutExpired):
        return False
