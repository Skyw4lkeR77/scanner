"""Export findings to JSON/CSV formats."""
import csv
import io
import json
from typing import List
from app.models import Finding


def findings_to_json(findings: List[Finding]) -> str:
    """Export findings as JSON string with enhanced details."""
    data = []
    for f in findings:
        finding_data = {
            # Basic info
            "id": f.id,
            "source": f.source,
            "rule_id": f.rule_id,
            "name": f.name,
            "severity": f.severity,
            "status": f.status,
            
            # Classification
            "cwe": f.cwe,
            "owasp_category": f.owasp_category,
            "owasp_name": f.owasp_name,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            
            # Details
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "references": json.loads(f.references) if f.references else [],
            
            # Endpoint info
            "matched_url": f.matched_url,
            "endpoint_path": f.endpoint_path,
            "http_method": f.http_method,
            
            # Parameter info
            "vulnerable_parameter": f.vulnerable_parameter,
            "parameter_location": f.parameter_location,
            
            # Request/Response
            "request_data": f.request_data,
            "response_data": f.response_data,
            
            # Metadata
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "raw_json": f.raw_json,
        }
        data.append(finding_data)
    
    return json.dumps(data, indent=2, ensure_ascii=False)


def findings_to_csv(findings: List[Finding]) -> str:
    """Export findings as CSV string with enhanced details."""
    output = io.StringIO()
    fieldnames = [
        "id", "source", "rule_id", "name", "severity", "status",
        "cwe", "owasp_category", "owasp_name", "cvss_score",
        "description", "evidence", "remediation", "references",
        "matched_url", "endpoint_path", "http_method",
        "vulnerable_parameter", "parameter_location",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for f in findings:
        # Parse references for CSV
        refs = ""
        if f.references:
            try:
                ref_list = json.loads(f.references)
                refs = "; ".join(ref_list) if isinstance(ref_list, list) else f.references
            except:
                refs = f.references
        
        writer.writerow({
            "id": f.id,
            "source": f.source,
            "rule_id": f.rule_id,
            "name": f.name,
            "severity": f.severity,
            "status": f.status,
            "cwe": f.cwe,
            "owasp_category": f.owasp_category,
            "owasp_name": f.owasp_name,
            "cvss_score": f.cvss_score,
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "references": refs,
            "matched_url": f.matched_url,
            "endpoint_path": f.endpoint_path,
            "http_method": f.http_method,
            "vulnerable_parameter": f.vulnerable_parameter,
            "parameter_location": f.parameter_location,
        })
    
    return output.getvalue()


def findings_to_html(findings: List[Finding], job) -> str:
    """Export findings as HTML report."""
    html_parts = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<meta charset='utf-8'>",
        "<title>Scan Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }",
        ".container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }",
        ".header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }",
        ".severity-critical { color: #dc3545; font-weight: bold; }",
        ".severity-high { color: #fd7e14; font-weight: bold; }",
        ".severity-medium { color: #ffc107; font-weight: bold; }",
        ".severity-low { color: #17a2b8; font-weight: bold; }",
        ".severity-info { color: #6c757d; }",
        ".finding { border: 1px solid #ddd; margin-bottom: 20px; padding: 20px; border-radius: 4px; }",
        ".finding-header { background: #f8f9fa; padding: 10px; margin: -20px -20px 15px -20px; border-radius: 4px 4px 0 0; }",
        ".finding-title { font-size: 18px; font-weight: bold; margin: 0; }",
        ".metadata { color: #666; font-size: 14px; margin-top: 5px; }",
        ".section { margin: 15px 0; }",
        ".section-title { font-weight: bold; color: #333; margin-bottom: 5px; }",
        ".code { background: #f4f4f4; padding: 10px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; word-break: break-all; }",
        ".badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 5px; }",
        ".badge-source-nuclei { background: #e3f2fd; color: #1976d2; }",
        ".badge-source-xray { background: #fce4ec; color: #c2185b; }",
        "</style>",
        "</head>",
        "<body>",
        "<div class='container'>",
    ]
    
    # Header
    html_parts.append("<div class='header'>")
    html_parts.append(f"<h1>Security Scan Report</h1>")
    html_parts.append(f"<p><strong>Target:</strong> {job.target_url if job else 'N/A'}</p>")
    html_parts.append(f"<p><strong>Scan Mode:</strong> {job.scan_mode if job else 'N/A'}</p>")
    html_parts.append(f"<p><strong>Total Findings:</strong> {len(findings)}</p>")
    html_parts.append("</div>")
    
    # Findings
    for f in findings:
        severity_class = f"severity-{f.severity}" if f.severity else "severity-info"
        source_class = f"badge-source-{f.source}" if f.source else ""
        
        html_parts.append("<div class='finding'>")
        
        # Header
        html_parts.append("<div class='finding-header'>")
        html_parts.append(f"<h3 class='finding-title {severity_class}'>{f.name}</h3>")
        html_parts.append("<div class='metadata'>")
        html_parts.append(f"<span class='badge {source_class}'>{f.source.upper()}</span>")
        html_parts.append(f"Severity: {f.severity.upper()} | ")
        if f.cwe:
            html_parts.append(f"CWE: {f.cwe} | ")
        if f.owasp_category:
            html_parts.append(f"OWASP: {f.owasp_category}")
        html_parts.append("</div>")
        html_parts.append("</div>")
        
        # Description
        if f.description:
            html_parts.append("<div class='section'>")
            html_parts.append("<div class='section-title'>Description</div>")
            html_parts.append(f"<p>{f.description}</p>")
            html_parts.append("</div>")
        
        # URL and Endpoint
        if f.matched_url:
            html_parts.append("<div class='section'>")
            html_parts.append("<div class='section-title'>Affected URL</div>")
            html_parts.append(f"<p><code>{f.matched_url}</code></p>")
            if f.endpoint_path:
                html_parts.append(f"<p>Endpoint: <code>{f.endpoint_path}</code></p>")
            if f.http_method:
                html_parts.append(f"<p>Method: {f.http_method}</p>")
            html_parts.append("</div>")
        
        # Parameter
        if f.vulnerable_parameter:
            html_parts.append("<div class='section'>")
            html_parts.append("<div class='section-title'>Vulnerable Parameter</div>")
            html_parts.append(f"<p>Name: <code>{f.vulnerable_parameter}</code></p>")
            if f.parameter_location:
                html_parts.append(f"<p>Location: {f.parameter_location}</p>")
            html_parts.append("</div>")
        
        # Evidence
        if f.evidence:
            html_parts.append("<div class='section'>")
            html_parts.append("<div class='section-title'>Evidence</div>")
            html_parts.append(f"<div class='code'>{f.evidence}</div>")
            html_parts.append("</div>")
        
        # Remediation
        if f.remediation:
            html_parts.append("<div class='section'>")
            html_parts.append("<div class='section-title'>Remediation</div>")
            html_parts.append(f"<p>{f.remediation}</p>")
            html_parts.append("</div>")
        
        # CVSS
        if f.cvss_score:
            html_parts.append("<div class='section'>")
            html_parts.append("<div class='section-title'>CVSS Score</div>")
            html_parts.append(f"<p>Score: {f.cvss_score}</p>")
            if f.cvss_vector:
                html_parts.append(f"<p>Vector: {f.cvss_vector}</p>")
            html_parts.append("</div>")
        
        html_parts.append("</div>")  # End finding
    
    html_parts.append("</div>")  # End container
    html_parts.append("</body>")
    html_parts.append("</html>")
    
    return "\n".join(html_parts)
