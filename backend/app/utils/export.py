"""Export findings to JSON/CSV formats."""
import csv
import io
import json
from typing import List
from app.models import Finding


def findings_to_json(findings: List[Finding]) -> str:
    """Export findings as JSON string."""
    data = []
    for f in findings:
        data.append({
            "id": f.id,
            "rule_id": f.rule_id,
            "name": f.name,
            "severity": f.severity,
            "cwe": f.cwe,
            "owasp_category": f.owasp_category,
            "owasp_name": f.owasp_name,
            "description": f.description,
            "evidence": f.evidence,
            "matched_url": f.matched_url,
            "remediation": f.remediation,
            "status": f.status,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })
    return json.dumps(data, indent=2, ensure_ascii=False)


def findings_to_csv(findings: List[Finding]) -> str:
    """Export findings as CSV string."""
    output = io.StringIO()
    fieldnames = [
        "id", "rule_id", "name", "severity", "cwe",
        "owasp_category", "owasp_name", "description",
        "evidence", "matched_url", "remediation", "status",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for f in findings:
        writer.writerow({
            "id": f.id,
            "rule_id": f.rule_id,
            "name": f.name,
            "severity": f.severity,
            "cwe": f.cwe,
            "owasp_category": f.owasp_category,
            "owasp_name": f.owasp_name,
            "description": f.description,
            "evidence": f.evidence,
            "matched_url": f.matched_url,
            "remediation": f.remediation,
            "status": f.status,
        })
    return output.getvalue()
