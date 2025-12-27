from datetime import datetime

class ReportBuilder:
    def __init__(self, target_url, scanned_by):
        self.target_url = target_url
        self.scanned_by = scanned_by
        self.timestamp = datetime.now().isoformat()
        self.project_name = "Security Scan Project" # Can be made dynamic

    def build_json_report(self, findings):
        severity_counts = {
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'Low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        total_vulnerabilities = len(findings)
        
        executive_summary = (
            f"A security scan was performed on {self.target_url} at {self.timestamp}. "
            f"The scan identified {total_vulnerabilities} vulnerabilities."
        )

        report = {
            "project_name": self.project_name,
            "target_url": self.target_url,
            "scan_timestamp": self.timestamp,
            "scanned_by": str(self.scanned_by),
            "executive_summary": executive_summary,
            "total_vulnerabilities": total_vulnerabilities,
            "severity_breakdown": severity_counts,
            "detailed_findings": findings
        }

        return report
