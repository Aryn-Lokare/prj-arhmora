# Test script for AI Scanner
from api.scanner.scanners import VulnerabilityScanner

def test_ai_scanner():
    target = "http://example.com"
    scanner = VulnerabilityScanner(target)
    
    # Mock crawled data with mixed URLs
    crawled_data = {
        'visited_urls': [
            "http://example.com/login",                                     # Normal
            "http://example.com/search?q=<script>alert(1)</script>",         # XSS
            "http://example.com/download?file=../../../../etc/passwd",      # Path Traversal
            "http://example.com/user?id=1' OR '1'='1"                       # SQLi
        ]
    }
    
    print(f"Running scans on {target}...")
    findings = scanner.run_scans(crawled_data)
    
    print(f"\nTotal Findings: {len(findings)}")
    ai_findings = [f for f in findings if f['type'] == 'AI-Detected Anomaly']
    print(f"AI-Detected Findings: {len(ai_findings)}")
    
    for finding in findings:
        print(f"[{finding['severity']}] {finding['type']} on {finding['affected_url']}")
        if finding['type'] == 'AI-Detected Anomaly':
            print(f"  > Evidence: {finding['evidence']}")

if __name__ == "__main__":
    test_ai_scanner()
