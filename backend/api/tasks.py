import logging
from celery import shared_task
from django.contrib.auth.models import User
from .models import ScanHistory, ScanFinding
from .scanner.crawler import Crawler
from .scanner.scanners import VulnerabilityScanner

logger = logging.getLogger(__name__)

@shared_task(bind=True)
def run_web_scan(self, scan_history_id, target_url):
    try:
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        scan_history.task_id = self.request.id
        scan_history.save()

        # 1. Initialize and run Crawler
        crawler = Crawler(target_url, max_pages=20) # Increased max_pages for async
        crawled_data = crawler.crawl()

        # 2. Initialize and run Vulnerability Scanner
        scanner = VulnerabilityScanner(target_url)
        findings = scanner.run_scans(crawled_data)

        # 3. Save findings to database
        for finding in findings:
            ScanFinding.objects.create(
                scan=scan_history,
                v_type=finding['type'],
                severity=finding['severity'],
                affected_url=finding['affected_url'],
                evidence=finding['evidence'],
                remediation=finding['remediation'],
                risk_score=finding.get('risk_score', 0),
                confidence=finding.get('confidence', 0.0),
                priority_rank=finding.get('priority_rank'),
                endpoint_sensitivity=finding.get('endpoint_sensitivity', 'public'),
                action_taken=finding.get('action_taken', 'flagged')
            )

        # 4. Update scan status
        scan_history.status = 'Completed'
        scan_history.save()
        
        return f"Scan {scan_history_id} completed successfully"

    except Exception as e:
        logger.error(f"Async scan failed: {str(e)}")
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            scan_history.status = 'Failed'
            scan_history.save()
        except:
            pass
        return f"Scan {scan_history_id} failed: {str(e)}"
