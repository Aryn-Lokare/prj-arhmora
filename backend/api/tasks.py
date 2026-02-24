import logging
from celery import shared_task
from django.contrib.auth.models import User
from .models import ScanHistory, ScanFinding
from .scanner.smart_crawler import SmartCrawler
from .scanner.scanner import ArmoraScanner

logger = logging.getLogger(__name__)


@shared_task(bind=True)
def run_web_scan(self, scan_history_id, target_url):
    """
    Armora v2 — Async scan task.

    Flow:
    1. Crawl the target.
    2. Run ArmoraScanner (Smart Detection Engine + Gemini Explainer).
    3. Save findings to the database.
    4. Mark scan as completed.
    """
    try:
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        scan_history.task_id = self.request.id
        scan_history.save()

        # 1. Crawl (Playwright for SPAs, falls back to static crawler)
        scan_history.current_step = "Crawling Target Endpoints..."
        scan_history.save()
        crawler = SmartCrawler(target_url, max_pages=10)
        crawled_data = crawler.crawl()

        # 2. Scan (Layer 1 + Layer 2)
        scan_history.current_step = "Analyzing HTTP Headers & Security Controls..."
        scan_history.save()
        scanner = ArmoraScanner(target_url)
        report = scanner.run(crawled_data)
        findings = report.get("findings", [])

        # 3. Save findings
        scan_history.current_step = "Processing Vulnerability Intelligence..."
        scan_history.save()
        for finding in findings:
            evidence_text = finding.get("evidence_text", "")
            explanation = finding.get("explanation", {})

            # Build remediation fields
            remediation = finding.get("remediation", "")
            remediation_simple = finding.get("remediation_simple", remediation)
            remediation_technical = finding.get("remediation_technical", remediation)

            # Gemini explanation fields (only populated for Confirmed)
            explanation_simple = explanation.get("executive_summary", "")
            explanation_technical = explanation.get("technical_explanation", "")

            # If Gemini provided remediation, prefer it
            if explanation.get("remediation"):
                remediation_technical = explanation["remediation"]

            # Improved confidence mapping
            conf_score = finding.get("confidence", 0)
            
            ScanFinding.objects.create(
                scan=scan_history,
                v_type=finding.get("type", "Unknown"),
                severity=finding.get("severity", "Medium"),
                affected_url=finding.get("affected_url", target_url),
                evidence=evidence_text,
                remediation=remediation,
                remediation_simple=remediation_simple,
                remediation_technical=remediation_technical,
                explanation_simple=explanation_simple,
                explanation_technical=explanation_technical,
                risk_score=conf_score,
                pattern_confidence=conf_score if conf_score < 100 else 100,
                exploit_confidence=70 if conf_score >= 70 else 0,
                response_confidence=20 if (conf_score % 70) >= 20 or conf_score == 20 else 0,
                total_confidence=conf_score,
                classification=finding.get("status", "Likely").lower(),
                detection_method="rule",
            )

        # 4. Complete
        scan_history.status = "Completed"
        scan_history.save()

        return (
            f"Scan {scan_history_id} completed: "
            f"{len(findings)} findings"
        )

    except Exception as e:
        logger.error(f"Async scan failed: {str(e)}", exc_info=True)
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            scan_history.status = "Failed"
            scan_history.save()
        except Exception:
            pass
        return f"Scan {scan_history_id} failed: {str(e)}"
