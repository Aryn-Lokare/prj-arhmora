import logging
from celery import shared_task, chord
from django.contrib.auth.models import User
from .models import ScanHistory, ScanFinding
from .scanner.smart_crawler import SmartCrawler
from .scanner.scanner import ArmoraScanner
from .scanner.detectors import ALL_DETECTORS

logger = logging.getLogger(__name__)


@shared_task(bind=True)
def run_web_scan(self, scan_history_id, target_url):
    """
    Armora v2 (Distributed) — Async entry point.
    """
    import os
    worker_name = os.environ.get('HOSTNAME', 'default-worker')
    
    try:
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        scan_history.task_id = self.request.id
        scan_history.worker_name = worker_name
        scan_history.current_step = "Crawling Target Endpoints..."
        scan_history.save()

        # 1. Crawl
        crawler = SmartCrawler(target_url, max_pages=10)
        crawled_data = crawler.crawl()
        
        _update_heartbeat(scan_history_id)
        
        # 2. Setup Scanner and Framework Detection
        from .scanner.intelligence.framework_detector import detect_framework
        scanner = ArmoraScanner(target_url)
        basic_findings, target_resp = scanner.run_basic_checks(target_url)
        
        framework = "Unknown"
        if target_resp:
            framework = detect_framework(target_resp.get("headers", {}), target_resp.get("body", ""))
            scan_history.current_step = f"Stack Detected: {framework}. Starting parallel scan..."
            scan_history.save()
        
        # 3. Generate Layer 1 Sub-tasks
        tasks = scanner.engine.generate_scan_tasks(
            crawled_data.get("visited_urls", []),
            crawled_data.get("forms", []),
            framework=framework
        )

        if not tasks:
            return finalize_distributed_scan(
                [{"findings": basic_findings}], 
                scan_history_id, 
                target_url
            )

        # 4. Dispatch Chord
        callback = finalize_distributed_scan.s(scan_history_id, target_url, basic_findings)
        header = [run_detector_subtask.s(t) for t in tasks]
        
        return chord(header)(callback)

    except Exception as e:
        logger.error(f"Distributed scan dispatch failed: {str(e)}", exc_info=True)
        _mark_failed(scan_history_id, str(e))
        return f"Scan {scan_history_id} failed at dispatch"


@shared_task
def run_detector_subtask(task_def: dict):
    """
    Worker task: Runs ONE detector against ONE parameter set.
    Includes framework-specific mutation tips (Level Up).
    """
    from .scanner.detectors import SQLiDetector, XSSDetector, SSRFDetector, LFIDetector, RCEDetector
    from .scanner.intelligence.payload_optimizer import get_mutation_tips
    
    mapping = {
        "SQLiDetector": SQLiDetector,
        "XSSDetector": XSSDetector,
        "SSRFDetector": SSRFDetector,
        "LFIDetector": LFIDetector,
        "RCEDetector": RCEDetector
    }
    
    cls = mapping.get(task_def["detector_class"])
    if not cls:
        return {"findings": []}
    
    detector = cls()
    framework = task_def.get("framework", "Unknown")
    
    # Pillar 4: LEVEL UP - Add framework mutations
    mutation_tips = get_mutation_tips(framework, detector.vuln_type)
    
    try:
        # We need to update detector.detect to accept extra_payloads/mutation_tips
        findings = detector.detect(
            task_def["url"], 
            task_def["params"], 
            extra_payloads=mutation_tips
        )
        
        for f in findings:
            f["affected_url"] = task_def["original_url"]
        return {"findings": findings}
    except Exception as exc:
        logger.error(f"Subtask {task_def.get('id')} failed: {exc}")
        return {"findings": []}


@shared_task
def finalize_distributed_scan(results, scan_history_id, target_url, basic_findings=None):
    """
    Callback: Aggregates all subtask results, runs Layer 2 (Gemini), and saves.
    """
    try:
        _update_heartbeat(scan_history_id)
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        scan_history.current_step = "Processing Vulnerability Intelligence..."
        scan_history.save()

        # 1. Aggregate Findings
        all_findings = basic_findings or []
        for res in results:
            all_findings.extend(res.get("findings", []))

        # 2. Layer 2: Gemini Explainer (Enrichment)
        scanner = ArmoraScanner(target_url)
        unique_findings = scanner.engine._deduplicate(all_findings)
        
        enriched = []
        for f in unique_findings:
            e = scanner.enrich_finding(f)
            enriched.append(e)

        confirmed = [f for f in enriched if f.get("status") == "Confirmed"]
        if confirmed:
            scanner.attach_gemini_explanations(confirmed)
        
        # 3. Save to DB
        for finding in enriched:
            _save_finding(scan_history, finding, target_url)

        # 4. Finish
        scan_history.status = "Completed"
        scan_history.current_step = "All Checks Finished"
        scan_history.save()

        return f"Scan {scan_history_id} completed: {len(enriched)} findings"

    except Exception as e:
        logger.error(f"Scan finalization failed: {str(e)}", exc_info=True)
        _mark_failed(scan_history_id, str(e))
        return f"Scan {scan_history_id} failed at finalization"


def _update_heartbeat(scan_history_id):
    """Update the last_heartbeat timestamp to show the scan is still alive."""
    try:
        from django.utils import timezone
        ScanHistory.objects.filter(id=scan_history_id).update(last_heartbeat=timezone.now())
    except Exception:
        logger.warning(f"Failed to update heartbeat for scan {scan_history_id}", exc_info=True)


def _save_finding(scan_history, finding, target_url):
    """Heper to save a finding dict to the database."""
    explanation = finding.get("explanation", {})
    remediation = finding.get("remediation", "")
    
    ScanFinding.objects.create(
        scan=scan_history,
        v_type=finding.get("type", "Unknown"),
        severity=finding.get("severity", "Medium"),
        affected_url=finding.get("affected_url", target_url),
        evidence=finding.get("evidence_text", ""),
        remediation=remediation,
        remediation_simple=finding.get("remediation_simple", remediation),
        remediation_technical=finding.get("remediation_technical", remediation),
        explanation_simple=explanation.get("executive_summary", ""),
        explanation_technical=explanation.get("technical_explanation", ""),
        risk_score=finding.get("confidence", 0),
        total_confidence=finding.get("confidence", 0),
        classification=_map_status_to_classification(finding.get("status", "Likely")),
        detection_method="hybrid",
    )


def _mark_failed(scan_history_id, error_msg):
    try:
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        scan_history.status = "Failed"
        scan_history.save()
    except Exception:
        logger.error(f"Failed to mark scan {scan_history_id} as failed", exc_info=True)


def _map_status_to_classification(status: str) -> str:
    mapping = {
        'confirmed': 'confirmed',
        'likely': 'likely',
        'discard': 'suspicious',
    }
    return mapping.get(status.lower(), 'suspicious')
