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
        crawler = Crawler(target_url, max_pages=20)
        crawled_data = crawler.crawl()

        # 2. Initialize and run Vulnerability Scanner
        scanner = VulnerabilityScanner(target_url)
        findings = scanner.run_scans(crawled_data)

        # 3. Save findings to database with multi-factor confidence
        created_finding_ids = []
        for finding in findings:
            scan_finding = ScanFinding.objects.create(
                scan=scan_history,
                v_type=finding['type'],
                severity=finding['severity'],
                affected_url=finding['affected_url'],
                evidence=finding['evidence'],
                remediation=finding['remediation'],
                remediation_simple=finding.get('remediation_simple', ''),
                remediation_technical=finding.get('remediation_technical', ''),
                risk_score=finding.get('risk_score', 0),
                priority_rank=finding.get('priority_rank'),
                endpoint_sensitivity=finding.get('endpoint_sensitivity', 'public'),
                # Multi-factor confidence
                pattern_confidence=finding.get('pattern_confidence', 0),
                response_confidence=finding.get('response_confidence', 0),
                exploit_confidence=finding.get('exploit_confidence', 0),
                context_confidence=finding.get('context_confidence', 0),
                total_confidence=finding.get('total_confidence', 0),
                classification=finding.get('classification', 'suspicious'),
                validation_status='pending',
            )
            created_finding_ids.append(scan_finding.id)

        # 4. Trigger async validation for each finding
        for finding_id in created_finding_ids:
            validate_finding.delay(finding_id)

        # 5. Update scan status
        scan_history.status = 'Completed'
        scan_history.save()
        
        return f"Scan {scan_history_id} completed with {len(findings)} findings"

    except Exception as e:
        logger.error(f"Async scan failed: {str(e)}")
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            scan_history.status = 'Failed'
            scan_history.save()
        except:
            pass
        return f"Scan {scan_history_id} failed: {str(e)}"


@shared_task
def validate_finding(finding_id: int):
    """
    Validate a single finding using controlled payloads.
    Runs asynchronously after initial detection.
    """
    from .scanner.validation_engine import ValidationEngine
    from .scanner.confidence_engine import MultiFactorConfidenceEngine
    
    try:
        finding = ScanFinding.objects.get(id=finding_id)
        validator = ValidationEngine()
        confidence_engine = MultiFactorConfidenceEngine()
        
        # Run validation
        validation_result = validator.validate_finding(finding.v_type, finding.affected_url)
        
        # Update exploit confidence based on validation
        if validation_result:
            exploit_conf = confidence_engine.calculate_exploit_confidence(
                finding.v_type, validation_result
            )
            finding.exploit_confidence = exploit_conf
            
            # Determine validation status
            if validation_result.get('validated', False):
                finding.validation_status = 'validated'
            elif validation_result.get('payload_reflected') or validation_result.get('differential_confirmed'):
                finding.validation_status = 'partial'
            else:
                finding.validation_status = 'failed'
                # Downgrade severity if not validated and originally high
                if finding.severity == 'High' and exploit_conf < 10:
                    finding.severity = 'Medium'
        
        # Recalculate total confidence and classification
        total_conf, classification = confidence_engine.calculate_total_confidence(
            finding.pattern_confidence,
            finding.response_confidence,
            finding.exploit_confidence,
            finding.context_confidence
        )
        finding.total_confidence = total_conf
        finding.classification = classification
        finding.save()
        
        logger.info(f"Validated finding {finding_id}: {finding.validation_status}, conf={total_conf}%")
        return f"Validated finding {finding_id}: {finding.validation_status}"
        
    except ScanFinding.DoesNotExist:
        logger.warning(f"Finding {finding_id} not found for validation")
        return f"Finding {finding_id} not found"
    except Exception as e:
        logger.error(f"Validation failed for finding {finding_id}: {e}")
        return f"Validation failed: {e}"
