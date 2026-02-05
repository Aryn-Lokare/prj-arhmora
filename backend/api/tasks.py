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
        raw_findings = scanner.run_scans(crawled_data)
        
        # 3. Deduplicate findings
        from .scanner.deduplication import deduplicate_findings
        deduplicated_result = deduplicate_findings(
            raw_findings, 
            crawled_data.get('visited_urls', [])
        )
        
        vulnerabilities = deduplicated_result['vulnerabilities']
        summary = deduplicated_result['scan_summary']
        logger.info(f"Scan summary: {summary}")

        # 4. Save DEDUPLICATED findings to database
        created_finding_ids = []
        for vuln in vulnerabilities:
            # Construct rich evidence string with all affected endpoints
            evidence_summary = [
                f"### Root Cause\n{vuln['root_cause']}\n",
                f"### Affected Endpoints ({vuln['occurrences']})",
                *[f"- {ep}" for ep in vuln['affected_endpoints'][:10]],
            ]
            if len(vuln['affected_endpoints']) > 10:
                evidence_summary.append(f"... and {len(vuln['affected_endpoints']) - 10} more")
            
            # Add primary evidence details
            if vuln['evidence']:
                primary = vuln['evidence'][0]
                evidence_summary.extend([
                    f"\n### Evidence (Primary: {primary['endpoint']})",
                    f"Payload: `{primary['payload']}`",
                    f"Response: `{primary.get('response', '')[:200]}`"
                ])
                
            full_evidence = "\n".join(evidence_summary)

            # Use primary endpoint for the record
            primary_endpoint = vuln['evidence'][0]['full_url'] if vuln['evidence'] else target_url

            scan_finding = ScanFinding.objects.create(
                scan=scan_history,
                v_type=vuln['type'],
                severity=vuln['severity'],
                affected_url=primary_endpoint,
                evidence=full_evidence,
                remediation=vuln['remediation'],
                remediation_simple=vuln.get('remediation_simple', ''),
                remediation_technical=vuln.get('remediation_technical', ''),
                risk_score=vuln.get('risk', 0),
                priority_rank=0, # Calculated later if needed
                endpoint_sensitivity='public', # Default/Assumed
                # Store max info
                total_confidence=int(vuln['confidence']),
                classification='likely', # Default for AI/Rule matches
                validation_status='pending',
                detection_method=vuln['detection_method'],
                # Store structured data if JSON field available, else relying on text evidence
            )
            created_finding_ids.append(scan_finding.id)

        # 5. Trigger async validation for each deduplicated finding
        for finding_id in created_finding_ids:
            validate_finding.delay(finding_id)

        # 6. Update scan status
        scan_history.status = 'Completed'
        scan_history.save()
        
        return f"Scan {scan_history_id} completed: {len(vulnerabilities)} unique vulnerabilities (from {len(raw_findings)} raw findings)"

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
