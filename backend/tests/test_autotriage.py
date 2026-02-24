"""
Unit tests for AutoTriage Engine.

Tests intelligent false positive filtering and classification logic.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from api.scanner.autotriage_engine import AutoTriageEngine


class TestAutoTriageEngine:
    """Test suite for AutoTriageEngine."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.engine = AutoTriageEngine()
    
    def test_classify_high_confidence_finding(self):
        """Test that high-confidence findings are classified as confirmed."""
        finding = {
            'total_confidence': 95,
            'severity': 'High',
            'validation_status': 'pending'
        }
        
        classification = self.engine.classify_finding(finding)
        assert classification == 'confirmed'
    
    def test_classify_validated_finding(self):
        """Test that validated findings are always confirmed."""
        finding = {
            'total_confidence': 60,  # Even with lower confidence
            'severity': 'Medium',
            'validation_status': 'validated'
        }
        
        classification = self.engine.classify_finding(finding)
        assert classification == 'confirmed'
    
    def test_classify_failed_validation(self):
        """Test that failed validation downgrades to informational."""
        finding = {
            'total_confidence': 80,
            'severity': 'High',
            'validation_status': 'failed'
        }
        
        classification = self.engine.classify_finding(finding)
        assert classification == 'informational'
    
    def test_classify_likely_finding(self):
        """Test likely classification for moderate confidence."""
        finding = {
            'total_confidence': 75,
            'severity': 'High',
            'validation_status': 'pending'
        }
        
        classification = self.engine.classify_finding(finding)
        assert classification == 'likely'
    
    def test_classify_suspicious_finding(self):
        """Test suspicious classification for lower confidence."""
        finding = {
            'total_confidence': 55,
            'severity': 'Medium',
            'validation_status': 'pending'
        }
        
        classification = self.engine.classify_finding(finding)
        assert classification == 'suspicious'
    
    def test_classify_informational_finding(self):
        """Test informational classification for low confidence."""
        finding = {
            'total_confidence': 40,
            'severity': 'Low',
            'validation_status': 'pending'
        }
        
        classification = self.engine.classify_finding(finding)
        assert classification == 'informational'
    
    def test_should_alert_confirmed_high_severity(self):
        """Test that confirmed high-severity findings trigger alerts."""
        finding = {
            'total_confidence': 90,
            'severity': 'High',
            'validation_status': 'pending'
        }
        
        assert self.engine.should_alert(finding) == True
    
    def test_should_alert_very_high_confidence(self):
        """Test that very high confidence triggers alert regardless of severity."""
        finding = {
            'total_confidence': 96,
            'severity': 'Low',
            'validation_status': 'pending'
        }
        
        assert self.engine.should_alert(finding) == True
    
    def test_should_not_alert_low_confidence(self):
        """Test that low confidence does not trigger alerts."""
        finding = {
            'total_confidence': 50,
            'severity': 'High',
            'validation_status': 'pending'
        }
        
        assert self.engine.should_alert(finding) == False
    
    def test_triage_reason_generation(self):
        """Test generation of triage reason."""
        finding = {
            'total_confidence': 88,
            'severity': 'High',
            'validation_status': 'pending'
        }
        
        reason = self.engine.get_triage_reason(finding)
        assert 'confirmed' in reason.lower()
        assert '88%' in reason
    
    def test_confidence_breakdown(self):
        """Test confidence breakdown generation."""
        finding = {
            'pattern_confidence': 25,
            'response_confidence': 30,
            'exploit_confidence': 20,
            'context_confidence': 10,
            'total_confidence': 85
        }
        
        breakdown = self.engine.get_confidence_breakdown(finding)
        assert breakdown['total_confidence'] == 85
        assert breakdown['pattern_confidence'] == 25
        assert breakdown['response_confidence'] == 30
        assert 'Pattern detection' in breakdown['breakdown_explanation']
    
    def test_filter_by_minimum_confidence(self):
        """Test filtering findings by minimum confidence."""
        findings = [
            {'total_confidence': 90, 'severity': 'High', 'validation_status': 'pending'},
            {'total_confidence': 50, 'severity': 'Medium', 'validation_status': 'pending'},
            {'total_confidence': 30, 'severity': 'Low', 'validation_status': 'pending'},
        ]
        
        filtered = self.engine.filter_findings(findings, min_confidence=60)
        assert len(filtered) == 1
        assert filtered[0]['total_confidence'] == 90
    
    def test_filter_by_classification(self):
        """Test filtering findings by classification."""
        findings = [
            {'total_confidence': 90, 'severity': 'High', 'validation_status': 'pending'},  # confirmed
            {'total_confidence': 50, 'severity': 'Medium', 'validation_status': 'pending'},  # suspicious
        ]
        
        filtered = self.engine.filter_findings(findings, classification_filter=['confirmed'])
        assert len(filtered) == 1
        assert filtered[0]['total_confidence'] == 90
    
    def test_filter_by_severity(self):
        """Test filtering findings by severity."""
        findings = [
            {'total_confidence': 85, 'severity': 'High', 'validation_status': 'pending'},
            {'total_confidence': 70, 'severity': 'Medium', 'validation_status': 'pending'},
            {'total_confidence': 50, 'severity': 'Low', 'validation_status': 'pending'},
        ]
        
        filtered = self.engine.filter_findings(findings, severity_filter=['High', 'Medium'])
        assert len(filtered) == 2
    
    def test_triage_summary(self):
        """Test triage summary generation."""
        findings = [
            {'total_confidence': 90, 'severity': 'High', 'validation_status': 'pending'},
            {'total_confidence': 75, 'severity': 'High', 'validation_status': 'pending'},
            {'total_confidence': 50, 'severity': 'Medium', 'validation_status': 'pending'},
            {'total_confidence': 30, 'severity': 'Low', 'validation_status': 'pending'},
        ]
        
        summary = self.engine.get_triage_summary(findings)
        
        assert summary['total_findings'] == 4
        assert summary['classification_counts']['confirmed'] == 1
        assert summary['classification_counts']['likely'] == 1
        assert summary['classification_counts']['suspicious'] == 1
        assert summary['classification_counts']['informational'] == 1
        assert summary['severity_counts']['High'] == 2
        assert summary['high_confidence_findings'] == 1  # >= 85
        assert summary['low_confidence_findings'] == 1  # < 50


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
