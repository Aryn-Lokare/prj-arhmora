"""
Unit Tests for Decision Fusion Layer.

Tests the hybrid decision logic combining rule-based and AI-based detection.
"""

import pytest
import sys
import os

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.scanner.decision_fusion import (
    DecisionFusionEngine,
    RuleResult,
    AIResult,
    ContextResult,
    Verdict,
    DetectionSource,
    create_rule_result,
    create_ai_result,
    create_context_result,
)


class TestDecisionFusion:
    """Tests for DecisionFusionEngine."""
    
    @pytest.fixture
    def engine(self):
        """Create a fresh engine for each test."""
        return DecisionFusionEngine()
    
    # =========================================================================
    # Rule Trust Tests
    # =========================================================================
    
    def test_rule_match_high_severity_blocks(self, engine):
        """Rule match with high severity should throttle/block."""
        rule = create_rule_result(
            matched=True,
            rule_name="SQL Injection",
            pattern_confidence=25,
            severity="High"
        )
        ai = create_ai_result()
        
        decision = engine.fuse(rule, ai)
        
        assert decision.source == DetectionSource.RULE
        assert decision.verdict in [Verdict.BLOCK, Verdict.THROTTLE]
        assert decision.should_log is True
        assert decision.classification == "SQL Injection"
    
    def test_rule_match_medium_severity_throttles(self, engine):
        """Rule match with medium severity should throttle."""
        rule = create_rule_result(
            matched=True,
            rule_name="XSS",
            pattern_confidence=25,
            severity="Medium"
        )
        
        decision = engine.fuse(rule_result=rule)
        
        assert decision.verdict == Verdict.THROTTLE
        assert decision.should_log is True
    
    def test_rule_match_low_confidence_falls_through(self, engine):
        """Rule match with low confidence falls through to AI."""
        rule = create_rule_result(
            matched=True,
            rule_name="XSS",
            pattern_confidence=10,  # Below threshold
            severity="Medium"
        )
        ai = create_ai_result(
            class_id=0,
            confidence=0.9,
            classification="Normal"
        )
        
        decision = engine.fuse(rule, ai)
        
        # Should not trust rule, should fall through to AI
        assert decision.verdict == Verdict.SAFE
        assert decision.source == DetectionSource.AI
    
    # =========================================================================
    # AI Detection Tests
    # =========================================================================
    
    def test_ai_attack_detected_flags(self, engine):
        """AI-detected specific attack should flag for review."""
        ai = create_ai_result(
            probability=0.85,
            risk_score=75,
            confidence=0.8,
            classification="SQL Injection",
            class_id=1,
            severity="High"
        )
        
        decision = engine.fuse(ai_result=ai)
        
        assert decision.source == DetectionSource.AI
        assert decision.verdict in [Verdict.THROTTLE, Verdict.FLAG]
        assert decision.should_log is True
        assert decision.classification == "SQL Injection"
    
    def test_ai_normal_confident_safe(self, engine):
        """AI confident normal classification should return safe."""
        ai = create_ai_result(
            probability=0.1,
            risk_score=10,
            confidence=0.95,
            classification="Normal",
            class_id=0,
            severity="Info"
        )
        
        decision = engine.fuse(ai_result=ai)
        
        assert decision.verdict == Verdict.SAFE
        assert decision.should_log is False
    
    def test_ai_high_risk_anomaly_flags(self, engine):
        """AI high risk without specific class should flag."""
        ai = create_ai_result(
            probability=0.7,
            risk_score=60,  # Above medium threshold
            confidence=0.5,  # Not confident specific class
            classification="Normal",
            class_id=0,
            severity="Medium"
        )
        
        decision = engine.fuse(ai_result=ai)
        
        assert decision.verdict == Verdict.FLAG
        assert decision.classification == "AI-Detected Anomaly"
    
    # =========================================================================
    # Context Override Tests
    # =========================================================================
    
    def test_safe_context_caps_risk(self, engine):
        """Safe context should cap AI risk score."""
        context = create_context_result(
            is_safe_context=True,
            reason="Static resource (.css)",
            max_risk_ceiling=25
        )
        ai = create_ai_result(
            risk_score=80,  # High risk
            confidence=0.6,
            severity="High"
        )
        
        decision = engine.fuse(ai_result=ai, context_result=context)
        
        # Risk should be capped
        assert decision.risk_score <= 25
        assert decision.verdict == Verdict.MONITOR
        assert decision.should_log is False
    
    def test_safe_context_and_safe_ai_returns_safe(self, engine):
        """Safe context + low risk AI should return safe."""
        context = create_context_result(
            is_safe_context=True,
            reason="Base URL",
            max_risk_ceiling=25
        )
        ai = create_ai_result(
            risk_score=15,
            confidence=0.7,
            classification="Normal",
            class_id=0
        )
        
        decision = engine.fuse(ai_result=ai, context_result=context)
        
        assert decision.verdict == Verdict.SAFE
        assert decision.should_log is False
    
    # =========================================================================
    # Hybrid Tests
    # =========================================================================
    
    def test_rule_plus_ai_agreement_boosts_confidence(self, engine):
        """Rule + AI agreement should boost confidence."""
        rule = create_rule_result(
            matched=True,
            rule_name="SQL Injection",
            pattern_confidence=25,
            severity="High"
        )
        ai = create_ai_result(
            class_id=1,  # SQL Injection
            confidence=0.8
        )
        
        decision = engine.fuse(rule, ai)
        
        # Should trust rule with boosted confidence
        assert decision.source == DetectionSource.RULE
        # Confidence should include AI boost
        # Base: 25/30 = 0.833, boost: 0.1 → ~0.93
        assert decision.confidence > 0.9
    
    def test_no_signals_returns_monitor(self, engine):
        """No strong signals should return monitor verdict."""
        ai = create_ai_result(
            probability=0.3,
            risk_score=20,
            confidence=0.4,  # Low confidence
            classification="Normal",
            class_id=0
        )
        
        decision = engine.fuse(ai_result=ai)
        
        assert decision.verdict == Verdict.MONITOR
        assert decision.should_log is False
    
    # =========================================================================
    # Stats and Utility Tests
    # =========================================================================
    
    def test_decision_stats(self, engine):
        """Test decision statistics tracking."""
        # Make several decisions
        engine.fuse(ai_result=create_ai_result(class_id=0, confidence=0.9))
        engine.fuse(ai_result=create_ai_result(class_id=1, confidence=0.8, risk_score=70))
        engine.fuse(rule_result=create_rule_result(matched=True, pattern_confidence=25, severity="High"))
        
        stats = engine.get_decision_stats()
        
        assert stats['total'] == 3
        assert 'verdicts' in stats
        assert 'sources' in stats
    
    def test_reset_history(self, engine):
        """Test history reset."""
        engine.fuse(ai_result=create_ai_result())
        engine.fuse(ai_result=create_ai_result())
        
        engine.reset_history()
        
        stats = engine.get_decision_stats()
        assert stats['total'] == 0
    
    def test_decision_to_dict(self, engine):
        """Test FusionDecision.to_dict() method."""
        decision = engine.fuse(
            rule_result=create_rule_result(
                matched=True, 
                pattern_confidence=25,
                rule_name="XSS",
                severity="Medium"
            )
        )
        
        d = decision.to_dict()
        
        assert 'verdict' in d
        assert 'source' in d
        assert 'risk_score' in d
        assert 'confidence' in d
        assert 'reasoning' in d
        assert d['source'] == 'rule'


class TestFactoryFunctions:
    """Test the factory helper functions."""
    
    def test_create_rule_result(self):
        result = create_rule_result(
            matched=True,
            rule_name="Test",
            pattern_confidence=20
        )
        assert result.matched is True
        assert result.rule_name == "Test"
        assert result.pattern_confidence == 20
    
    def test_create_ai_result(self):
        result = create_ai_result(
            probability=0.75,
            class_id=2,
            classification="XSS"
        )
        assert result.probability == 0.75
        assert result.class_id == 2
        assert result.classification == "XSS"
    
    def test_create_context_result(self):
        result = create_context_result(
            is_safe_context=True,
            reason="Static file",
            max_risk_ceiling=20
        )
        assert result.is_safe_context is True
        assert result.max_risk_ceiling == 20


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
