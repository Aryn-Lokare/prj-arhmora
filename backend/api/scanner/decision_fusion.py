"""
Decision Fusion Layer for Hybrid Detection.

This module consolidates the logic for combining rule-based and AI-based 
detection signals into a final verdict. It implements a principled 
decision hierarchy:

1. IF Rule Match → Trust Rule (highest priority, lowest FP)
2. ELSE IF AI Score + Context → Flag for review
3. ELSE → Mark as Safe

This approach balances precision (rules) with recall (AI).
"""

import logging
from typing import Dict, Optional, List, Tuple
from enum import Enum, auto
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class DetectionSource(Enum):
    """Source of the detection signal."""
    RULE = auto()      # Rule-based detection (signatures, patterns)
    AI = auto()        # AI/ML-based detection (XGBoost, anomaly)
    HYBRID = auto()    # Combination of both


class Verdict(Enum):
    """Final decision verdict."""
    BLOCK = "block"           # Confirmed threat, block immediately
    THROTTLE = "throttle"     # Probable threat, rate-limit
    FLAG = "flag"             # Suspicious, needs review
    MONITOR = "monitor"       # Worth watching, log only
    SAFE = "safe"             # No threat detected


@dataclass
class RuleResult:
    """Result from rule-based detection."""
    matched: bool
    rule_name: str = ""
    pattern_confidence: int = 0  # 0-30
    evidence: str = ""
    severity: str = "Low"  # Low, Medium, High
    
    
@dataclass
class AIResult:
    """Result from AI-based detection."""
    probability: float = 0.0        # Attack probability 0-1
    risk_score: int = 0             # 0-100
    confidence: float = 0.0         # Model confidence 0-1
    classification: str = "Normal"  # Specific class name
    class_id: int = 0               # Class ID (0=Normal)
    severity: str = "Info"
    action: str = "allow"
    anomaly_score: float = 0.0


@dataclass
class ContextResult:
    """Result from context validation."""
    is_safe_context: bool = False
    reason: str = ""
    max_risk_ceiling: int = 100
    endpoint_sensitivity: str = "public"


@dataclass 
class FusionDecision:
    """Final fused decision with reasoning."""
    verdict: Verdict
    source: DetectionSource
    risk_score: int              # Final risk score 0-100
    confidence: float            # Final confidence 0-1
    severity: str                # High, Medium, Low, Info
    classification: str          # Vulnerability type
    reasoning: str               # Human-readable explanation
    should_log: bool             # Whether to create a finding
    
    def to_dict(self) -> Dict:
        return {
            'verdict': self.verdict.value,
            'source': self.source.name.lower(),
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'severity': self.severity,
            'classification': self.classification,
            'reasoning': self.reasoning,
            'should_log': self.should_log,
        }


class DecisionFusionEngine:
    """
    Combines rule-based and AI-based signals into final verdicts.
    
    Decision Hierarchy:
    1. IF Rule Match with high confidence → Trust Rule (block/throttle)
    2. ELSE IF AI + Context indicates threat → Flag for review
    3. ELSE IF AI says normal with high confidence → Safe
    4. ELSE → Monitor (low priority logging)
    
    Thresholds:
    - RULE_TRUST_THRESHOLD: Pattern confidence needed to trust rule alone
    - AI_FLAG_THRESHOLD: AI confidence needed to flag without rule match
    - AI_SAFE_THRESHOLD: AI confidence needed to mark as definitively safe
    - CONTEXT_OVERRIDE_CEILING: Maximum risk for safe-context URLs
    """
    
    # Thresholds (tune based on validation data)
    RULE_TRUST_THRESHOLD = 20       # Pattern confidence (0-30) to trust rule
    AI_FLAG_THRESHOLD = 0.6         # AI confidence to flag without rule
    AI_SAFE_THRESHOLD = 0.8         # AI confidence to mark as safe
    CONTEXT_OVERRIDE_CEILING = 25   # Max risk for safe contexts
    
    # Risk thresholds for severity
    HIGH_RISK_THRESHOLD = 70
    MEDIUM_RISK_THRESHOLD = 40
    LOW_RISK_THRESHOLD = 20
    
    def __init__(self):
        """Initialize the decision fusion engine."""
        self._decision_history: List[FusionDecision] = []
    
    def fuse(
        self,
        rule_result: Optional[RuleResult] = None,
        ai_result: Optional[AIResult] = None,
        context_result: Optional[ContextResult] = None,
    ) -> FusionDecision:
        """
        Fuse detection signals into a single decision.
        
        Args:
            rule_result: Result from rule-based detection (optional)
            ai_result: Result from AI-based detection (optional)
            context_result: Context validation result (optional)
            
        Returns:
            FusionDecision with verdict, reasoning, and metadata
        """
        # Handle missing inputs with defaults
        rule = rule_result or RuleResult(matched=False)
        ai = ai_result or AIResult()
        context = context_result or ContextResult()
        
        # Track decision logic
        reasoning_parts = []
        
        # =========================================================
        # DECISION HIERARCHY
        # =========================================================
        
        # 1. RULE MATCH: If rule matched with sufficient confidence, trust it
        if rule.matched and rule.pattern_confidence >= self.RULE_TRUST_THRESHOLD:
            decision = self._trust_rule(rule, ai, context)
            reasoning_parts.append(f"Rule '{rule.rule_name}' matched (pattern_conf={rule.pattern_confidence})")
            decision.reasoning = "; ".join(reasoning_parts)
            self._decision_history.append(decision)
            return decision
        
        # 2. CONTEXT OVERRIDE: Check if context makes this inherently safe
        if context.is_safe_context:
            # Apply risk ceiling - AI cannot exceed this
            capped_risk = min(ai.risk_score, context.max_risk_ceiling)
            
            # If AI was high-risk but context says safe, flag for review instead of blocking
            if ai.risk_score > context.max_risk_ceiling:
                reasoning_parts.append(
                    f"Context override: AI risk {ai.risk_score} capped to {capped_risk} ({context.reason})"
                )
                decision = FusionDecision(
                    verdict=Verdict.MONITOR,
                    source=DetectionSource.AI,
                    risk_score=capped_risk,
                    confidence=ai.confidence * 0.5,  # Reduce confidence
                    severity="Info",
                    classification=ai.classification,
                    reasoning="; ".join(reasoning_parts),
                    should_log=False,
                )
                self._decision_history.append(decision)
                return decision
            else:
                # Context says safe and AI agrees
                reasoning_parts.append(f"Safe context: {context.reason}")
                decision = FusionDecision(
                    verdict=Verdict.SAFE,
                    source=DetectionSource.HYBRID,
                    risk_score=capped_risk,
                    confidence=ai.confidence,
                    severity="Info",
                    classification="Normal",
                    reasoning="; ".join(reasoning_parts),
                    should_log=False,
                )
                self._decision_history.append(decision)
                return decision
        
        # 3. AI DETECTION: Evaluate AI signals
        is_ai_attack = ai.class_id > 0 and ai.confidence >= self.AI_FLAG_THRESHOLD
        is_ai_high_risk = ai.risk_score >= self.MEDIUM_RISK_THRESHOLD
        is_ai_confident_normal = ai.class_id == 0 and ai.confidence >= self.AI_SAFE_THRESHOLD
        
        # 3a. AI says specific attack with confidence
        if is_ai_attack:
            decision = self._trust_ai_attack(ai, context)
            reasoning_parts.append(
                f"AI classified as {ai.classification} (conf={ai.confidence:.1%})"
            )
            decision.reasoning = "; ".join(reasoning_parts)
            self._decision_history.append(decision)
            return decision
        
        # 3b. AI shows high risk but no specific classification
        if is_ai_high_risk and not is_ai_confident_normal:
            decision = self._flag_anomaly(ai, context)
            reasoning_parts.append(
                f"AI anomaly detected (risk={ai.risk_score}, severity={ai.severity})"
            )
            decision.reasoning = "; ".join(reasoning_parts)
            self._decision_history.append(decision)
            return decision
        
        # 3c. AI confidently says normal
        if is_ai_confident_normal:
            reasoning_parts.append(
                f"AI classified as Normal with {ai.confidence:.1%} confidence"
            )
            decision = FusionDecision(
                verdict=Verdict.SAFE,
                source=DetectionSource.AI,
                risk_score=ai.risk_score,
                confidence=ai.confidence,
                severity="Info",
                classification="Normal",
                reasoning="; ".join(reasoning_parts),
                should_log=False,
            )
            self._decision_history.append(decision)
            return decision
        
        # 4. FALLBACK: Low-confidence situation, monitor only
        reasoning_parts.append("No strong signals from rules or AI")
        decision = FusionDecision(
            verdict=Verdict.MONITOR,
            source=DetectionSource.HYBRID,
            risk_score=ai.risk_score,
            confidence=max(ai.confidence, 0.3),
            severity="Info",
            classification="Unknown",
            reasoning="; ".join(reasoning_parts),
            should_log=False,
        )
        self._decision_history.append(decision)
        return decision
    
    def _trust_rule(
        self, 
        rule: RuleResult, 
        ai: AIResult, 
        context: ContextResult
    ) -> FusionDecision:
        """
        Create decision that trusts rule-based detection.
        Rules are precise (high precision, lower recall).
        """
        # Calculate final risk combining rule severity and AI confirmation
        base_risk = self._severity_to_risk(rule.severity)
        
        # Boost confidence if AI agrees
        ai_boost = 0.1 if ai.class_id > 0 else 0.0
        final_confidence = min(1.0, (rule.pattern_confidence / 30.0) + ai_boost)
        
        # Determine verdict based on severity
        if rule.severity == "High" and final_confidence >= 0.8:
            verdict = Verdict.BLOCK
        elif rule.severity in ["High", "Medium"]:
            verdict = Verdict.THROTTLE
        else:
            verdict = Verdict.FLAG
            
        return FusionDecision(
            verdict=verdict,
            source=DetectionSource.RULE,
            risk_score=base_risk,
            confidence=final_confidence,
            severity=rule.severity,
            classification=rule.rule_name,
            reasoning="",  # Set by caller
            should_log=True,
        )
    
    def _trust_ai_attack(
        self, 
        ai: AIResult, 
        context: ContextResult
    ) -> FusionDecision:
        """
        Create decision for AI-detected specific attack.
        """
        # Adjust risk based on endpoint sensitivity
        risk_multiplier = self._sensitivity_multiplier(context.endpoint_sensitivity)
        adjusted_risk = min(100, int(ai.risk_score * risk_multiplier))
        
        # Determine verdict
        if ai.severity == "High" and ai.confidence >= 0.85:
            verdict = Verdict.THROTTLE  # AI alone doesn't block, but throttles
        elif ai.severity in ["High", "Medium"]:
            verdict = Verdict.FLAG
        else:
            verdict = Verdict.MONITOR
            
        return FusionDecision(
            verdict=verdict,
            source=DetectionSource.AI,
            risk_score=adjusted_risk,
            confidence=ai.confidence,
            severity=ai.severity,
            classification=ai.classification,
            reasoning="",
            should_log=True,
        )
    
    def _flag_anomaly(
        self, 
        ai: AIResult, 
        context: ContextResult
    ) -> FusionDecision:
        """
        Create decision for AI anomaly without specific classification.
        """
        return FusionDecision(
            verdict=Verdict.FLAG,
            source=DetectionSource.AI,
            risk_score=ai.risk_score,
            confidence=ai.confidence * 0.8,  # Reduce confidence for anomalies
            severity=ai.severity,
            classification="AI-Detected Anomaly",
            reasoning="",
            should_log=True,
        )
    
    def _severity_to_risk(self, severity: str) -> int:
        """Convert severity level to risk score."""
        return {
            "High": 85,
            "Medium": 55,
            "Low": 25,
            "Info": 10,
        }.get(severity, 10)
    
    def _sensitivity_multiplier(self, sensitivity: str) -> float:
        """Get risk multiplier based on endpoint sensitivity."""
        return {
            "admin": 1.2,
            "auth": 1.1,
            "data": 1.0,
            "api": 0.9,
            "public": 0.8,
        }.get(sensitivity, 1.0)
    
    def get_decision_stats(self) -> Dict:
        """
        Get statistics on decisions made by this engine.
        Useful for monitoring and tuning.
        """
        if not self._decision_history:
            return {"total": 0}
            
        total = len(self._decision_history)
        verdicts = {}
        sources = {}
        
        for d in self._decision_history:
            verdicts[d.verdict.value] = verdicts.get(d.verdict.value, 0) + 1
            sources[d.source.name] = sources.get(d.source.name, 0) + 1
            
        return {
            "total": total,
            "verdicts": verdicts,
            "sources": sources,
            "logged": sum(1 for d in self._decision_history if d.should_log),
        }
    
    def reset_history(self):
        """Clear decision history (e.g., between scans)."""
        self._decision_history.clear()


# =============================================================================
# Convenience Functions
# =============================================================================

def create_rule_result(
    matched: bool,
    rule_name: str = "",
    pattern_confidence: int = 0,
    evidence: str = "",
    severity: str = "Low",
) -> RuleResult:
    """Factory function to create RuleResult."""
    return RuleResult(
        matched=matched,
        rule_name=rule_name,
        pattern_confidence=pattern_confidence,
        evidence=evidence,
        severity=severity,
    )


def create_ai_result(
    probability: float = 0.0,
    risk_score: int = 0,
    confidence: float = 0.0,
    classification: str = "Normal",
    class_id: int = 0,
    severity: str = "Info",
    action: str = "allow",
    anomaly_score: float = 0.0,
) -> AIResult:
    """Factory function to create AIResult."""
    return AIResult(
        probability=probability,
        risk_score=risk_score,
        confidence=confidence,
        classification=classification,
        class_id=class_id,
        severity=severity,
        action=action,
        anomaly_score=anomaly_score,
    )


def create_context_result(
    is_safe_context: bool = False,
    reason: str = "",
    max_risk_ceiling: int = 100,
    endpoint_sensitivity: str = "public",
) -> ContextResult:
    """Factory function to create ContextResult."""
    return ContextResult(
        is_safe_context=is_safe_context,
        reason=reason,
        max_risk_ceiling=max_risk_ceiling,
        endpoint_sensitivity=endpoint_sensitivity,
    )
