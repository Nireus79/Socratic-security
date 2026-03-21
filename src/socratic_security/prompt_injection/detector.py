"""Prompt Injection Detector"""
import re
from dataclasses import dataclass
from typing import List, Optional
from .config import INJECTION_PATTERNS, PATTERN_SEVERITY, RISK_THRESHOLDS

@dataclass
class DetectionResult:
    """Result of prompt injection detection."""
    is_suspicious: bool
    risk_score: float
    matched_patterns: List[str]
    severity_level: str
    reasons: List[str]
    warnings: List[str]

class PromptInjectionDetector:
    """Detects prompt injection attempts in user input."""

    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficient matching."""
        self.compiled_patterns = {}
        for category, patterns in INJECTION_PATTERNS.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]

    def detect(self, user_input: str, context: Optional[str] = None) -> DetectionResult:
        """Detect prompt injection attempts in user input."""
        warnings = []
        matched_patterns = []
        risk_scores = []
        reasons = []

        if not isinstance(user_input, str):
            return DetectionResult(
                is_suspicious=False,
                risk_score=0,
                matched_patterns=[],
                severity_level="low",
                reasons=["Input is not a string"],
                warnings=["Type check passed"],
            )

        # Check against OWASP patterns
        for category, compiled_patterns in self.compiled_patterns.items():
            for pattern in compiled_patterns:
                matches = pattern.findall(user_input)
                if matches:
                    matched_patterns.extend(matches)
                    severity = PATTERN_SEVERITY.get(category, 50)
                    risk_scores.append(severity)
                    reasons.append(f"Matched {category}: {matches[0]}")

        # Calculate final risk score
        if risk_scores:
            risk_score = max(risk_scores)
        else:
            risk_score = 0

        # Determine severity level
        if risk_score >= RISK_THRESHOLDS["critical"]:
            severity_level = "critical"
        elif risk_score >= RISK_THRESHOLDS["high"]:
            severity_level = "high"
        elif risk_score >= RISK_THRESHOLDS["medium"]:
            severity_level = "medium"
        else:
            severity_level = "low"

        is_suspicious = (
            risk_score >= (RISK_THRESHOLDS["high"] if self.strict_mode else RISK_THRESHOLDS["medium"])
        )

        return DetectionResult(
            is_suspicious=is_suspicious,
            risk_score=min(100, risk_score),
            matched_patterns=list(set(matched_patterns)),
            severity_level=severity_level,
            reasons=reasons,
            warnings=warnings,
        )

    def is_safe(self, user_input: str, threshold: float = 50) -> bool:
        """Quick check if input is safe."""
        result = self.detect(user_input)
        return result.risk_score < threshold
