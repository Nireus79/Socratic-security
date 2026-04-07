"""Prompt Injection Configuration - OWASP patterns"""

INJECTION_PATTERNS = {
    "instruction_override": [
        r"ignore\s+(previous|all|above|prior)\s+(instructions|rules|prompts|context)",
        r"disregard\s+(previous|all|above|prior)\s+(instructions|rules|prompts|context)",
        r"forget\s+(everything|all|previous|prior|above)",
        r"you\s+are\s+now",
        r"new\s+instructions?:",
    ],
    "system_prompt_extraction": [
        r"what\s+are\s+your\s+(system\s+)?instructions",
        r"show\s+me\s+your\s+(system\s+)?prompt",
        r"reveal\s+your\s+(system\s+)?prompt",
        r"system\s*:\s*",
    ],
    "jailbreak": [
        r"jailbreak",
        r"bypass",
        r"disable\s+safety",
        r"developer\s+mode",
    ],
    "data_extraction": [
        r"reveal\s+(api\s+)?keys",
        r"show\s+(api\s+)?secrets",
        r"dump\s+data",
    ],
}

PATTERN_SEVERITY = {
    "instruction_override": 95,
    "system_prompt_extraction": 90,
    "jailbreak": 88,
    "data_extraction": 85,
}

RISK_THRESHOLDS = {
    "critical": 90,
    "high": 75,
    "medium": 50,
    "low": 30,
}

INPUT_DELIMITERS = {
    "start": "USER_INPUT_START",
    "end": "USER_INPUT_END",
}

MAX_LENGTHS = {
    "prompt": 2000,
    "user_message": 1000,
}
