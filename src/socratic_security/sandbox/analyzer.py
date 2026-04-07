"""Code Static Analysis"""

import ast
from dataclasses import dataclass
from typing import Optional


@dataclass
class AnalysisResult:
    """Result of code analysis."""

    safe: bool
    reason: Optional[str] = None


class CodeAnalyzer:
    """Static analysis for malicious code patterns."""

    BLACKLISTED_IMPORTS = [
        "os",
        "subprocess",
        "socket",
        "urllib",
        "requests",
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
    ]

    def analyze(self, code: str) -> AnalysisResult:
        """Detect dangerous patterns before execution."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return AnalysisResult(safe=False, reason="Syntax error")

        # Check for dangerous imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.BLACKLISTED_IMPORTS:
                        return AnalysisResult(
                            safe=False, reason=f"Blacklisted import: {alias.name}"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module in self.BLACKLISTED_IMPORTS:
                    return AnalysisResult(safe=False, reason=f"Blacklisted import: {node.module}")

        return AnalysisResult(safe=True)
