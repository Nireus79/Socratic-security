"""Sandbox Security Policies"""

class SandboxPolicy:
    """Security policy for code execution."""

    BLACKLISTED_IMPORTS = [
        "os", "subprocess", "socket", "urllib", "requests",
        "eval", "exec", "compile", "__import__", "open",
    ]

    ALLOWED_IMPORTS = [
        "math", "datetime", "json", "typing",
        "dataclasses", "enum", "collections",
    ]

    MAX_EXECUTION_TIME = 5  # seconds
    MAX_MEMORY = 128  # MB
    MAX_OUTPUT_SIZE = 10 * 1024  # 10KB
