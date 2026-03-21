"""Input Validation and Sanitization"""
import re

class SanitizedStr(str):
    """String type with automatic HTML sanitization."""

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str):
            raise TypeError("string required")
        
        # Remove HTML tags
        sanitized = re.sub(r'<[^>]+>', '', v)
        
        # Remove control characters
        sanitized = "".join(char for char in sanitized if ord(char) >= 32 or char in "\n\r\t")
        
        return cls(sanitized)

class SafeFilename(str):
    """Validated filename without path traversal."""

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if ".." in v or "/" in v or "\\" in v or "\0" in v:
            raise ValueError("Invalid filename")
        return cls(v)

def validate_no_sql_injection(v: str) -> str:
    """Validate string doesn't contain SQL injection patterns."""
    dangerous_patterns = [
        "DROP TABLE", "DELETE FROM", "UPDATE ", "INSERT INTO",
        "--", "/*", "*/", "UNION", "SELECT * FROM"
    ]
    
    v_upper = v.upper()
    for pattern in dangerous_patterns:
        if pattern in v_upper:
            raise ValueError(f"Potentially dangerous SQL pattern detected")
    
    return v
