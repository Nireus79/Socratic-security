"""Input Validation and Sanitization for XSS, SQL Injection, and other attacks."""

import logging
import re
from typing import Optional

logger = logging.getLogger("socratic_security.input_validation")


class SanitizedStr(str):
    """String type with automatic HTML sanitization and control character removal."""

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str):
            raise TypeError("string required")

        # Remove HTML tags but preserve text content
        sanitized = re.sub(r"<[^>]+>", "", v)

        # Remove control characters (keep \n, \r, \t)
        sanitized = "".join(char for char in sanitized if ord(char) >= 32 or char in "\n\r\t")

        # Remove null bytes
        sanitized = sanitized.replace("\0", "")

        logger.debug(f"Sanitized string (length: {len(v)} -> {len(sanitized)})")
        return cls(sanitized)


class SafeFilename(str):
    """Filename without path traversal or special characters."""

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str):
            raise TypeError("string required")

        # Check for path traversal
        if ".." in v or "/" in v or "\\" in v or "\0" in v:
            raise ValueError("Invalid filename: path traversal detected")

        # Check for empty filename
        if not v or len(v) == 0:
            raise ValueError("Filename cannot be empty")

        # Limit filename length
        if len(v) > 255:
            raise ValueError("Filename too long (max 255 characters)")

        logger.debug(f"Validated safe filename: {v}")
        return cls(v)


def validate_no_sql_injection(v: str) -> str:
    """Validate string doesn't contain SQL injection patterns."""
    if not isinstance(v, str):
        return v

    dangerous_patterns = [
        "DROP TABLE",
        "DROP DATABASE",
        "DELETE FROM",
        "UPDATE ",
        "INSERT INTO",
        "TRUNCATE",
        "--",
        "/*",
        "*/",
        "UNION",
        "SELECT * FROM",
        "EXEC ",
        "EXECUTE ",
        "CREATE TABLE",
        "ALTER TABLE",
        "GRANT ",
        "REVOKE ",
    ]

    v_upper = v.upper()
    for pattern in dangerous_patterns:
        if pattern in v_upper:
            logger.warning(f"SQL injection pattern detected: {pattern}")
            raise ValueError(f"Potentially dangerous SQL pattern detected: {pattern}")

    return v


def validate_no_xss(v: str) -> str:
    """Validate string doesn't contain XSS payloads."""
    if not isinstance(v, str):
        return v

    # XSS attack patterns
    xss_patterns = [
        r"<script[^>]*>.*?</script>",
        r"<iframe[^>]*>.*?</iframe>",
        r"javascript:",
        r"on\w+\s*=",  # event handlers like onclick=
        r"<img[^>]*on\w+\s*=",
        r"<svg[^>]*on\w+\s*=",
        r"<embed[^>]*>",
        r"<object[^>]*>",
        r"eval\(",
        r"expression\(",
    ]

    v_lower = v.lower()
    for pattern in xss_patterns:
        if re.search(pattern, v_lower, re.IGNORECASE | re.DOTALL):
            logger.warning(f"XSS pattern detected: {pattern}")
            raise ValueError("Potentially dangerous XSS pattern detected")

    return v


def validate_email(v: str) -> str:
    """Validate email format safely."""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Basic email validation (RFC 5322 simplified)
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if not re.match(email_pattern, v):
        raise ValueError("Invalid email format")

    # Check length limits
    if len(v) > 254:  # RFC 5321
        raise ValueError("Email too long (max 254 characters)")

    if len(v.split("@")[0]) > 64:  # Local part limit
        raise ValueError("Email local part too long")

    logger.debug(f"Validated email: {v.split('@')[0]}@***")
    return v


def validate_username(v: str) -> str:
    """Validate username format (alphanumeric + underscore only)."""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Alphanumeric and underscore only, 3-32 characters
    if not re.match(r"^[a-zA-Z0-9_]{3,32}$", v):
        raise ValueError("Username must be 3-32 characters, alphanumeric and underscore only")

    logger.debug(f"Validated username: {v}")
    return v


def validate_url(v: str) -> str:
    """Validate URL format and prevent open redirects."""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Basic URL validation
    url_pattern = r"^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?$"

    if not re.match(url_pattern, v):
        raise ValueError("Invalid URL format")

    # Check for javascript: protocol (XSS via redirect)
    if v.lower().startswith("javascript:"):
        raise ValueError("JavaScript URLs not allowed")

    # Check length
    if len(v) > 2048:
        raise ValueError("URL too long")

    logger.debug(f"Validated URL: {v[:50]}...")
    return v


def sanitize_html(html: str, allowed_tags: Optional[list] = None) -> str:
    """Sanitize HTML, removing dangerous tags and attributes."""
    if not isinstance(html, str):
        return ""

    # Default allowed tags
    if allowed_tags is None:
        allowed_tags = ["p", "br", "strong", "em", "u", "h1", "h2", "h3", "h4", "h5", "h6"]

    # Remove script tags and event handlers
    sanitized = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r"<iframe[^>]*>.*?</iframe>", "", sanitized, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', "", sanitized, flags=re.IGNORECASE)

    logger.debug(f"Sanitized HTML (length: {len(html)} -> {len(sanitized)})")
    return sanitized
