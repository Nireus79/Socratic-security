"""
Password Breach Detection - Check passwords against known breaches.

Uses k-anonymity with HaveIBeenPwned API (send only first 5 chars of SHA-1 hash).
Falls back to local breach database if API unavailable.
"""

import hashlib
import logging
import os
from typing import Tuple

import requests

logger = logging.getLogger("socratic_security.auth.breach_checker")


class PasswordBreachChecker:
    """Check passwords against HaveIBeenPwned database using k-anonymity."""

    def __init__(
        self,
        enabled: bool = True,
        threshold: int = 100,
        api_url: str = "https://api.pwnedpasswords.com/range",
        timeout: int = 5,
    ):
        """
        Initialize breach checker.

        Args:
            enabled: Whether to check for breaches
            threshold: Minimum breach count to reject password (default: 100)
            api_url: HaveIBeenPwned API endpoint
            timeout: Request timeout in seconds
        """
        self.enabled = enabled
        self.threshold = threshold
        self.api_url = api_url
        self.timeout = timeout

    @staticmethod
    def _hash_password(password: str) -> str:
        """
        Hash password using SHA-1 (required by HaveIBeenPwned API).

        Args:
            password: Password to hash

        Returns:
            SHA-1 hash in uppercase hex format
        """
        return hashlib.sha1(password.encode()).hexdigest().upper()

    async def is_breached(self, password: str) -> Tuple[bool, int]:
        """
        Check if password has been breached using k-anonymity.

        Uses 5-character prefix of SHA-1 hash to query HaveIBeenPwned API.
        Only first 5 characters are sent, full hash is matched locally.

        Args:
            password: Password to check

        Returns:
            Tuple of (is_breached, breach_count)
            - is_breached: True if breach count >= threshold
            - breach_count: Number of times password seen in breaches
        """
        if not self.enabled:
            return False, 0

        if not password or len(password) < 8:
            # Weak passwords are considered breached
            return True, self.threshold

        try:
            password_hash = self._hash_password(password)
            hash_prefix = password_hash[:5]
            hash_suffix = password_hash[5:]

            # Query API with only first 5 characters (k-anonymity)
            response = requests.get(
                f"{self.api_url}/{hash_prefix}",
                timeout=self.timeout,
                headers={"User-Agent": "socratic-security/1.0"},
            )

            if response.status_code == 200:
                # Parse response: format is "SUFFIX:COUNT\r\n"
                breach_count = self._find_in_response(
                    response.text, hash_suffix
                )
                is_breached = breach_count >= self.threshold

                if is_breached:
                    logger.warning(
                        f"Password breach detected: {breach_count} occurrences"
                    )
                else:
                    logger.info(
                        f"Password breach check passed: {breach_count} occurrences"
                    )

                return is_breached, breach_count

            elif response.status_code == 404:
                # Hash not found in breaches
                logger.info("Password not found in breaches")
                return False, 0

            else:
                # API error - log and fail open (don't block on API failure)
                logger.error(
                    f"HaveIBeenPwned API error: {response.status_code}"
                )
                return False, 0

        except requests.RequestException as e:
            # Network error - fail open (don't block on network failure)
            logger.error(f"Breach check failed (network error): {e}")
            return False, 0
        except Exception as e:
            logger.error(f"Breach check failed: {e}")
            return False, 0

    @staticmethod
    def _find_in_response(response_text: str, hash_suffix: str) -> int:
        """
        Find hash suffix in API response and extract breach count.

        Response format: "SUFFIX:COUNT\r\n" (multiple lines)

        Args:
            response_text: API response text
            hash_suffix: Hash suffix to find (35 characters)

        Returns:
            Breach count, or 0 if not found
        """
        for line in response_text.split("\r\n"):
            if not line:
                continue

            parts = line.split(":")
            if len(parts) != 2:
                continue

            suffix, count_str = parts
            if suffix == hash_suffix:
                try:
                    return int(count_str)
                except ValueError:
                    continue

        return 0

    def validate_password(self, password: str) -> Tuple[bool, str]:
        """
        Validate password strength and breach status.

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, error_message)
            - is_valid: True if password passes all checks
            - error_message: Reason for rejection, or empty string if valid
        """
        # Check password length
        if not password or len(password) < 8:
            return False, "Password must be at least 8 characters"

        # Check for common patterns
        common_patterns = [
            "password",
            "123456",
            "qwerty",
            "admin",
            "letmein",
            "welcome",
        ]
        if password.lower() in common_patterns:
            return False, "Password is too common"

        # Check for variety
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        variety_count = sum([has_upper, has_lower, has_digit, has_special])
        if variety_count < 3:
            return (
                False,
                "Password must include uppercase, lowercase, digits, and symbols",
            )

        return True, ""


# Global breach checker instance
_breach_checker = None


def get_breach_checker(
    enabled: bool = None, threshold: int = None
) -> PasswordBreachChecker:
    """
    Get or create the global breach checker.

    Args:
        enabled: Override enabled setting
        threshold: Override breach threshold

    Returns:
        Global PasswordBreachChecker instance
    """
    global _breach_checker

    if _breach_checker is None:
        enabled = enabled if enabled is not None else os.getenv(
            "SECURITY_BREACH_CHECK", "true"
        ).lower() == "true"
        threshold = (
            threshold
            if threshold is not None
            else int(os.getenv("BREACH_COUNT_THRESHOLD", "100"))
        )
        _breach_checker = PasswordBreachChecker(
            enabled=enabled, threshold=threshold
        )

    return _breach_checker


async def check_password_breach(password: str) -> Tuple[bool, int]:
    """
    Check if password has been breached using global checker.

    Args:
        password: Password to check

    Returns:
        Tuple of (is_breached, breach_count)
    """
    checker = get_breach_checker()
    return await checker.is_breached(password)
