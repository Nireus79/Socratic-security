"""
Multi-Factor Authentication (MFA) Manager using TOTP.

Handles TOTP secret generation, verification, and backup recovery codes.
Uses time-based one-time passwords compatible with authenticator apps.
"""

import hashlib
import logging
import secrets
import string
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import pyotp

logger = logging.getLogger("socratic_security.auth.mfa")


@dataclass
class MFASetup:
    """Information for MFA setup."""

    secret: str
    qr_code_uri: str
    backup_codes: List[str]
    recovery_codes_display: str  # Formatted for user display


@dataclass
class MFAVerification:
    """Result of MFA verification."""

    is_valid: bool
    error: Optional[str] = None
    used_recovery_code: bool = False


class MFAManager:
    """Manages TOTP-based multi-factor authentication."""

    def __init__(
        self,
        issuer: str = "Socrates",
        totp_window: int = 1,
        backup_code_count: int = 10,
    ):
        """
        Initialize MFA manager.

        Args:
            issuer: Name displayed in authenticator app
            totp_window: Number of time windows to allow (current +/- windows)
            backup_code_count: Number of backup codes to generate
        """
        self.issuer = issuer
        self.totp_window = totp_window
        self.backup_code_count = backup_code_count

        # In-memory storage: {username: {"secret": str, "enabled": bool, "recovery_codes": {...}}}
        self._mfa_state: Dict = {}

    def generate_secret(self, username: str) -> MFASetup:
        """
        Generate a TOTP secret for a user.

        Args:
            username: Username to generate secret for

        Returns:
            MFASetup with secret, QR code URI, and backup codes
        """
        # Generate TOTP secret
        secret = pyotp.random_base32()

        # Create TOTP instance for generating QR code
        totp = pyotp.TOTP(secret)
        qr_code_uri = totp.provisioning_uri(
            name=username,
            issuer_name=self.issuer
        )

        # Generate backup recovery codes
        backup_codes = self._generate_backup_codes(self.backup_code_count)

        # Store MFA state (in production, store in database with encryption)
        if username not in self._mfa_state:
            self._mfa_state[username] = {
                "secret": secret,
                "enabled": False,
                "backup_codes": backup_codes,
                "recovery_codes": {},
                "created_at": datetime.now(timezone.utc),
            }
        else:
            # Update existing state with new secret and codes
            self._mfa_state[username]["secret"] = secret
            self._mfa_state[username]["backup_codes"] = backup_codes

        # Format recovery codes for display
        recovery_codes_display = "\n".join(backup_codes)

        logger.info(f"Generated TOTP secret for user {username}")

        return MFASetup(
            secret=secret,
            qr_code_uri=qr_code_uri,
            backup_codes=backup_codes,
            recovery_codes_display=recovery_codes_display,
        )

    def verify_totp(self, secret: str, code: str) -> bool:
        """
        Verify a TOTP code against a secret.

        Args:
            secret: TOTP secret
            code: 6-digit TOTP code to verify

        Returns:
            True if code is valid, False otherwise
        """
        try:
            totp = pyotp.TOTP(secret)
            # Allow window of +/- self.totp_window time windows
            return totp.verify(code, valid_window=self.totp_window)
        except Exception as e:
            logger.warning(f"TOTP verification failed: {e}")
            return False

    def _generate_backup_codes(self, count: int) -> List[str]:
        """
        Generate backup recovery codes.

        Args:
            count: Number of codes to generate

        Returns:
            List of recovery codes
        """
        codes = []
        # Generate codes in format: XXXX-XXXX-XXXX (12 alphanumeric chars)
        charset = string.ascii_uppercase + string.digits
        for _ in range(count):
            code = "".join(secrets.choice(charset) for _ in range(12))
            formatted = f"{code[:4]}-{code[4:8]}-{code[8:12]}"
            codes.append(formatted)
        return codes

    def _hash_recovery_code(self, code: str) -> str:
        """
        Hash a recovery code (like password hashing).

        Args:
            code: Recovery code to hash

        Returns:
            SHA256 hash of the code
        """
        return hashlib.sha256(code.encode()).hexdigest()

    def enable_mfa(self, username: str, secret: str, totp_code: str) -> Tuple[bool, str]:
        """
        Enable MFA for a user after verifying TOTP code.

        Args:
            username: Username enabling MFA
            secret: TOTP secret to enable
            totp_code: Current TOTP code to verify

        Returns:
            Tuple of (success, message)
        """
        if not self.verify_totp(secret, totp_code):
            logger.warning(f"Failed to verify TOTP code for user {username}")
            return False, "Invalid TOTP code. Please try again."

        if username not in self._mfa_state:
            return False, "TOTP secret not found. Please generate a new secret."

        state = self._mfa_state[username]

        # Store hashed recovery codes
        recovery_codes = state.get("backup_codes", [])
        state["recovery_codes"] = {
            self._hash_recovery_code(code): {"used": False, "used_at": None}
            for code in recovery_codes
        }

        # Enable MFA
        state["enabled"] = True
        state["enabled_at"] = datetime.now(timezone.utc)

        logger.info(f"MFA enabled for user {username}")
        return True, "MFA enabled successfully"

    def disable_mfa(self, username: str) -> None:
        """
        Disable MFA for a user.

        Args:
            username: Username to disable MFA for
        """
        if username in self._mfa_state:
            state = self._mfa_state[username]
            state["enabled"] = False
            state["secret"] = None
            state["recovery_codes"] = {}
            logger.info(f"MFA disabled for user {username}")

    def is_mfa_enabled(self, username: str) -> bool:
        """
        Check if MFA is enabled for a user.

        Args:
            username: Username to check

        Returns:
            True if MFA is enabled, False otherwise
        """
        if username not in self._mfa_state:
            return False
        return self._mfa_state[username].get("enabled", False)

    def get_totp_secret(self, username: str) -> Optional[str]:
        """
        Get TOTP secret for a user.

        Args:
            username: Username to get secret for

        Returns:
            TOTP secret if it exists, None otherwise
        """
        if username not in self._mfa_state:
            return None
        return self._mfa_state[username].get("secret")

    def verify_with_recovery_code(
        self, username: str, code: str
    ) -> MFAVerification:
        """
        Verify login using a recovery code (if TOTP device is lost).

        Args:
            username: Username verifying
            code: Recovery code to use

        Returns:
            MFAVerification result
        """
        if username not in self._mfa_state:
            return MFAVerification(
                is_valid=False,
                error="MFA not enabled for this user",
            )

        state = self._mfa_state[username]
        code_hash = self._hash_recovery_code(code)

        if code_hash not in state.get("recovery_codes", {}):
            logger.warning(
                f"Invalid recovery code attempt for user {username}"
            )
            return MFAVerification(
                is_valid=False,
                error="Invalid recovery code",
            )

        recovery_code_info = state["recovery_codes"][code_hash]
        if recovery_code_info["used"]:
            logger.warning(
                f"Recovery code already used for user {username}"
            )
            return MFAVerification(
                is_valid=False,
                error="Recovery code already used",
            )

        # Mark recovery code as used
        recovery_code_info["used"] = True
        recovery_code_info["used_at"] = datetime.now(timezone.utc)

        logger.info(f"Recovery code used for user {username}")
        return MFAVerification(
            is_valid=True,
            used_recovery_code=True,
        )

    def verify_mfa(
        self, username: str, totp_code: Optional[str] = None, recovery_code: Optional[str] = None
    ) -> MFAVerification:
        """
        Verify MFA using either TOTP or recovery code.

        Args:
            username: Username verifying
            totp_code: TOTP code (optional)
            recovery_code: Recovery code (optional)

        Returns:
            MFAVerification result
        """
        if not self.is_mfa_enabled(username):
            return MFAVerification(
                is_valid=False,
                error="MFA not enabled for this user",
            )

        # Try TOTP first
        if totp_code:
            secret = self.get_totp_secret(username)
            if secret and self.verify_totp(secret, totp_code):
                logger.info(f"MFA verification successful (TOTP) for user {username}")
                return MFAVerification(is_valid=True)
            else:
                logger.warning(f"TOTP verification failed for user {username}")
                return MFAVerification(
                    is_valid=False,
                    error="Invalid TOTP code",
                )

        # Try recovery code
        if recovery_code:
            return self.verify_with_recovery_code(username, recovery_code)

        return MFAVerification(
            is_valid=False,
            error="TOTP code or recovery code required",
        )


# Global instance for singleton pattern
_mfa_manager: Optional[MFAManager] = None


def get_mfa_manager(
    issuer: str = "Socrates",
    totp_window: int = 1,
    backup_code_count: int = 10,
) -> MFAManager:
    """
    Get or create the global MFA manager.

    Args:
        issuer: Name displayed in authenticator app
        totp_window: Number of time windows to allow
        backup_code_count: Number of backup codes to generate

    Returns:
        Global MFAManager instance
    """
    global _mfa_manager

    if _mfa_manager is None:
        _mfa_manager = MFAManager(
            issuer=issuer,
            totp_window=totp_window,
            backup_code_count=backup_code_count,
        )

    return _mfa_manager
