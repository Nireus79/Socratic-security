"""
Database Encryption - Field-level encryption for sensitive data.

Provides transparent encryption/decryption for database values using Fernet.
"""

import logging
import os
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("socratic_security.database.encryption")


class EncryptedField:
    """Wrapper for encrypting/decrypting sensitive database fields."""

    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize encrypted field.

        Args:
            encryption_key: Fernet key (base64 encoded). If not provided,
                          uses DATABASE_ENCRYPTION_KEY environment variable.
        """
        if encryption_key is None:
            encryption_key = os.getenv("DATABASE_ENCRYPTION_KEY")

        if not encryption_key:
            logger.warning(
                "No encryption key provided. Database encryption will be disabled."
            )
            self.cipher = None
            return

        try:
            self.cipher = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
            logger.info("Database encryption initialized")
        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")
            self.cipher = None

    def encrypt(self, value: Any) -> Optional[str]:
        """
        Encrypt a value.

        Args:
            value: Value to encrypt (will be converted to string)

        Returns:
            Encrypted value (base64 encoded), or original value if encryption disabled
        """
        if self.cipher is None:
            return str(value) if value is not None else None

        if value is None:
            return None

        try:
            # Convert to string if needed
            str_value = str(value) if not isinstance(value, str) else value

            # Encrypt and decode to string
            encrypted = self.cipher.encrypt(str_value.encode())
            return encrypted.decode()

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise ValueError(f"Failed to encrypt value: {e}")

    def decrypt(self, encrypted_value: Any) -> Optional[str]:
        """
        Decrypt a value.

        Args:
            encrypted_value: Encrypted value to decrypt

        Returns:
            Decrypted value, or original value if encryption disabled
        """
        if self.cipher is None:
            return str(encrypted_value) if encrypted_value is not None else None

        if encrypted_value is None:
            return None

        try:
            # Handle both string and bytes input
            if isinstance(encrypted_value, str):
                encrypted_value = encrypted_value.encode()

            # Decrypt and decode to string
            decrypted = self.cipher.decrypt(encrypted_value)
            return decrypted.decode()

        except InvalidToken:
            logger.error("Invalid encrypted token - may be corrupted or using wrong key")
            raise ValueError("Failed to decrypt value - invalid token")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError(f"Failed to decrypt value: {e}")

    def is_encrypted(self, value: Any) -> bool:
        """
        Check if a value appears to be encrypted (base64 string starting with gAAAAA).

        Args:
            value: Value to check

        Returns:
            True if value appears encrypted, False otherwise
        """
        if value is None or self.cipher is None:
            return False

        try:
            str_value = str(value) if not isinstance(value, str) else value
            # Fernet tokens are base64-encoded and start with 'gAAAAAA'
            # (the base64 encoding of the Fernet version byte)
            return isinstance(str_value, str) and str_value.startswith("gAAAAAA")
        except Exception:
            return False


# Global encryption instance
_encryption: Optional[EncryptedField] = None


def get_encryption() -> EncryptedField:
    """
    Get or create the global encryption instance.

    Returns:
        Global EncryptedField instance
    """
    global _encryption
    if _encryption is None:
        _encryption = EncryptedField()
    return _encryption


def encrypt_value(value: Any) -> Optional[str]:
    """
    Encrypt a value using global encryption instance.

    Args:
        value: Value to encrypt

    Returns:
        Encrypted value
    """
    return get_encryption().encrypt(value)


def decrypt_value(encrypted_value: Any) -> Optional[str]:
    """
    Decrypt a value using global encryption instance.

    Args:
        encrypted_value: Value to decrypt

    Returns:
        Decrypted value
    """
    return get_encryption().decrypt(encrypted_value)
