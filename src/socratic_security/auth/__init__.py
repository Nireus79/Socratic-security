"""
Authentication security utilities.

Provides password validation, token management, account lockout protection,
and multi-factor authentication (TOTP).
"""

from socratic_security.auth.breach_checker import (
    PasswordBreachChecker,
    check_password_breach,
    get_breach_checker,
)
from socratic_security.auth.lockout import (
    AccountLockoutManager,
    LockoutInfo,
    get_lockout_manager,
)
from socratic_security.auth.mfa import (
    MFAManager,
    MFASetup,
    MFAVerification,
    get_mfa_manager,
)

__all__ = [
    "AccountLockoutManager",
    "LockoutInfo",
    "get_lockout_manager",
    "MFAManager",
    "MFASetup",
    "MFAVerification",
    "get_mfa_manager",
    "PasswordBreachChecker",
    "check_password_breach",
    "get_breach_checker",
]
