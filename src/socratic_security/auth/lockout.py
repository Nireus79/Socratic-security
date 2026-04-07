"""
Account Lockout Manager - Prevents brute force attacks on user accounts.

Tracks failed login attempts and implements progressive account lockout.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

logger = logging.getLogger("socratic_security.auth.lockout")


@dataclass
class LockoutInfo:
    """Information about a locked account."""

    is_locked: bool
    locked_until: Optional[datetime] = None
    lockout_count: int = 0
    remaining_minutes: int = 0
    reason: str = ""


class AccountLockoutManager:
    """Manages account lockout after failed login attempts."""

    def __init__(
        self,
        max_attempts: int = 5,
        lockout_window_minutes: int = 15,
        initial_lockout_minutes: int = 30,
        progressive_lockout: bool = True,
    ):
        """
        Initialize lockout manager.

        Args:
            max_attempts: Number of failed attempts before lockout
            lockout_window_minutes: Time window to count attempts
            initial_lockout_minutes: Initial lockout duration
            progressive_lockout: Increase duration on repeated lockouts
        """
        self.max_attempts = max_attempts
        self.lockout_window_minutes = lockout_window_minutes
        self.initial_lockout_minutes = initial_lockout_minutes
        self.progressive_lockout = progressive_lockout

        # In-memory storage: {username: {"attempts": [...], "lockout_until": datetime}}
        self._account_state: Dict = {}

    def record_attempt(self, username: str, ip_address: str, success: bool) -> None:
        """
        Record a login attempt.

        Args:
            username: Username attempting to login
            ip_address: IP address of the attempt
            success: Whether the attempt was successful
        """
        if username not in self._account_state:
            self._account_state[username] = {
                "attempts": [],
                "lockout_until": None,
                "lockout_count": 0,
            }

        state = self._account_state[username]

        if success:
            # Clear failed attempts on successful login
            logger.info(f"Successful login for user {username}, clearing attempts")
            state["attempts"] = []
            return

        # Record failed attempt
        now = datetime.now(timezone.utc)
        state["attempts"].append({"timestamp": now, "ip_address": ip_address})

        # Remove attempts outside the window
        window_start = now - timedelta(minutes=self.lockout_window_minutes)
        state["attempts"] = [a for a in state["attempts"] if a["timestamp"] > window_start]

        logger.warning(
            f"Failed login attempt for {username} from {ip_address} "
            f"(attempt {len(state['attempts'])} of {self.max_attempts})"
        )

    def is_locked_out(self, username: str) -> bool:
        """
        Check if account is currently locked out.

        Args:
            username: Username to check

        Returns:
            True if account is locked, False otherwise
        """
        if username not in self._account_state:
            return False

        state = self._account_state[username]
        lockout_until = state.get("lockout_until")

        if lockout_until is None:
            return False

        now = datetime.now(timezone.utc)
        if now > lockout_until:
            # Lockout expired, unlock account
            logger.info(f"Lockout expired for user {username}")
            state["lockout_until"] = None
            return False

        return True

    def check_and_lock(self, username: str, ip_address: str) -> Optional[LockoutInfo]:
        """
        Check if account should be locked and apply lockout if needed.

        Args:
            username: Username to check
            ip_address: IP address of current attempt

        Returns:
            LockoutInfo if account just got locked, None otherwise
        """
        if username not in self._account_state:
            self._account_state[username] = {
                "attempts": [],
                "lockout_until": None,
                "lockout_count": 0,
            }

        state = self._account_state[username]

        # Count attempts in current window
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=self.lockout_window_minutes)
        recent_attempts = [a for a in state["attempts"] if a["timestamp"] > window_start]

        if len(recent_attempts) >= self.max_attempts:
            # Lock the account
            lockout_count = state.get("lockout_count", 0) + 1
            state["lockout_count"] = lockout_count

            if self.progressive_lockout:
                # Progressive lockout: 30min -> 1hr -> 2hrs -> 4hrs, etc.
                lockout_minutes = self.initial_lockout_minutes * (2 ** (lockout_count - 1))
            else:
                lockout_minutes = self.initial_lockout_minutes

            lockout_until = now + timedelta(minutes=lockout_minutes)
            state["lockout_until"] = lockout_until

            logger.warning(
                f"Account locked for user {username} from {ip_address} "
                f"after {len(recent_attempts)} failed attempts. "
                f"Lockout duration: {lockout_minutes} minutes. "
                f"Lockout count: {lockout_count}"
            )

            return LockoutInfo(
                is_locked=True,
                locked_until=lockout_until,
                lockout_count=lockout_count,
                remaining_minutes=lockout_minutes,
                reason=f"Too many failed login attempts ({len(recent_attempts)} in {self.lockout_window_minutes} minutes)",
            )

        return None

    def get_lockout_info(self, username: str) -> LockoutInfo:
        """
        Get current lockout information for an account.

        Args:
            username: Username to check

        Returns:
            LockoutInfo with current lockout status
        """
        if username not in self._account_state:
            return LockoutInfo(is_locked=False)

        state = self._account_state[username]
        lockout_until = state.get("lockout_until")

        if lockout_until is None:
            return LockoutInfo(is_locked=False)

        now = datetime.now(timezone.utc)
        if now > lockout_until:
            # Lockout expired
            state["lockout_until"] = None
            return LockoutInfo(is_locked=False)

        remaining = (lockout_until - now).total_seconds() / 60
        return LockoutInfo(
            is_locked=True,
            locked_until=lockout_until,
            lockout_count=state.get("lockout_count", 0),
            remaining_minutes=int(remaining),
            reason="Account locked due to too many failed login attempts",
        )

    def unlock_account(self, username: str) -> None:
        """
        Manually unlock an account.

        Args:
            username: Username to unlock
        """
        if username in self._account_state:
            state = self._account_state[username]
            state["lockout_until"] = None
            state["lockout_count"] = 0
            state["attempts"] = []
            logger.info(f"Account manually unlocked: {username}")

    def reset_attempts(self, username: str) -> None:
        """
        Reset failed attempts for an account (without unlocking).

        Args:
            username: Username to reset
        """
        if username in self._account_state:
            self._account_state[username]["attempts"] = []
            logger.info(f"Failed attempts reset for user {username}")


# Global instance for singleton pattern
_lockout_manager: Optional[AccountLockoutManager] = None


def get_lockout_manager(
    max_attempts: int = 5,
    lockout_window_minutes: int = 15,
    initial_lockout_minutes: int = 30,
    progressive_lockout: bool = True,
) -> AccountLockoutManager:
    """
    Get or create the global lockout manager.

    Args:
        max_attempts: Number of failed attempts before lockout
        lockout_window_minutes: Time window to count attempts
        initial_lockout_minutes: Initial lockout duration
        progressive_lockout: Increase duration on repeated lockouts

    Returns:
        Global AccountLockoutManager instance
    """
    global _lockout_manager

    if _lockout_manager is None:
        _lockout_manager = AccountLockoutManager(
            max_attempts=max_attempts,
            lockout_window_minutes=lockout_window_minutes,
            initial_lockout_minutes=initial_lockout_minutes,
            progressive_lockout=progressive_lockout,
        )

    return _lockout_manager
