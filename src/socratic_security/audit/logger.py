"""
Audit Logging - Comprehensive logging of security events and user actions.

Tracks authentication, authorization, data access, and error events.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("socratic_security.audit")


@dataclass
class AuditEvent:
    """Represents an auditable event."""

    event_id: str
    timestamp: datetime
    user_id: Optional[str]
    ip_address: Optional[str]
    action: str
    resource_type: str
    resource_id: Optional[str]
    details: Dict[str, Any]
    status: str  # success, failure, warning
    error_message: Optional[str] = None


class AuditLogger:
    """Centralized audit logging for security events."""

    def __init__(self, retention_days: int = 30):
        """
        Initialize audit logger.

        Args:
            retention_days: Days to retain audit logs
        """
        self.retention_days = retention_days
        self._events: list[AuditEvent] = []

    def log_auth_event(
        self,
        action: str,
        user_id: Optional[str],
        ip_address: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
    ) -> str:
        """
        Log authentication event.

        Args:
            action: auth_action (login, logout, register, etc.)
            user_id: User performing action
            ip_address: Client IP address
            status: success, failure, warning
            details: Additional details
            error_message: Error if failed

        Returns:
            Event ID
        """
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            ip_address=ip_address,
            action=action,
            resource_type="auth",
            resource_id=user_id,
            details=details or {},
            status=status,
            error_message=error_message,
        )

        self._events.append(event)
        logger.info(f"Auth event: {action} for user={user_id} ip={ip_address} status={status}")

        return event.event_id

    def log_account_event(
        self,
        action: str,
        user_id: str,
        ip_address: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Log account-related event (lockout, unlock, role change)."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            ip_address=ip_address,
            action=action,
            resource_type="account",
            resource_id=user_id,
            details=details or {},
            status=status,
        )

        self._events.append(event)
        logger.info(f"Account event: {action} for user={user_id} status={status}")

        return event.event_id

    def log_data_access(
        self,
        action: str,
        user_id: str,
        resource_type: str,
        resource_id: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Log data access event (read, write, delete)."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            ip_address=None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            status=status,
        )

        self._events.append(event)
        logger.info(f"Data access: {action} {resource_type}:{resource_id} by user={user_id}")

        return event.event_id

    def log_security_event(
        self,
        action: str,
        user_id: Optional[str],
        ip_address: Optional[str],
        details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
    ) -> str:
        """Log security-related event (injection attempt, token theft, etc.)."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            ip_address=ip_address,
            action=action,
            resource_type="security",
            resource_id=None,
            details=details or {},
            status="failure",
            error_message=error_message,
        )

        self._events.append(event)
        logger.warning(f"Security event: {action} user={user_id} ip={ip_address}")

        return event.event_id

    def get_events(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """
        Retrieve audit events with optional filtering.

        Args:
            user_id: Filter by user
            action: Filter by action
            limit: Maximum number of events

        Returns:
            List of audit events
        """
        events = self._events

        if user_id:
            events = [e for e in events if e.user_id == user_id]

        if action:
            events = [e for e in events if e.action == action]

        # Return most recent first
        return sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]

    def clear_events(self) -> int:
        """Clear all in-memory events. Returns count cleared."""
        count = len(self._events)
        self._events = []
        return count


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger(retention_days: int = 30) -> AuditLogger:
    """
    Get or create the global audit logger.

    Args:
        retention_days: Days to retain audit logs

    Returns:
        Global AuditLogger instance
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(retention_days=retention_days)
    return _audit_logger
