"""
Audit logging module for security events and user actions.

Provides comprehensive logging for:
- Authentication events (login, logout, registration)
- Account events (lockout, role changes)
- Data access (read, write, delete)
- Security events (injection attempts, token theft)
"""

from socratic_security.audit.logger import (
    AuditEvent,
    AuditLogger,
    get_audit_logger,
)

__all__ = [
    "AuditEvent",
    "AuditLogger",
    "get_audit_logger",
]
