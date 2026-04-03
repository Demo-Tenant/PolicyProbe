"""
Audit Logger

Provides audit logging for security-relevant events.
"""

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)

_AUDIT_HMAC_KEY = os.environ.get("AUDIT_HMAC_KEY", os.urandom(32))


def _compute_integrity_tag(event: dict) -> str:
    """Compute an HMAC tag for tamper-evidence."""
    serialized = json.dumps(event, sort_keys=True, default=str).encode("utf-8")
    key = _AUDIT_HMAC_KEY if isinstance(_AUDIT_HMAC_KEY, bytes) else _AUDIT_HMAC_KEY.encode("utf-8")
    return hmac.new(key, serialized, hashlib.sha256).hexdigest()


class AuditLogger:
    """
    Audit logging for security events with tamper-evident records.
    """

    def __init__(self):
        self._events = []

    async def log_event(
        self,
        event_type: str,
        details: dict[str, Any],
        user_id: Optional[str] = None,
        severity: str = "info"
    ) -> None:
        """
        Log a security-relevant event with integrity protection.
        """
        # Sanitize inputs to prevent log injection
        safe_event_type = str(event_type).replace("\n", "").replace("\r", "")[:128]
        safe_user_id = str(user_id).replace("\n", "").replace("\r", "")[:256] if user_id else None
        safe_severity = str(severity).replace("\n", "").replace("\r", "")[:32]

        # Sanitize details values to prevent log injection
        safe_details = {}
        for k, v in details.items():
            safe_key = str(k).replace("\n", "").replace("\r", "")[:128]
            safe_val = str(v).replace("\n", " ").replace("\r", " ") if isinstance(v, str) else v
            safe_details[safe_key] = safe_val

        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": safe_event_type,
            "details": safe_details,
            "user_id": safe_user_id,
            "severity": safe_severity
        }

        # Compute integrity tag for tamper-evidence
        event["integrity_tag"] = _compute_integrity_tag(
            {k: v for k, v in event.items() if k != "integrity_tag"}
        )

        self._events.append(event)

        log_fn = logger.warning if safe_severity in ("warning", "error", "critical") else logger.info
        log_fn(
            "Audit: %s user=%s severity=%s",
            safe_event_type,
            safe_user_id,
            safe_severity,
            extra={"audit_event": event}
        )

    async def log_policy_violation(
        self,
        policy_type: str,
        violation_details: dict
    ) -> None:
        """
        Log a policy violation.
        """
        await self.log_event(
            event_type="policy_violation",
            details={
                "policy": policy_type,
                **violation_details
            },
            severity="warning"
        )

    async def log_data_access(
        self,
        resource: str,
        action: str,
        user_id: str
    ) -> None:
        """
        Log data access for compliance.
        """
        await self.log_event(
            event_type="data_access",
            details={
                "resource": resource,
                "action": action
            },
            user_id=user_id
        )

    def get_recent_events(self, count: int = 100) -> list[dict]:
        """Get recent audit events."""
        safe_count = max(1, min(int(count), 1000))
        return self._events[-safe_count:]

    def verify_event_integrity(self, event: dict) -> bool:
        """Verify the integrity tag of a stored audit event."""
        tag = event.get("integrity_tag")
        if not tag:
            return False
        payload = {k: v for k, v in event.items() if k != "integrity_tag"}
        expected = _compute_integrity_tag(payload)
        return hmac.compare_digest(tag, expected)