from datetime import datetime
import json

from backend.core.logger import logger
from backend.database.manager import db


class AuditLogger:
    """
    Security audit logging system for Cyber Sentinel X.

    Records important user and system actions.
    """

    def record(
        self,
        action,
        username=None,
        resource=None,
        resource_id=None,
        source_ip=None,
        details=None
    ):
        timestamp = datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        self._write_database(
            timestamp=timestamp,
            username=username,
            action=action,
            resource=resource,
            resource_id=resource_id,
            source_ip=source_ip,
            details=details
        )

        logger.info(
            f"AUDIT | action={action} | "
            f"user={username or 'SYSTEM'} | "
            f"resource={resource or '-'}"
        )

    def _write_database(
        self,
        timestamp,
        username,
        action,
        resource,
        resource_id,
        source_ip,
        details
    ):
        # SQLite cannot directly store Python dict/list objects.
        # Convert structured audit details into JSON text.
        if isinstance(details, (dict, list)):
            details = json.dumps(
                details,
                ensure_ascii=False,
                default=str
            )

        db.insert(
            "audit_logs",
            {
                "timestamp": timestamp,
                "username": username,
                "action": action,
                "resource": resource,
                "resource_id": resource_id,
                "source_ip": source_ip,
                "details": details
            }
        )

    def login_success(self, username, source_ip=None):
        self.record(
            action="LOGIN_SUCCESS",
            username=username,
            resource="authentication",
            source_ip=source_ip,
            details="User authentication successful"
        )

    def login_failure(self, username, source_ip=None):
        self.record(
            action="LOGIN_FAILURE",
            username=username,
            resource="authentication",
            source_ip=source_ip,
            details="User authentication failed"
        )

    def logout(self, username, source_ip=None):
        self.record(
            action="LOGOUT",
            username=username,
            resource="authentication",
            source_ip=source_ip,
            details="User logged out"
        )

    def system_action(self, action, details=None):
        self.record(
            action=action,
            username="SYSTEM",
            resource="system",
            details=details
        )


audit = AuditLogger()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - SECURITY AUDIT LOGGER")
    print("=" * 60)

    audit.system_action(
        action="AUDIT_TEST",
        details="Security audit logging system test"
    )

    print("Audit event : CREATED")
    print("Audit table : audit_logs")
    print("Audit system: READY")
