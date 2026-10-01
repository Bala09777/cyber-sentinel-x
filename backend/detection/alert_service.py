from datetime import datetime
import uuid

from backend.core.logger import logger
from backend.database.manager import db


class AlertService:
    """
    Central alert management service for Cyber Sentinel X.
    """

    ALERT_SEVERITIES = {
        "SUSPICIOUS",
        "HIGH",
        "CRITICAL"
    }

    def generate_alert_id(self):
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        unique_id = uuid.uuid4().hex[:8].upper()

        return f"ALT-{timestamp}-{unique_id}"

    def create_alert(self, event):
        severity = str(
            event.get("severity", "NORMAL")
        ).upper()

        if severity not in self.ALERT_SEVERITIES:
            return None

        alert_id = self.generate_alert_id()

        timestamp = datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip")
        risk_score = int(
            event.get("risk_score", 0)
        )
        activity = event.get(
            "activity",
            "Suspicious network activity detected"
        )

        title = f"{severity} Security Alert"

        message = (
            f"{activity}. "
            f"Source: {source_ip}. "
            f"Destination: {destination_ip}. "
            f"Risk score: {risk_score}/100."
        )

        alert = {
            "alert_id": alert_id,
            "event_id": event.get("event_id"),
            "timestamp": timestamp,
            "severity": severity,
            "title": title,
            "message": message,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "risk_score": risk_score,
            "status": "OPEN",
            "acknowledged": 0,
            "created_at": timestamp
        }

        db.insert(
            "alerts",
            alert
        )

        logger.warning(
            f"ALERT_CREATED | "
            f"id={alert_id} | "
            f"severity={severity} | "
            f"risk={risk_score} | "
            f"src={source_ip}"
        )

        return alert

    def create_from_event_id(self, event_id):
        event = db.fetch_one(
            """
            SELECT *
            FROM events
            WHERE event_id = ?
            """,
            (event_id,)
        )

        if not event:
            logger.warning(
                f"ALERT_EVENT_NOT_FOUND | "
                f"event_id={event_id}"
            )
            return None

        return self.create_alert(event)

    def get_alert(self, alert_id):
        return db.fetch_one(
            """
            SELECT *
            FROM alerts
            WHERE alert_id = ?
            """,
            (alert_id,)
        )

    def get_open_alerts(self, limit=100):
        limit = max(
            1,
            min(1000, int(limit))
        )

        return db.fetch_all(
            f"""
            SELECT *
            FROM alerts
            WHERE status = 'OPEN'
            ORDER BY id DESC
            LIMIT {limit}
            """
        )

    def get_recent_alerts(self, limit=100):
        limit = max(
            1,
            min(1000, int(limit))
        )

        return db.fetch_all(
            f"""
            SELECT *
            FROM alerts
            ORDER BY id DESC
            LIMIT {limit}
            """
        )

    def acknowledge_alert(self, alert_id):
        result = db.update(
            "alerts",
            {
                "acknowledged": 1,
                "status": "ACKNOWLEDGED"
            },
            "alert_id = ?",
            (alert_id,)
        )

        logger.info(
            f"ALERT_ACKNOWLEDGED | "
            f"id={alert_id}"
        )

        return result

    def close_alert(self, alert_id):
        result = db.update(
            "alerts",
            {
                "status": "CLOSED"
            },
            "alert_id = ?",
            (alert_id,)
        )

        logger.info(
            f"ALERT_CLOSED | "
            f"id={alert_id}"
        )

        return result

    def get_alert_count(self):
        return db.count("alerts")

    def get_open_alert_count(self):
        return db.count(
            "alerts",
            "status = ?",
            ("OPEN",)
        )


alert_service = AlertService()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - ALERT SERVICE")
    print("=" * 60)

    event = {
        "event_id": "CSX-TEST-ALERT-001",
        "severity": "HIGH",
        "risk_score": 75,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.100",
        "activity": "High-risk network behaviour detected"
    }

    alert = alert_service.create_alert(event)

    if alert:
        print(f"Alert ID : {alert['alert_id']}")
        print(f"Severity : {alert['severity']}")
        print(f"Risk     : {alert['risk_score']}")
        print(f"Status   : {alert['status']}")
    else:
        print("No alert created")

    print(
        f"Total Alerts : "
        f"{alert_service.get_alert_count()}"
    )

    print(
        f"Open Alerts  : "
        f"{alert_service.get_open_alert_count()}"
    )

    print("Alert Service : READY")
