from datetime import datetime
import uuid

from backend.core.logger import logger
from backend.database.manager import db


class EventService:
    """
    Central service for creating and storing
    normalized security events.
    """

    def __init__(self):
        self.service_name = "EventService"

    def generate_event_id(self):
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        unique_id = uuid.uuid4().hex[:8].upper()

        return f"CSX-{timestamp}-{unique_id}"

    def calculate_severity(self, risk_score):
        if risk_score >= 80:
            return "CRITICAL"

        if risk_score >= 60:
            return "HIGH"

        if risk_score >= 40:
            return "SUSPICIOUS"

        return "NORMAL"

    def create_event(
        self,
        source_ip,
        destination_ip,
        source_port=None,
        destination_port=None,
        protocol=None,
        packet_count=0,
        unique_ports=0,
        risk_score=0,
        activity=None,
        country="Unknown",
        city="Unknown",
        organization="Unknown",
        asn="Unknown",
        anomaly_score=0.0
    ):
        event_id = self.generate_event_id()

        risk_score = max(
            0,
            min(100, int(risk_score))
        )

        severity = self.calculate_severity(
            risk_score
        )

        timestamp = datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        event = {
            "event_id": event_id,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": str(source_port)
                if source_port is not None else None,
            "destination_port": str(destination_port)
                if destination_port is not None else None,
            "protocol": protocol,
            "packet_count": int(packet_count),
            "unique_ports": int(unique_ports),
            "risk_score": risk_score,
            "severity": severity,
            "activity": activity,
            "country": country,
            "city": city,
            "organization": organization,
            "asn": asn,
            "anomaly_score": float(anomaly_score),
            "created_at": timestamp
        }

        db.insert(
            "events",
            event
        )

        logger.info(
            f"EVENT_CREATED | "
            f"id={event_id} | "
            f"src={source_ip} | "
            f"dst={destination_ip} | "
            f"severity={severity} | "
            f"risk={risk_score}"
        )

        return event

    def get_event(self, event_id):
        return db.fetch_one(
            """
            SELECT *
            FROM events
            WHERE event_id = ?
            """,
            (event_id,)
        )

    def get_recent_events(self, limit=100):
        limit = max(
            1,
            min(1000, int(limit))
        )

        return db.fetch_all(
            f"""
            SELECT *
            FROM events
            ORDER BY id DESC
            LIMIT {limit}
            """
        )

    def get_events_by_severity(
        self,
        severity,
        limit=100
    ):
        limit = max(
            1,
            min(1000, int(limit))
        )

        return db.fetch_all(
            f"""
            SELECT *
            FROM events
            WHERE severity = ?
            ORDER BY id DESC
            LIMIT {limit}
            """,
            (severity.upper(),)
        )

    def get_event_count(self):
        return db.count("events")


event_service = EventService()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - EVENT SERVICE")
    print("=" * 60)

    test_event = event_service.create_event(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        source_port=49152,
        destination_port=443,
        protocol="TCP",
        packet_count=25,
        unique_ports=2,
        risk_score=45,
        activity="Test security event",
        anomaly_score=0.12
    )

    print(f"Event ID : {test_event['event_id']}")
    print(f"Severity : {test_event['severity']}")
    print(f"Risk     : {test_event['risk_score']}")
    print(f"Events   : {event_service.get_event_count()}")
    print("Event Service : READY")
