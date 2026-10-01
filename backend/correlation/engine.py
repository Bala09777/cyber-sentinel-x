from datetime import datetime, timedelta
import uuid

from backend.core.config import settings
from backend.core.logger import logger
from backend.database.manager import db


class CorrelationEngine:
    """
    Correlates related security events and creates incidents.

    Defensive purpose:
    Groups multiple related events into a single
    investigation-ready incident.
    """

    def __init__(self):
        self.window_seconds = settings.CORRELATION_WINDOW_SECONDS
        self.minimum_events = settings.MIN_EVENTS_FOR_INCIDENT

    def generate_incident_id(self):
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        unique_id = uuid.uuid4().hex[:8].upper()

        return f"INC-{timestamp}-{unique_id}"

    def calculate_incident_severity(self, events):
        highest_risk = max(
            int(event.get("risk_score", 0))
            for event in events
        )

        if highest_risk >= 80:
            return "CRITICAL"

        if highest_risk >= 60:
            return "HIGH"

        if highest_risk >= 40:
            return "MEDIUM"

        return "LOW"

    def calculate_incident_risk(self, events):
        scores = [
            int(event.get("risk_score", 0))
            for event in events
        ]

        if not scores:
            return 0

        average_score = sum(scores) / len(scores)
        highest_score = max(scores)

        risk = (
            (average_score * 0.4)
            + (highest_score * 0.6)
        )

        return min(100, round(risk))

    def get_related_events(
        self,
        source_ip,
        destination_ip=None
    ):
        cutoff = datetime.utcnow() - timedelta(
            seconds=self.window_seconds
        )

        cutoff_string = cutoff.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        if destination_ip:
            return db.fetch_all(
                """
                SELECT *
                FROM events
                WHERE source_ip = ?
                  AND destination_ip = ?
                  AND timestamp >= ?
                  AND severity IN (
                      'SUSPICIOUS',
                      'HIGH',
                      'CRITICAL'
                  )
                ORDER BY id ASC
                """,
                (
                    source_ip,
                    destination_ip,
                    cutoff_string
                )
            )

        return db.fetch_all(
            """
            SELECT *
            FROM events
            WHERE source_ip = ?
              AND timestamp >= ?
              AND severity IN (
                  'SUSPICIOUS',
                  'HIGH',
                  'CRITICAL'
              )
            ORDER BY id ASC
            """,
            (
                source_ip,
                cutoff_string
            )
        )

    def incident_already_exists(
        self,
        source_ip,
        destination_ip=None
    ):
        if destination_ip:
            result = db.fetch_one(
                """
                SELECT incident_id
                FROM incidents
                WHERE source_ip = ?
                  AND destination_ip = ?
                  AND status IN (
                      'OPEN',
                      'INVESTIGATING'
                  )
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    source_ip,
                    destination_ip
                )
            )
        else:
            result = db.fetch_one(
                """
                SELECT incident_id
                FROM incidents
                WHERE source_ip = ?
                  AND status IN (
                      'OPEN',
                      'INVESTIGATING'
                  )
                ORDER BY id DESC
                LIMIT 1
                """,
                (source_ip,)
            )

        return result["incident_id"] if result else None

    def create_incident(
        self,
        events,
        attack_type="Correlated Network Activity"
    ):
        if len(events) < self.minimum_events:
            return None

        source_ip = events[0].get("source_ip")
        destination_ip = events[0].get("destination_ip")

        existing_incident = self.incident_already_exists(
            source_ip,
            destination_ip
        )

        if existing_incident:
            self._attach_new_events(
                existing_incident,
                events
            )

            logger.info(
                f"INCIDENT_UPDATED | "
                f"id={existing_incident} | "
                f"events={len(events)}"
            )

            return db.fetch_one(
                """
                SELECT *
                FROM incidents
                WHERE incident_id = ?
                """,
                (existing_incident,)
            )

        incident_id = self.generate_incident_id()

        severity = self.calculate_incident_severity(
            events
        )

        risk_score = self.calculate_incident_risk(
            events
        )

        timestamps = [
            event.get("timestamp")
            for event in events
            if event.get("timestamp")
        ]

        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None

        activity_types = sorted(
            set(
                event.get("activity")
                for event in events
                if event.get("activity")
            )
        )

        description = (
            f"Correlated {len(events)} security events "
            f"from {source_ip}. "
            f"Observed activities: "
            f"{', '.join(activity_types) or 'Network anomalies'}."
        )

        timestamp = datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        incident = {
            "incident_id": incident_id,
            "title": f"{severity} Correlated Network Activity",
            "description": description,
            "severity": severity,
            "risk_score": risk_score,
            "status": "OPEN",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "attack_type": attack_type,
            "mitre_tactic": None,
            "mitre_technique": None,
            "assigned_to": None,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "created_at": timestamp,
            "updated_at": timestamp
        }

        db.insert(
            "incidents",
            incident
        )

        for event in events:
            self.attach_event(
                incident_id,
                event.get("event_id")
            )

        logger.warning(
            f"INCIDENT_CREATED | "
            f"id={incident_id} | "
            f"severity={severity} | "
            f"risk={risk_score} | "
            f"events={len(events)}"
        )

        return incident

    def attach_event(
        self,
        incident_id,
        event_id
    ):
        if not event_id:
            return

        try:
            db.insert(
                "incident_events",
                {
                    "incident_id": incident_id,
                    "event_id": event_id,
                    "created_at": datetime.utcnow().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                }
            )

        except Exception as error:
            logger.debug(
                f"INCIDENT_EVENT_DUPLICATE | "
                f"incident={incident_id} | "
                f"event={event_id} | "
                f"error={error}"
            )

    def _attach_new_events(
        self,
        incident_id,
        events
    ):
        for event in events:
            self.attach_event(
                incident_id,
                event.get("event_id")
            )

        now = datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        db.update(
            "incidents",
            {
                "updated_at": now,
                "last_seen": now
            },
            "incident_id = ?",
            (incident_id,)
        )

    def correlate_source(
        self,
        source_ip,
        destination_ip=None
    ):
        events = self.get_related_events(
            source_ip,
            destination_ip
        )

        if len(events) < self.minimum_events:
            logger.info(
                f"CORRELATION_SKIPPED | "
                f"src={source_ip} | "
                f"events={len(events)}"
            )

            return None

        return self.create_incident(
            events
        )

    def get_incident(self, incident_id):
        return db.fetch_one(
            """
            SELECT *
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,)
        )

    def get_recent_incidents(self, limit=100):
        limit = max(
            1,
            min(1000, int(limit))
        )

        return db.fetch_all(
            f"""
            SELECT *
            FROM incidents
            ORDER BY id DESC
            LIMIT {limit}
            """
        )

    def get_open_incidents(self):
        return db.fetch_all(
            """
            SELECT *
            FROM incidents
            WHERE status IN (
                'OPEN',
                'INVESTIGATING'
            )
            ORDER BY id DESC
            """
        )

    def update_status(
        self,
        incident_id,
        status
    ):
        allowed_statuses = {
            "OPEN",
            "INVESTIGATING",
            "RESOLVED",
            "CLOSED"
        }

        status = status.upper()

        if status not in allowed_statuses:
            raise ValueError(
                f"Invalid incident status: {status}"
            )

        result = db.update(
            "incidents",
            {
                "status": status,
                "updated_at": datetime.utcnow().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            },
            "incident_id = ?",
            (incident_id,)
        )

        logger.info(
            f"INCIDENT_STATUS_CHANGED | "
            f"id={incident_id} | "
            f"status={status}"
        )

        return result


correlation_engine = CorrelationEngine()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - CORRELATION ENGINE")
    print("=" * 60)

    print(
        f"Correlation Window : "
        f"{correlation_engine.window_seconds}s"
    )

    print(
        f"Minimum Events     : "
        f"{correlation_engine.minimum_events}"
    )

    print("Correlation Engine : READY")
