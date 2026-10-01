from datetime import datetime

from backend.database.manager import db
from backend.core.logger import logger
from backend.core.audit import audit
from backend.behaviour.behaviour_engine import behaviour_engine
from backend.ml.anomaly_detector import anomaly_detector
from backend.intelligence.threat_intel import threat_intelligence


class IncidentService:

    VALID_STATUS = {
        "OPEN",
        "INVESTIGATING",
        "RESOLVED",
        "CLOSED"
    }

    def _now(self):
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    def get_incident(self, incident_id):
        return db.fetch_one(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,)
        )

    def get_all(self, limit=100):
        return db.fetch_all(
            """
            SELECT *
            FROM incidents
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (limit,)
        )

    def get_open(self):
        return db.fetch_all(
            """
            SELECT *
            FROM incidents
            WHERE status IN ('OPEN', 'INVESTIGATING')
            ORDER BY risk_score DESC, updated_at DESC
            """
        )

    def update_status(self, incident_id, status, user="SOC_ANALYST"):
        status = status.upper()

        if status not in self.VALID_STATUS:
            raise ValueError(
                f"Invalid incident status: {status}"
            )

        incident = self.get_incident(incident_id)

        if not incident:
            return False

        now = self._now()

        db.update(
            "incidents",
            {
                "status": status,
                "updated_at": now
            },
            "incident_id = ?",
            (incident_id,)
        )

        audit.record(
            action="INCIDENT_STATUS_CHANGED",
            username=user,
            resource="incident",
            resource_id=incident_id,
            details=f"status={status}"
        )

        logger.info(
            f"INCIDENT_STATUS_CHANGED | "
            f"id={incident_id} | status={status}"
        )

        return True

    def assign(self, incident_id, analyst):
        incident = self.get_incident(incident_id)

        if not incident:
            return False

        now = self._now()

        db.update(
            """
            UPDATE incidents
            SET assigned_to = ?,
                updated_at = ?
            WHERE incident_id = ?
            """,
            (analyst, now, incident_id)
        )

        audit.record(
            action="INCIDENT_ASSIGNED",
            user=analyst,
            resource="incident",
            resource_id=incident_id,
            details=f"assigned_to={analyst}"
        )

        logger.info(
            f"INCIDENT_ASSIGNED | "
            f"id={incident_id} | analyst={analyst}"
        )

        return True

    def get_timeline(self, incident_id):
        return db.fetch_all(
            """
            SELECT
                e.event_id,
                e.source_ip,
                e.destination_ip,
                e.protocol,
                e.source_port,
                e.destination_port,
                e.packet_count,
                e.unique_ports,
                e.risk_score,
                e.severity,
                e.activity,
                e.anomaly_score,
                e.created_at
            FROM incident_events ie
            JOIN events e
                ON e.event_id = ie.event_id
            JOIN incidents i
                ON i.incident_id = ie.incident_id
            WHERE ie.incident_id = ?
            ORDER BY e.created_at ASC
            """,
            (incident_id,)
        )

    def get_analysis(self, incident_id):
        incident = self.get_incident(incident_id)

        if not incident:
            return None

        events = [dict(row) for row in self.get_timeline(incident_id)]
        source_ip = incident["source_ip"]

        behaviour = behaviour_engine.analyze_source(source_ip)

        ml_results = [
            anomaly_detector.predict(event)
            for event in events
        ]

        ml_score = max(
            (float(result.get("anomaly_score", 0)) for result in ml_results),
            default=0.0
        )

        ml_threshold = (
            float(ml_results[0].get("threshold", 0))
            if ml_results else 0.0
        )

        ml_anomalies = sum(
            1
            for result in ml_results
            if result.get("is_anomaly")
        )

        threat_intel = threat_intelligence.assess(source_ip)

        return {
            "incident_id": incident_id,
            "behaviour": behaviour,
            "ml": {
                "anomaly_score": round(ml_score, 4),
                "threshold": ml_threshold,
                "is_anomaly": ml_anomalies > 0,
                "anomalous_events": ml_anomalies,
                "event_count": len(ml_results),
                "method": (
                    ml_results[0].get("method")
                    if ml_results else "NO_EVENTS"
                )
            },
            "threat_intelligence": threat_intel
        }

    def get_statistics(self):
        total = db.count("incidents")

        open_count = db.count(
            "incidents",
            "status IN ('OPEN', 'INVESTIGATING')"
        )

        critical = db.count(
            "incidents",
            "severity = 'CRITICAL'"
        )

        high = db.count(
            "incidents",
            "severity = 'HIGH'"
        )

        return {
            "total": total,
            "open": open_count,
            "critical": critical,
            "high": high
        }


incident_service = IncidentService()


if __name__ == "__main__":
    print("=" * 60)
    print("CYBER SENTINEL X - INCIDENT SERVICE")
    print("=" * 60)

    stats = incident_service.get_statistics()

    print("Total Incidents :", stats["total"])
    print("Open Incidents  :", stats["open"])
    print("Critical        :", stats["critical"])
    print("High            :", stats["high"])
    print("Incident Service: READY")
    print("=" * 60)
