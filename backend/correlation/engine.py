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

    def get_related_events(self, source_ip, destination_ip=None):
        """Recent suspicious events, excluding evidence from closed cases.

        Never fold already resolved/closed case evidence into a new incident.
        Evidence assigned to an active case remains eligible so a later
        suspicious event can update that existing case.
        """
        if not source_ip:
            return []
        cutoff = (datetime.utcnow() - timedelta(
            seconds=self.window_seconds
        )).strftime("%Y-%m-%d %H:%M:%S")
        sql = """
            SELECT e.* FROM events e
            WHERE e.source_ip = ? AND e.timestamp >= ?
              AND e.severity IN ('SUSPICIOUS', 'HIGH', 'CRITICAL')
              AND NOT EXISTS (
                  SELECT 1 FROM incident_events ie
                  JOIN incidents i ON i.incident_id = ie.incident_id
                  WHERE ie.event_id = e.event_id
                    AND (
                      i.status IN ('CLOSED', 'RESOLVED')
                      OR COALESCE(i.last_seen, i.created_at) < ?
                    )
              )
        """
        params = [source_ip, cutoff, cutoff]
        if destination_ip:
            sql += " AND e.destination_ip = ?"
            params.append(destination_ip)
        sql += " ORDER BY e.id ASC"
        return db.fetch_all(sql, tuple(params))

    def incident_already_exists(self, source_ip, destination_ip=None):
        """Only reuse an OPEN/INVESTIGATING case within the time window."""
        cutoff = (datetime.utcnow() - timedelta(
            seconds=self.window_seconds
        )).strftime("%Y-%m-%d %H:%M:%S")
        sql = """
            SELECT incident_id FROM incidents
            WHERE source_ip = ? AND status IN ('OPEN', 'INVESTIGATING')
              AND COALESCE(last_seen, created_at) >= ?
        """
        params = [source_ip, cutoff]
        if destination_ip:
            sql += " AND destination_ip = ?"
            params.append(destination_ip)
        sql += " ORDER BY id DESC LIMIT 1"
        result = db.fetch_one(sql, tuple(params))
        return result["incident_id"] if result else None

    def create_incident(self, events, attack_type="Correlated Network Activity"):
        """Atomically create/update one case and attach distinct evidence.

        BEGIN IMMEDIATE serializes writers so overlapping network flow
        workers cannot independently create duplicate open incidents.
        """
        if len(events) < self.minimum_events:
            return None
        source_ip = events[0].get("source_ip")
        if not source_ip:
            return None
        destinations = {e.get("destination_ip") for e in events}
        destination_ip = next(iter(destinations)) if len(destinations) == 1 else None
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        cutoff = (datetime.utcnow() - timedelta(
            seconds=self.window_seconds
        )).strftime("%Y-%m-%d %H:%M:%S")

        # Do not invoke db.fetch_one/db.insert inside the locked transaction:
        # those open separate connections and could deadlock.
        with db.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            sql = """
                SELECT incident_id FROM incidents
                WHERE source_ip = ? AND status IN ('OPEN', 'INVESTIGATING')
                  AND COALESCE(last_seen, created_at) >= ?
            """
            params = [source_ip, cutoff]
            if destination_ip:
                sql += " AND destination_ip = ?"
                params.append(destination_ip)
            sql += " ORDER BY id DESC LIMIT 1"
            match = conn.execute(sql, tuple(params)).fetchone()
            created = match is None
            if created:
                incident_id = self.generate_incident_id()
                conn.execute("""
                    INSERT INTO incidents (
                        incident_id, title, description, severity, risk_score,
                        status, source_ip, destination_ip, attack_type,
                        mitre_tactic, mitre_technique, assigned_to,
                        first_seen, last_seen, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (incident_id, "Correlated Network Activity", "",
                      "MEDIUM", 0, "OPEN", source_ip, destination_ip,
                      attack_type, None, None, None,
                      now, now, now, now))
            else:
                incident_id = match["incident_id"]

            new_links = 0
            for event in events:
                if not event.get("event_id"):
                    continue
                result = conn.execute("""
                    INSERT OR IGNORE INTO incident_events
                    (incident_id, event_id, created_at)
                    VALUES (?, ?, ?)
                """, (incident_id, event["event_id"], now))
                new_links += result.rowcount

            if new_links:
                linked = [dict(row) for row in conn.execute("""
                    SELECT e.* FROM incident_events ie
                    JOIN events e ON e.event_id = ie.event_id
                    WHERE ie.incident_id = ? ORDER BY e.id ASC
                """, (incident_id,)).fetchall()]
                severity = self.calculate_incident_severity(linked)
                risk = self.calculate_incident_risk(linked)
                times = [e["timestamp"] for e in linked if e.get("timestamp")]
                first_seen = min(times) if times else now
                last_seen = max(times) if times else now
                activities = sorted({str(e["activity"]) for e in linked
                                     if e.get("activity")})
                desc = (
                    f"Correlated {len(linked)} suspicious events from "
                    f"{source_ip}. Activities: "
                    f"{', '.join(activities[:8]) or 'Unknown'}."
                )
                conn.execute("""
                    UPDATE incidents
                    SET title=?, description=?, severity=?, risk_score=?,
                        first_seen=?, last_seen=?, updated_at=?
                    WHERE incident_id=?
                """, (f"{severity} Correlated Network Activity", desc,
                      severity, risk, first_seen, last_seen, now, incident_id))

        if new_links:
            logger.warning(
                f"INCIDENT_{'CREATED' if created else 'UPDATED'} | "
                f"id={incident_id} | added_events={new_links}"
            )
        return db.fetch_one(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,)
        )

    def attach_event(self, incident_id, event_id):
        """Attach evidence once; return True only when a new link exists."""
        if not event_id:
            return False
        with db.connection() as conn:
            result = conn.execute("""
                INSERT OR IGNORE INTO incident_events
                (incident_id, event_id, created_at)
                VALUES (?, ?, ?)
            """, (incident_id, event_id,
                  datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
            return result.rowcount == 1

    def _attach_new_events(self, incident_id, events):
        """Kept for compatibility; normal correlation uses create_incident."""
        return sum(bool(self.attach_event(incident_id, e.get("event_id")))
                   for e in events)

    def correlate_source(self, source_ip, destination_ip=None):
        if not settings.CORRELATION_ENABLED:
            return None
        events = self.get_related_events(source_ip, destination_ip)
        if len(events) < self.minimum_events:
            logger.info(
                f"CORRELATION_SKIPPED | src={source_ip} | events={len(events)}"
            )
            return None
        return self.create_incident(events)

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
