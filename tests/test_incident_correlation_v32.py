"""Defensive incident-correlation regression tests; isolated temporary DB only."""
import sqlite3
from contextlib import closing
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from backend.database.manager import db
from backend.database.schema import SCHEMA
from backend.detection.event_service import event_service
from backend.correlation.engine import CorrelationEngine
from backend.incidents.incident_service import incident_service


class TestIncidentCorrelationV32(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = db.db_file
        db.db_file = Path(self.tmp.name) / "isolated.db"
        with closing(sqlite3.connect(db.db_file)) as conn, conn:
            conn.executescript(SCHEMA)
        self.engine = CorrelationEngine()

    def tearDown(self):
        db.db_file = self.old_db
        self.tmp.cleanup()

    def event(self, source="192.0.2.61", destination="198.51.100.8", risk=70):
        return event_service.create_event(
            source_ip=source, destination_ip=destination,
            source_port=52000, destination_port=443, protocol="TCP",
            risk_score=risk, packet_count=2,
            activity="SIMULATED CORRELATION UNIT TEST ONLY"
        )

    def test_one_suspicious_event_does_not_create_case(self):
        self.event()
        self.assertIsNone(self.engine.correlate_source("192.0.2.61"))
        self.assertEqual(db.count("incidents"), 0)

    def test_two_related_events_create_one_linked_case(self):
        self.event(risk=65)
        self.event(risk=75)
        case = self.engine.correlate_source("192.0.2.61")
        self.assertIsNotNone(case)
        self.assertEqual(case["severity"], "HIGH")
        self.assertEqual(db.count("incidents"), 1)
        self.assertEqual(db.count("incident_events"), 2)
        self.assertEqual(len(incident_service.get_timeline(case["incident_id"])), 2)

    def test_duplicate_rechecks_do_not_add_links(self):
        self.event()
        self.event()
        first = self.engine.correlate_source("192.0.2.61")
        again = self.engine.correlate_source("192.0.2.61")
        self.assertEqual(first["incident_id"], again["incident_id"])
        self.assertEqual(db.count("incidents"), 1)
        self.assertEqual(db.count("incident_events"), 2)

    def test_unrelated_sources_do_not_correlate(self):
        self.event(source="192.0.2.61")
        self.event(source="192.0.2.62")
        self.assertIsNone(self.engine.correlate_source("192.0.2.61"))
        self.assertIsNone(self.engine.correlate_source("192.0.2.62"))

    def test_critical_event_escalates_existing_case(self):
        self.event(risk=65)
        self.event(risk=70)
        first = self.engine.correlate_source("192.0.2.61")
        self.event(destination="198.51.100.9", risk=95)
        changed = self.engine.correlate_source("192.0.2.61")
        self.assertEqual(first["incident_id"], changed["incident_id"])
        self.assertEqual(changed["severity"], "CRITICAL")
        self.assertGreater(changed["risk_score"], first["risk_score"])
        self.assertEqual(db.count("incident_events"), 3)
        self.assertIn("3 suspicious events", changed["description"])
        self.assertEqual(changed["status"], "OPEN")

    def test_closed_case_evidence_never_reused(self):
        self.event(); self.event()
        closed = self.engine.correlate_source("192.0.2.61")
        self.assertTrue(incident_service.update_status(closed["incident_id"], "CLOSED", "test"))
        self.event(); self.event()
        second = self.engine.correlate_source("192.0.2.61")
        self.assertNotEqual(closed["incident_id"], second["incident_id"])
        self.assertEqual(db.count("incidents"), 2)
        self.assertEqual(len(incident_service.get_timeline(second["incident_id"])), 2)

    def test_stale_open_case_not_reused(self):
        self.event(); self.event()
        old = self.engine.correlate_source("192.0.2.61")
        stale = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        db.update("incidents", {"last_seen": stale}, "incident_id = ?", (old["incident_id"],))
        # Old event evidence is within the window, but an explicitly stale
        # case must not be quietly revived.
        self.event(); self.event()
        new = self.engine.correlate_source("192.0.2.61")
        self.assertNotEqual(old["incident_id"], new["incident_id"])
        self.assertEqual(len(incident_service.get_timeline(new["incident_id"])), 2)

    def test_disabled_correlation_is_respected(self):
        self.event(); self.event()
        with patch("backend.correlation.engine.settings.CORRELATION_ENABLED", False):
            self.assertIsNone(self.engine.correlate_source("192.0.2.61"))
        self.assertEqual(db.count("incidents"), 0)

    def test_normal_events_not_correlated(self):
        self.event(risk=0); self.event(risk=20)
        self.assertIsNone(self.engine.correlate_source("192.0.2.61"))
        self.assertEqual(db.count("incidents"), 0)


if __name__ == "__main__":
    unittest.main()
