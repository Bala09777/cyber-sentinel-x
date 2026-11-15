"""V3.3 target-scoped behaviour detection tests against isolated SQLite.

No real traffic, Gmail SMTP connections, firewall changes, or live DB writes.
"""
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.database.manager import db
from backend.database.schema import SCHEMA
from backend.detection.pipeline import pipeline
from backend.behaviour.behaviour_engine import behaviour_engine


class TestBehaviourAlertV33(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="csx_v33_test_")
        self.original = db.db_file
        db.db_file = Path(self.temp.name) / "ISOLATED_ONLY.db"
        with closing(sqlite3.connect(db.db_file)) as conn, conn:
            conn.executescript(SCHEMA)
        self.stack = []
        for path, value in (
            ("backend.detection.pipeline.anomaly_detector.predict", {"anomaly_score": 0.0}),
            ("backend.detection.pipeline.threat_intelligence.assess", {"score": 0}),
            ("backend.response.notifications.configured", {"email": True, "voice": False}),
        ):
            mocker = patch(path, return_value=value)
            mocker.start()
            self.stack.append(mocker)

    def tearDown(self):
        for mocker in reversed(self.stack):
            mocker.stop()
        db.db_file = self.original
        self.temp.cleanup()

    def event(self, port, target="198.51.100.75"):
        # Intentionally omit risk_score; source activity must drive detection.
        return pipeline.process_event({
            "source_ip": "192.0.2.75",
            "destination_ip": target,
            "source_port": 51000,
            "destination_port": port,
            "protocol": "TCP",
            "packet_count": 1,
            "activity": "SIMULATED TEST ONLY",
        })

    def test_ten_ports_one_host_triggers_alert_without_seeded_risk(self):
        result = None
        for p in range(10000, 10010):
            result = self.event(p)
        self.assertGreaterEqual(result["event"]["risk_score"], 40)
        self.assertEqual(result["event"]["severity"], "SUSPICIOUS")
        self.assertIn("PORT_SCAN_PATTERN", result["event"]["activity"])
        self.assertEqual(result["risk"]["port_scan_evidence"]["unique_target_ports"], 10)
        self.assertEqual(db.count("alerts"), 1)
        # SUSPICIOUS alerts do not send external Gmail under V3.1 policy.
        self.assertEqual(db.count("notification_outbox"), 0)

    def test_mixed_destinations_do_not_falsely_trigger_scan(self):
        result = None
        for p in range(10000, 10010):
            result = self.event(p, target=f"198.51.100.{100 + p - 10000}")
        self.assertLess(result["event"]["risk_score"], 40)
        self.assertEqual(db.count("alerts"), 0)
        self.assertEqual(behaviour_engine.detect_port_scan("192.0.2.75")["detected"], False)

    def test_rapid_targeted_activity_escalates_to_high_and_queues_email(self):
        result = None
        for i in range(30):
            result = self.event(20000 + (i % 10))
        self.assertEqual(result["event"]["severity"], "HIGH")
        self.assertEqual(result["event"]["risk_score"], 60)
        self.assertEqual(db.count("incidents"), 1)
        self.assertGreaterEqual(db.count("incident_events"), 2)
        queued = db.fetch_all("SELECT channel,status FROM notification_outbox")
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["channel"], "email")
        self.assertEqual(queued[0]["status"], "PENDING")
        # This isolated DB has no worker, so nothing was sent.

    def test_repeated_same_port_does_not_qualify(self):
        result = None
        for i in range(30):
            result = self.event(443)
        self.assertEqual(db.count("alerts"), 0)
        self.assertLess(result["event"]["risk_score"], 40)


if __name__ == "__main__":
    unittest.main()
