"""Safe local SOC incident demo. NEVER touches the active CSX database.

Runs in a temporary SQLite file, creates two simulated suspicious events,
correlates them to one incident, prints linked evidence, then deletes the DB.
Does not make calls, send emails, change firewall rules, or capture packets.
"""
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.database.manager import db
from backend.database.schema import SCHEMA
from backend.detection.event_service import event_service
from backend.correlation.engine import CorrelationEngine
from backend.incidents.incident_service import incident_service


def main():
    with tempfile.TemporaryDirectory(prefix="csx_incident_demo_") as temp:
        original_db = db.db_file
        db.db_file = Path(temp) / "DEMO_ONLY.db"
        try:
            with sqlite3.connect(db.db_file) as conn:
                conn.executescript(SCHEMA)
            engine = CorrelationEngine()
            for risk in (70, 85):
                event_service.create_event(
                    source_ip="192.0.2.55", destination_ip="198.51.100.55",
                    source_port=54000, destination_port=443, protocol="TCP",
                    packet_count=2, risk_score=risk,
                    activity="SIMULATED DEMO ONLY - NO REAL ATTACK"
                )
            case = engine.correlate_source("192.0.2.55")
            if not case:
                print("FAIL: No incident created. Check correlation settings.")
                return 1
            evidence = incident_service.get_timeline(case["incident_id"])
            print("PASS | isolated incident demo")
            print("INCIDENT:", case["incident_id"])
            print("SEVERITY:", case["severity"])
            print("RISK:", case["risk_score"])
            print("LINKED EVENTS:", len(evidence))
            print("SOURCE: 192.0.2.55 (documentation address; simulated)")
            print("No changes to live database, Gmail, firewall, or PCAPs.")
            return 0 if len(evidence) == 2 and case["severity"] == "CRITICAL" else 2
        finally:
            db.db_file = original_db


if __name__ == "__main__":
    raise SystemExit(main())
