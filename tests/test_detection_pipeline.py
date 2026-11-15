import unittest
from unittest.mock import patch

from backend.detection.pipeline import DetectionPipeline


class TestDetectionPipeline(unittest.TestCase):

    def run_pipeline(self, rule_score, calculated_risk):
        event = {
            "event_id": "TEST-EVENT-001",
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "risk_score": 0,
        }

        with (
            patch("backend.detection.pipeline.event_service") as events,
            patch("backend.detection.pipeline.rule_engine") as rules,
            patch("backend.detection.pipeline.behaviour_engine") as behaviour,
            patch("backend.detection.pipeline.anomaly_detector") as ml,
            patch("backend.detection.pipeline.threat_intelligence") as intel,
            patch("backend.detection.pipeline.risk_engine") as risk,
            patch("backend.detection.pipeline.alert_service") as alerts,
            patch("backend.detection.pipeline.correlation_engine") as correlation,
            patch("backend.detection.pipeline.db") as database,
        ):
            events.create_event.return_value = event
            rules.evaluate_event.return_value = (
                [{"risk_score": rule_score}] if rule_score else []
            )
            behaviour.analyze_source.return_value = {"behaviour_score": 0}
            ml.predict.return_value = {"anomaly_score": 0.0}
            intel.assess.return_value = {"score": 0}
            risk.calculate.return_value = {
                "risk_score": calculated_risk,
                "severity": "NORMAL",
            }
            correlation.correlate_source.return_value = {}

            result = DetectionPipeline().process_event({
                "source_ip": "192.0.2.10",
                "destination_ip": "192.0.2.20",
            })

            return result, alerts.create_from_event_id.call_count, database.update.call_count

    def test_normal_event(self):
        result, alert_count, update_count = self.run_pipeline(0, 0)
        self.assertEqual(result["event"]["severity"], "NORMAL")
        self.assertEqual(alert_count, 0)
        self.assertEqual(update_count, 2)

    def test_suspicious_risk_creates_alert(self):
        result, alert_count, _ = self.run_pipeline(40, 40)
        self.assertEqual(result["event"]["severity"], "SUSPICIOUS")
        self.assertEqual(alert_count, 1)

    def test_below_suspicious_creates_no_alert(self):
        result, alert_count, _ = self.run_pipeline(39, 39)
        self.assertEqual(result["event"]["severity"], "NORMAL")
        self.assertEqual(alert_count, 0)

    def test_high_risk_alert(self):
        result, alert_count, _ = self.run_pipeline(60, 60)
        self.assertEqual(result["event"]["severity"], "HIGH")
        self.assertEqual(alert_count, 1)

    def test_critical_rule_preserved(self):
        result, alert_count, _ = self.run_pipeline(90, 30)
        self.assertEqual(result["event"]["risk_score"], 90)
        self.assertEqual(result["event"]["severity"], "CRITICAL")
        self.assertEqual(alert_count, 1)


if __name__ == "__main__":
    unittest.main()
