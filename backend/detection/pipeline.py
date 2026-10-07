from backend.core.logger import logger
from backend.database.manager import db
from backend.core.risk_engine import risk_engine
from backend.detection.event_service import event_service
from backend.detection.rule_engine import rule_engine
from backend.detection.alert_service import alert_service
from backend.correlation.engine import correlation_engine
from backend.behaviour.behaviour_engine import behaviour_engine
from backend.ml.anomaly_detector import anomaly_detector
from backend.intelligence.threat_intel import threat_intelligence


class DetectionPipeline:

    def process_event(self, event_data):
        # 1. Create event
        event = event_service.create_event(**event_data)

        event_dict = dict(event)
        event_id = event_dict["event_id"]
        source_ip = event_dict["source_ip"]

        # 2. Rule Engine
        rule_matches = rule_engine.evaluate_event(event_dict)

        rule_score = event_dict.get("risk_score", 0)
        if rule_matches:
            rule_score = max(
                rule_score,
                max(
                    match.get("risk_score", 0)
                    for match in rule_matches
                )
            )

        # 3. Behaviour Engine
        behaviour_result = behaviour_engine.analyze_source(
            source_ip
        )

        behaviour_score = behaviour_result.get(
            "behaviour_score", 0
        )

        # 4. ML Engine
        ml_result = anomaly_detector.predict(event_dict)

        ml_score = ml_result.get(
            "anomaly_score", 0
        )

        # Persist ML anomaly score to the event record
        db.update(
            "events",
            {"anomaly_score": float(ml_score)},
            "event_id = ?",
            (event_id,)
        )

        # 5. Threat Intelligence
        ti_result = threat_intelligence.assess(
            source_ip
        )

        threat_intel_score = ti_result.get(
            "score", 0
        )

        # 6. Final Risk Engine
        risk_result = risk_engine.calculate(
            rule_score=rule_score,
            behaviour_score=behaviour_score,
            ml_score=ml_score,
            threat_intel_score=threat_intel_score,
        )

        final_risk = risk_result["risk_score"]
        final_severity = risk_result["severity"]

        # 7. Alert
        if final_risk >= 60:
            alert_service.create_from_event_id(
                event_id
            )

        # 8. Correlation
        correlation_result = correlation_engine.correlate_source(
            source_ip
        )

        logger.info(
            f"PIPELINE_COMPLETE | event={event_id} | "
            f"risk={final_risk} | severity={final_severity}"
        )

        return {
            "event": event_dict,
            "rules": rule_matches,
            "behaviour": behaviour_result,
            "ml": ml_result,
            "threat_intelligence": ti_result,
            "risk": risk_result,
            "correlation": correlation_result,
        }


pipeline = DetectionPipeline()


if __name__ == "__main__":
    print("=" * 60)
    print("CYBER SENTINEL X - DETECTION PIPELINE")
    print("=" * 60)
    print("Event Service       : READY")
    print("Rule Engine         : READY")
    print("Behaviour Engine    : READY")
    print("ML Engine            : READY")
    print("Threat Intelligence : READY")
    print("Risk Engine         : READY")
    print("Alert Service       : READY")
    print("Correlation Engine  : READY")
    print("Detection Pipeline  : READY")
    print("=" * 60)
