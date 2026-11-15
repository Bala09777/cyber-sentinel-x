from backend.core.logger import logger
from backend.core.config import settings
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

        # Preserve the strongest detection evidence.
        risk_result["risk_score"] = max(
            int(risk_result["risk_score"]),
            int(rule_score)
        )
        # CSX_V33_TARGET_SCOPED_PORT_SCAN
        # Evidence-aware floor: 10 ports on ONE host in the behaviour window
        # merits a SUSPICIOUS alert. Additional rapid events merit HIGH.
        # This does not override stronger existing rule/ML/TI risk.
        # A pattern is not proof of malicious activity; no firewall action.
        behaviour_metrics = behaviour_result.get("metrics") or {}
        scan_target = behaviour_metrics.get("port_scan_target")
        scan_ports = int(behaviour_metrics.get("max_ports_per_destination") or 0)
        scan_events = int(behaviour_metrics.get("event_count") or 0)
        scan_detected = bool(
            scan_target
            and scan_ports >= int(settings.PORT_SCAN_THRESHOLD)
            and scan_events >= scan_ports
        )
        if scan_detected:
            floor = (
                int(settings.RISK_HIGH)
                if scan_events >= int(settings.RAPID_PACKET_THRESHOLD)
                else int(settings.RISK_SUSPICIOUS)
            )
            risk_result["risk_score"] = max(int(risk_result["risk_score"]), floor)
            risk_result["port_scan_evidence"] = {
                "type": "PORT_SCAN_PATTERN",
                "source_ip": source_ip,
                "destination_ip": scan_target,
                "unique_target_ports": scan_ports,
                "events_in_window": scan_events,
                "assessment": "SUSPICIOUS_PATTERN_NOT_CONFIRMED_ATTACK",
            }
            logger.warning(
                f"PORT_SCAN_PATTERN | src={source_ip} | dst={scan_target} | "
                f"unique_ports={scan_ports} | events={scan_events} | "
                f"risk_floor={floor}"
            )
        final_risk = risk_result["risk_score"]
        if final_risk >= 80:
            risk_result["severity"] = "CRITICAL"
        elif final_risk >= 60:
            risk_result["severity"] = "HIGH"
        elif final_risk >= 40:
            risk_result["severity"] = "SUSPICIOUS"
        else:
            risk_result["severity"] = "NORMAL"
        final_severity = risk_result["severity"]

        # Save final risk before alert and correlation.
        updated_event_fields = {
            "risk_score": int(final_risk),
            "severity": final_severity,
        }
        if scan_detected:
            original_activity = str(event_dict.get("activity") or "NETWORK_ACTIVITY")
            if "PORT_SCAN_PATTERN" not in original_activity:
                original_activity += (
                    f" | PORT_SCAN_PATTERN target={scan_target} "
                    f"unique_ports={scan_ports} (heuristic)"
                )
            updated_event_fields["activity"] = original_activity[:500]
            event_dict["activity"] = updated_event_fields["activity"]
        db.update(
            "events", updated_event_fields, "event_id = ?", (event_id,)
        )
        event_dict["risk_score"] = int(final_risk)
        event_dict["severity"] = final_severity

        # 7. Alert
        if final_risk >= 40:
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
