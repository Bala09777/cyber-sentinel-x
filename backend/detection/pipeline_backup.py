from backend.core.logger import logger
from backend.detection.event_service import event_service
from backend.detection.rule_engine import rule_engine
from backend.correlation.engine import correlation_engine


class DetectionPipeline:
    """
    Central defensive detection pipeline.

    Flow:
    Event -> Rules -> Alerts -> Correlation
    """

    def process_event(self, event_data):
        if not event_data:
            return None

        event = event_service.create_event(
            **event_data
        )

        logger.info(
            f"PIPELINE_EVENT | "
            f"event={event['event_id']} | "
            f"risk={event['risk_score']}"
        )

        rule_matches = rule_engine.evaluate_event(
            event
        )

        incident = None

        if rule_matches:
            incident = correlation_engine.correlate_source(
                event["src_ip"]
            )

        result = {
            "event": event,
            "rule_matches": rule_matches,
            "incident": incident
        }

        logger.info(
            f"PIPELINE_COMPLETE | "
            f"event={event['event_id']} | "
            f"rules={len(rule_matches)} | "
            f"incident={'YES' if incident else 'NO'}"
        )

        return result

    def process_event_id(self, event_id):
        event = event_service.get_event(
            event_id
        )

        if not event:
            return None

        rule_matches = rule_engine.evaluate_event(
            event
        )

        incident = None

        if rule_matches:
            incident = correlation_engine.correlate_source(
                event["src_ip"]
            )

        return {
            "event": event,
            "rule_matches": rule_matches,
            "incident": incident
        }


detection_pipeline = DetectionPipeline()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - DETECTION PIPELINE")
    print("=" * 60)

    print("Event Service    : READY")
    print("Rule Engine      : READY")
    print("Alert Service    : READY")
    print("Correlation      : READY")
    print("Detection Pipeline: READY")
