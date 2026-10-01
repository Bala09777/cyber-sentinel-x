from datetime import datetime, timedelta

from backend.core.config import settings
from backend.core.logger import logger
from backend.database.manager import db


class BehaviourEngine:
    """
    Defensive behaviour analysis engine for Cyber Sentinel X.

    Uses the existing events table schema to analyze
    recent activity from a source IP.
    """

    def _now(self):
        return datetime.utcnow()

    def get_source_events(
        self,
        source_ip,
        window_seconds=None
    ):
        if not source_ip:
            return []

        if window_seconds is None:
            window_seconds = (
                settings.BEHAVIOUR_WINDOW_SECONDS
            )

        window_seconds = max(
            1,
            int(window_seconds)
        )

        cutoff = (
            self._now()
            - timedelta(
                seconds=window_seconds
            )
        ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        return db.fetch_all(
            """
            SELECT *
            FROM events
            WHERE source_ip = ?
              AND created_at >= ?
            ORDER BY created_at ASC
            """,
            (
                source_ip,
                cutoff
            )
        )

    def calculate_metrics(
        self,
        source_ip,
        window_seconds=None
    ):
        events = self.get_source_events(
            source_ip,
            window_seconds
        )

        if not events:
            return {
                "source_ip": source_ip,
                "event_count": 0,
                "unique_destinations": 0,
                "unique_ports": 0,
                "average_risk": 0,
                "maximum_risk": 0,
                "total_packets": 0
            }

        destinations = set()
        ports = set()
        risks = []
        total_packets = 0

        for event in events:

            destination_ip = event.get(
                "destination_ip"
            )

            if destination_ip:
                destinations.add(
                    destination_ip
                )

            destination_port = event.get(
                "destination_port"
            )

            if destination_port:
                ports.add(
                    str(destination_port)
                )

            try:
                risks.append(
                    int(
                        event.get(
                            "risk_score",
                            0
                        )
                    )
                )
            except (
                TypeError,
                ValueError
            ):
                pass

            try:
                total_packets += int(
                    event.get(
                        "packet_count",
                        0
                    )
                )
            except (
                TypeError,
                ValueError
            ):
                pass

        average_risk = (
            sum(risks) / len(risks)
            if risks
            else 0
        )

        maximum_risk = (
            max(risks)
            if risks
            else 0
        )

        return {
            "source_ip": source_ip,
            "event_count": len(events),
            "unique_destinations": len(
                destinations
            ),
            "unique_ports": len(
                ports
            ),
            "average_risk": round(
                average_risk,
                2
            ),
            "maximum_risk": maximum_risk,
            "total_packets": total_packets
        }

    def detect_port_scan(
        self,
        source_ip,
        window_seconds=None
    ):
        metrics = self.calculate_metrics(
            source_ip,
            window_seconds
        )

        threshold = (
            settings.PORT_SCAN_THRESHOLD
        )

        detected = (
            metrics["unique_ports"]
            >= threshold
        )

        return {
            "detected": detected,
            "type": "PORT_SCAN_PATTERN",
            "source_ip": source_ip,
            "unique_ports": metrics[
                "unique_ports"
            ],
            "threshold": threshold
        }

    def detect_high_packet_activity(
        self,
        source_ip,
        window_seconds=None
    ):
        metrics = self.calculate_metrics(
            source_ip,
            window_seconds
        )

        threshold = (
            settings.HIGH_PACKET_THRESHOLD
        )

        detected = (
            metrics["event_count"]
            >= threshold
        )

        return {
            "detected": detected,
            "type": "HIGH_ACTIVITY",
            "source_ip": source_ip,
            "event_count": metrics[
                "event_count"
            ],
            "threshold": threshold
        }

    def detect_rapid_activity(
        self,
        source_ip,
        window_seconds=None
    ):
        metrics = self.calculate_metrics(
            source_ip,
            window_seconds
        )

        threshold = (
            settings.RAPID_PACKET_THRESHOLD
        )

        detected = (
            metrics["event_count"]
            >= threshold
        )

        return {
            "detected": detected,
            "type": "RAPID_ACTIVITY",
            "source_ip": source_ip,
            "event_count": metrics[
                "event_count"
            ],
            "threshold": threshold
        }

    def calculate_behaviour_score(
        self,
        source_ip,
        window_seconds=None
    ):
        metrics = self.calculate_metrics(
            source_ip,
            window_seconds
        )

        score = 0
        reasons = []

        if (
            metrics["unique_ports"]
            >= settings.PORT_SCAN_THRESHOLD
        ):
            score += 40
            reasons.append(
                "Multiple unique destination ports"
            )

        if (
            metrics["event_count"]
            >= settings.RAPID_PACKET_THRESHOLD
        ):
            score += 20
            reasons.append(
                "Rapid event activity"
            )

        if (
            metrics["event_count"]
            >= settings.HIGH_PACKET_THRESHOLD
        ):
            score += 20
            reasons.append(
                "High event volume"
            )

        if (
            metrics["maximum_risk"]
            >= settings.RISK_HIGH
        ):
            score += 20
            reasons.append(
                "High-risk event observed"
            )

        score = min(
            100,
            score
        )

        if score >= settings.RISK_CRITICAL:
            classification = "CRITICAL"

        elif score >= settings.RISK_HIGH:
            classification = "HIGH"

        elif score >= settings.RISK_SUSPICIOUS:
            classification = "SUSPICIOUS"

        else:
            classification = "NORMAL"

        return {
            "source_ip": source_ip,
            "behaviour_score": score,
            "classification": classification,
            "reasons": reasons,
            "metrics": metrics
        }

    def analyze_source(
        self,
        source_ip,
        window_seconds=None
    ):
        result = self.calculate_behaviour_score(
            source_ip,
            window_seconds
        )

        logger.info(
            f"BEHAVIOUR_ANALYSIS | "
            f"src={source_ip} | "
            f"score={result['behaviour_score']} | "
            f"classification="
            f"{result['classification']}"
        )

        return result


behaviour_engine = BehaviourEngine()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - BEHAVIOUR ENGINE")
    print("=" * 60)

    test_ip = "192.168.1.50"

    result = behaviour_engine.analyze_source(
        test_ip
    )

    print(
        f"Source IP          : "
        f"{result['source_ip']}"
    )

    print(
        f"Behaviour Score    : "
        f"{result['behaviour_score']}"
    )

    print(
        f"Classification      : "
        f"{result['classification']}"
    )

    print(
        f"Event Count        : "
        f"{result['metrics']['event_count']}"
    )

    print(
        f"Unique Destinations: "
        f"{result['metrics']['unique_destinations']}"
    )

    print(
        f"Unique Ports       : "
        f"{result['metrics']['unique_ports']}"
    )

    print(
        f"Total Packets      : "
        f"{result['metrics']['total_packets']}"
    )

    print(
        f"Average Risk       : "
        f"{result['metrics']['average_risk']}"
    )

    print(
        f"Maximum Risk       : "
        f"{result['metrics']['maximum_risk']}"
    )

    if result["reasons"]:
        print(
            f"Reasons            : "
            f"{', '.join(result['reasons'])}"
        )
    else:
        print(
            "Reasons            : None"
        )

    print("Behaviour Engine   : READY")
