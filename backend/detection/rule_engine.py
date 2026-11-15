from backend.core.logger import logger
from backend.database.manager import db
from backend.detection.alert_service import alert_service


class RuleEngine:
    """
    Evaluates security events against enabled detection rules.
    """

    def get_enabled_rules(self):
        return db.fetch_all(
            """
            SELECT *
            FROM detection_rules
            WHERE enabled = 1
            ORDER BY threshold ASC
            """
        )

    def evaluate_event(self, event):
        if not event:
            return []

        matched_rules = []

        risk_score = int(
            event.get("risk_score", 0)
        )

        for rule in self.get_enabled_rules():

            category = rule.get(
                "category",
                ""
            )

            threshold = int(
                rule.get("threshold", 0)
            )

            severity = rule.get(
                "severity",
                "SUSPICIOUS"
            )

            matched = False

            if category == "NETWORK_RISK":
                if risk_score >= threshold:
                    matched = True

            if matched:
                result = {
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "severity": severity,
                    "threshold": threshold,
                    "risk_score": risk_score
                }

                matched_rules.append(result)

                logger.warning(
                    f"RULE_MATCHED | "
                    f"rule={rule['rule_id']} | "
                    f"name={rule['name']} | "
                    f"risk={risk_score}"
                )


        return matched_rules

    def evaluate_event_id(self, event_id):
        event = db.fetch_one(
            """
            SELECT *
            FROM events
            WHERE event_id = ?
            """,
            (event_id,)
        )

        if not event:
            return []

        return self.evaluate_event(
            event
        )

    def evaluate_recent_events(self, limit=50):
        limit = max(
            1,
            min(500, int(limit))
        )

        events = db.fetch_all(
            f"""
            SELECT *
            FROM events
            ORDER BY created_at DESC
            LIMIT {limit}
            """
        )

        results = []

        for event in events:
            matches = self.evaluate_event(
                event
            )

            if matches:
                results.append({
                    "event_id": event["event_id"],
                    "matches": matches
                })

        return results

    def get_rule_count(self):
        return db.count(
            "detection_rules",
            "enabled = ?",
            (1,)
        )


rule_engine = RuleEngine()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - RULE ENGINE")
    print("=" * 60)

    rules = rule_engine.get_enabled_rules()

    print(
        f"Enabled Rules : {len(rules)}"
    )

    for rule in rules:
        print(
            f"Rule          : {rule['name']}"
        )
        print(
            f"Category      : {rule['category']}"
        )
        print(
            f"Threshold     : {rule['threshold']}"
        )
        print(
            f"Severity      : {rule['severity']}"
        )

    print(
        f"Active Rules  : "
        f"{rule_engine.get_rule_count()}"
    )

    print("Rule Engine   : READY")
