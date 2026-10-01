from datetime import datetime

from backend.core.logger import logger
from backend.database.manager import db


class RuleService:
    """
    Detection rule management for Cyber Sentinel X.
    Compatible with the existing detection_rules schema.
    """

    VALID_SEVERITIES = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "SUSPICIOUS"
    }

    def _now(self):
        return datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    def generate_rule_id(self):
        timestamp = datetime.utcnow().strftime(
            "%Y%m%d%H%M%S"
        )

        return f"RULE-{timestamp}"

    def create_rule(
        self,
        name,
        description,
        category,
        threshold=0,
        severity="MEDIUM",
        enabled=1
    ):
        if not name:
            raise ValueError(
                "Rule name is required"
            )

        severity = str(severity).upper()
        enabled = 1 if enabled else 0

        if severity not in self.VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}"
            )

        existing = self.get_rule_by_name(name)

        if existing:
            return existing

        rule_id = self.generate_rule_id()

        rule = {
            "rule_id": rule_id,
            "name": name,
            "description": description,
            "category": category,
            "severity": severity,
            "threshold": int(threshold),
            "enabled": enabled,
            "created_at": self._now(),
            "updated_at": self._now()
        }

        db.insert(
            "detection_rules",
            rule
        )

        logger.info(
            f"RULE_CREATED | "
            f"id={rule_id} | "
            f"name={name} | "
            f"severity={severity}"
        )

        return self.get_rule(rule_id)

    def get_rule(self, rule_id):
        return db.fetch_one(
            """
            SELECT *
            FROM detection_rules
            WHERE rule_id = ?
            """,
            (rule_id,)
        )

    def get_rule_by_name(self, name):
        return db.fetch_one(
            """
            SELECT *
            FROM detection_rules
            WHERE name = ?
            """,
            (name,)
        )

    def get_all_rules(self):
        return db.fetch_all(
            """
            SELECT *
            FROM detection_rules
            ORDER BY created_at DESC
            """
        )

    def get_enabled_rules(self):
        return db.fetch_all(
            """
            SELECT *
            FROM detection_rules
            WHERE enabled = 1
            ORDER BY created_at DESC
            """
        )

    def enable_rule(self, rule_id):
        rule = self.get_rule(rule_id)

        if not rule:
            return None

        db.update(
            "detection_rules",
            {
                "enabled": 1,
                "updated_at": self._now()
            },
            "rule_id = ?",
            (rule_id,)
        )

        logger.info(
            f"RULE_ENABLED | id={rule_id}"
        )

        return self.get_rule(rule_id)

    def disable_rule(self, rule_id):
        rule = self.get_rule(rule_id)

        if not rule:
            return None

        db.update(
            "detection_rules",
            {
                "enabled": 0,
                "updated_at": self._now()
            },
            "rule_id = ?",
            (rule_id,)
        )

        logger.info(
            f"RULE_DISABLED | id={rule_id}"
        )

        return self.get_rule(rule_id)

    def delete_rule(self, rule_id):
        rule = self.get_rule(rule_id)

        if not rule:
            return False

        db.delete(
            "detection_rules",
            "rule_id = ?",
            (rule_id,)
        )

        logger.info(
            f"RULE_DELETED | id={rule_id}"
        )

        return True

    def get_rule_count(self):
        return db.count(
            "detection_rules"
        )


rule_service = RuleService()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - DETECTION RULE SERVICE")
    print("=" * 60)

    rule = rule_service.create_rule(
        name="High Risk Network Activity",
        description=(
            "Detect network activity "
            "with high risk score."
        ),
        category="NETWORK_RISK",
        threshold=60,
        severity="HIGH",
        enabled=1
    )

    print(
        f"Rule ID     : {rule['rule_id']}"
    )

    print(
        f"Rule Name   : {rule['name']}"
    )

    print(
        f"Category    : {rule['category']}"
    )

    print(
        f"Threshold   : {rule['threshold']}"
    )

    print(
        f"Severity    : {rule['severity']}"
    )

    print(
        f"Enabled     : {rule['enabled']}"
    )

    print(
        f"Total Rules : "
        f"{rule_service.get_rule_count()}"
    )

    print("Rule Service: READY")
