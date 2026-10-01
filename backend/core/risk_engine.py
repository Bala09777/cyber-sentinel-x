from backend.core.logger import logger


class RiskEngine:
    """
    Combines multiple defensive security signals
    into a normalized 0-100 risk score.
    """

    def __init__(self):
        self.weights = {
            "rule": 0.30,
            "behaviour": 0.25,
            "ml": 0.25,
            "threat_intel": 0.20,
        }

    def calculate(
        self,
        rule_score=0,
        behaviour_score=0,
        ml_score=0,
        threat_intel_score=0,
    ):
        rule_score = max(0, min(100, float(rule_score)))
        behaviour_score = max(0, min(100, float(behaviour_score)))
        ml_score = max(0, min(1, float(ml_score))) * 100
        threat_intel_score = max(
            0, min(100, float(threat_intel_score))
        )

        final_score = (
            rule_score * self.weights["rule"]
            + behaviour_score * self.weights["behaviour"]
            + ml_score * self.weights["ml"]
            + threat_intel_score * self.weights["threat_intel"]
        )

        final_score = round(
            max(0, min(100, final_score))
        )

        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 40:
            severity = "SUSPICIOUS"
        elif final_score >= 20:
            severity = "MEDIUM"
        else:
            severity = "NORMAL"

        logger.info(
            f"RISK_CALCULATED | score={final_score} | "
            f"severity={severity}"
        )

        return {
            "risk_score": final_score,
            "severity": severity,
            "components": {
                "rule": rule_score,
                "behaviour": behaviour_score,
                "ml": round(ml_score, 2),
                "threat_intel": threat_intel_score,
            },
        }


risk_engine = RiskEngine()


if __name__ == "__main__":
    print("=" * 60)
    print("CYBER SENTINEL X - RISK ENGINE")
    print("=" * 60)

    result = risk_engine.calculate(
        rule_score=80,
        behaviour_score=60,
        ml_score=1.0,
        threat_intel_score=40,
    )

    print("Final Risk :", result["risk_score"])
    print("Severity   :", result["severity"])
    print("Components :", result["components"])
    print("Risk Engine: READY")
