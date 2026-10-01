from pathlib import Path
import pickle
import math

from backend.core.config import settings
from backend.core.logger import logger


class AnomalyDetector:
    """
    Defensive ML-ready anomaly detection service.

    Provides model lifecycle management and a lightweight
    statistical anomaly fallback when a trained model
    is not yet available.
    """

    def __init__(self):
        self.model = None
        self.model_path = Path(
            settings.MODEL_FILE
        )

    def load_model(self):
        if not self.model_path.exists():
            logger.info(
                "ML_MODEL | no trained model found"
            )
            return False

        try:
            with open(
                self.model_path,
                "rb"
            ) as file:
                self.model = pickle.load(file)

            logger.info(
                f"ML_MODEL_LOADED | "
                f"path={self.model_path}"
            )

            return True

        except Exception as exc:
            logger.error(
                f"ML_MODEL_LOAD_ERROR | "
                f"error={exc}"
            )

            self.model = None
            return False

    def save_model(self, model):
        self.model_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            self.model_path,
            "wb"
        ) as file:
            pickle.dump(
                model,
                file
            )

        self.model = model

        logger.info(
            f"ML_MODEL_SAVED | "
            f"path={self.model_path}"
        )

        return True

    def build_features(self, event):
        """
        Convert a stored event into numerical ML features.
        """

        if not event:
            return []

        def to_int(value):
            try:
                return int(value or 0)
            except (
                TypeError,
                ValueError
            ):
                return 0

        def to_float(value):
            try:
                return float(value or 0)
            except (
                TypeError,
                ValueError
            ):
                return 0.0

        return [
            to_int(
                event.get("packet_count")
            ),
            to_int(
                event.get("unique_ports")
            ),
            to_int(
                event.get("source_port")
            ),
            to_int(
                event.get("destination_port")
            ),
            to_int(
                event.get("risk_score")
            ),
            to_float(
                event.get("anomaly_score")
            )
        ]

    def statistical_score(self, event):
        """
        Lightweight fallback anomaly score.

        This is not a trained ML model. It provides a
        deterministic baseline until real training data
        is available.
        """

        features = self.build_features(
            event
        )

        if not features:
            return 0.0

        packet_count = features[0]
        unique_ports = features[1]
        risk_score = features[4]

        score = 0.0

        if packet_count >= 100:
            score += 0.35
        elif packet_count >= 50:
            score += 0.20

        if unique_ports >= 10:
            score += 0.35
        elif unique_ports >= 5:
            score += 0.20

        if risk_score >= 80:
            score += 0.30
        elif risk_score >= 60:
            score += 0.20
        elif risk_score >= 40:
            score += 0.10

        return min(
            1.0,
            round(score, 4)
        )

    def predict(self, event):
        """
        Predict anomaly score for one event.
        """

        if not event:
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "method": "NONE"
            }

        features = self.build_features(
            event
        )

        if self.model is not None:
            try:
                if hasattr(
                    self.model,
                    "predict_proba"
                ):
                    probabilities = (
                        self.model.predict_proba(
                            [features]
                        )
                    )

                    score = float(
                        probabilities[0][-1]
                    )

                elif hasattr(
                    self.model,
                    "decision_function"
                ):
                    raw_score = float(
                        self.model.decision_function(
                            [features]
                        )[0]
                    )

                    score = 1.0 / (
                        1.0 + math.exp(
                            -raw_score
                        )
                    )

                else:
                    score = self.statistical_score(
                        event
                    )

                method = "ML_MODEL"

            except Exception as exc:
                logger.error(
                    f"ML_PREDICTION_ERROR | "
                    f"error={exc}"
                )

                score = self.statistical_score(
                    event
                )

                method = "STATISTICAL_FALLBACK"

        else:
            score = self.statistical_score(
                event
            )

            method = "STATISTICAL_BASELINE"

        threshold = float(
            settings.ANOMALY_THRESHOLD
        )

        is_anomaly = (
            score >= threshold
        )

        result = {
            "event_id": event.get(
                "event_id"
            ),
            "anomaly_score": round(
                score,
                4
            ),
            "threshold": threshold,
            "is_anomaly": is_anomaly,
            "method": method
        }

        logger.info(
            f"ML_PREDICTION | "
            f"event={result['event_id']} | "
            f"score={result['anomaly_score']} | "
            f"anomaly={result['is_anomaly']} | "
            f"method={method}"
        )

        return result

    def health_check(self):
        return {
            "enabled": settings.ML_ENABLED,
            "model_available": (
                self.model is not None
            ),
            "model_path": str(
                self.model_path
            ),
            "threshold": settings.ANOMALY_THRESHOLD
        }


anomaly_detector = AnomalyDetector()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - ANOMALY DETECTOR")
    print("=" * 60)

    model_loaded = (
        anomaly_detector.load_model()
    )

    print(
        f"ML Enabled       : "
        f"{settings.ML_ENABLED}"
    )

    print(
        f"Model Loaded     : "
        f"{model_loaded}"
    )

    print(
        f"Model Path       : "
        f"{anomaly_detector.model_path}"
    )

    print(
        f"Threshold        : "
        f"{settings.ANOMALY_THRESHOLD}"
    )

    test_event = {
        "event_id": "ML-TEST-001",
        "packet_count": 25,
        "unique_ports": 2,
        "source_port": 45000,
        "destination_port": 443,
        "risk_score": 25,
        "anomaly_score": 0.0
    }

    result = anomaly_detector.predict(
        test_event
    )

    print(
        f"Anomaly Score    : "
        f"{result['anomaly_score']}"
    )

    print(
        f"Is Anomaly       : "
        f"{result['is_anomaly']}"
    )

    print(
        f"Detection Method : "
        f"{result['method']}"
    )

    print("Anomaly Detector : READY")
