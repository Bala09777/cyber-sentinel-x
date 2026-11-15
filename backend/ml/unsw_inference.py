from pathlib import Path
import joblib
import json
import math

MODEL_PATH = (
    Path(__file__).resolve().parents[2]
    / "models"
    / "unsw_v34_candidate.joblib"
)

PROTOCOLS = {"TCP": 0, "UDP": 1, "ICMP": 2}


class UNSWInference:
    def __init__(self):
        self.model = None
        self.threshold = 0.7
        self.method = "UNSW_EXPERIMENTAL"
        self.protocols = dict(PROTOCOLS)

    def load(self):
        report_path = MODEL_PATH.with_suffix(".json")

        try:
            report = json.loads(report_path.read_text())
            threshold = float(report["threshold"])

            if report["features"] != [
                "spkts", "sbytes", "dur", "proto_code"
            ]:
                return False

            if report["protocols"] != ["tcp", "udp"]:
                return False

            if not math.isfinite(threshold) or not 0 < threshold < 1:
                return False

            model = joblib.load(MODEL_PATH)

            if model.n_features_in_ != 4:
                return False

            if set(model.classes_) != {0, 1}:
                return False

            self.model = model
            self.threshold = threshold
            self.method = "UNSW_V34_SHADOW"
            self.protocols = {"TCP": 0, "UDP": 1}

            return True

        except Exception:
            self.model = None
            return False

    def predict(self, flow):
        if self.model is None:
            return {
                "method": "MODEL_NOT_LOADED",
                "is_anomaly": False,
            }

        protocol = str(flow.get("protocol", "")).upper()

        if protocol not in self.protocols:
            return {
                "method": "UNSUPPORTED_PROTOCOL",
                "is_anomaly": False,
            }

        required = ("packet_count", "bytes", "duration_seconds")
        if any(flow.get(key) is None for key in required):
            return {
                "method": "MISSING_FEATURES",
                "is_anomaly": False,
            }

        try:
            values = [
                float(flow["packet_count"]),
                float(flow["bytes"]),
                float(flow["duration_seconds"])
            ]

            if not all(math.isfinite(v) and v >= 0 for v in values):
                raise ValueError("Invalid flow features")

            features = [values + [float(self.protocols[protocol])]]

        except (TypeError, ValueError, OverflowError):
            return {
                "method": "INVALID_FEATURES",
                "is_anomaly": False
            }

        attack_index = list(self.model.classes_).index(1)
        score = float(
            self.model.predict_proba(features)[0][attack_index]
        )

        return {
            "anomaly_score": round(score, 4),
            "is_anomaly": score >= self.threshold,
            "threshold": self.threshold,
            "method": self.method,
        }


unsw_inference = UNSWInference()
