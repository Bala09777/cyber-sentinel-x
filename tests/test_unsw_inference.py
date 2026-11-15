import unittest
from unittest.mock import Mock

from backend.ml.unsw_inference import UNSWInference


class TestUNSWInference(unittest.TestCase):

    def setUp(self):
        self.detector = UNSWInference()

    def test_model_not_loaded(self):
        result = self.detector.predict({
            "packet_count": 5,
            "bytes": 500,
            "duration_seconds": 1.0,
            "protocol": "TCP",
        })
        self.assertEqual(result["method"], "MODEL_NOT_LOADED")

    def test_unsupported_protocol(self):
        self.detector.model = Mock()
        result = self.detector.predict({
            "packet_count": 5,
            "bytes": 500,
            "duration_seconds": 1.0,
            "protocol": "OTHER",
        })
        self.assertEqual(result["method"], "UNSUPPORTED_PROTOCOL")

    def test_missing_features(self):
        self.detector.model = Mock()
        result = self.detector.predict({
            "packet_count": 5,
            "protocol": "TCP",
        })
        self.assertEqual(result["method"], "MISSING_FEATURES")

    def test_prediction_and_feature_order(self):
        model = Mock()
        model.classes_ = [0, 1]
        model.predict_proba.return_value = [[0.2, 0.8]]
        self.detector.model = model

        result = self.detector.predict({
            "packet_count": 5,
            "bytes": 500,
            "duration_seconds": 1.5,
            "protocol": "TCP",
        })

        model.predict_proba.assert_called_once_with(
            [[5.0, 500.0, 1.5, 0.0]]
        )
        self.assertEqual(result["method"], "UNSW_EXPERIMENTAL")
        self.assertEqual(result["anomaly_score"], 0.8)
        self.assertTrue(result["is_anomaly"])


if __name__ == "__main__":
    unittest.main()
