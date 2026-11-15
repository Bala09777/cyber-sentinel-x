from pathlib import Path
import os
import secrets


class Settings:
    """
    Central configuration for Cyber Sentinel X.
    """

    # --------------------------------------------------
    # PROJECT
    # --------------------------------------------------

    BASE_DIR = Path(__file__).resolve().parents[2]

    APP_NAME = "Cyber Sentinel X"
    APP_VERSION = "1.0.0"
    ENVIRONMENT = os.getenv(
        "CYBER_SENTINEL_ENV",
        "development"
    )

    # --------------------------------------------------
    # DIRECTORIES
    # --------------------------------------------------

    BACKEND_DIR = BASE_DIR / "backend"
    FRONTEND_DIR = BASE_DIR / "frontend"

    DATA_DIR = BASE_DIR / "data"
    LOG_DIR = BASE_DIR / "logs"
    PCAP_DIR = BASE_DIR / "pcaps"
    MODEL_DIR = BASE_DIR / "models"
    REPORT_DIR = BASE_DIR / "reports"

    # --------------------------------------------------
    # DATABASE
    # --------------------------------------------------

    DATABASE_FILE = DATA_DIR / "cyber_sentinel_x.db"

    # --------------------------------------------------
    # NETWORK MONITORING
    # --------------------------------------------------

    NETWORK_INTERFACE = os.getenv(
        "CYBER_SENTINEL_INTERFACE",
        "eth0"
    )

    PACKET_CAPTURE_ENABLED = True

    # Maximum packets processed per batch
    PACKET_BATCH_SIZE = 100

    # --------------------------------------------------
    # RISK ENGINE
    # --------------------------------------------------

    RISK_MIN = 0
    RISK_MAX = 100

    RISK_NORMAL = 39
    RISK_SUSPICIOUS = 40
    RISK_HIGH = 60
    RISK_CRITICAL = 80

    # --------------------------------------------------
    # DETECTION THRESHOLDS
    # --------------------------------------------------

    PORT_SCAN_THRESHOLD = 10

    HIGH_PACKET_THRESHOLD = 100

    RAPID_PACKET_THRESHOLD = 30

    VERY_HIGH_PACKET_THRESHOLD = 80

    BEHAVIOUR_WINDOW_SECONDS = 60

    # --------------------------------------------------
    # THREAT INTELLIGENCE
    # --------------------------------------------------

    THREAT_INTELLIGENCE_ENABLED = True

    GEOIP_ENABLED = True

    IP_REPUTATION_ENABLED = True

    # --------------------------------------------------
    # MACHINE LEARNING
    # --------------------------------------------------

    ML_ENABLED = True

    ANOMALY_THRESHOLD = 0.70

    MODEL_NAME = "network_anomaly_model"

    MODEL_FILE = MODEL_DIR / "network_anomaly_model.pkl"

    # --------------------------------------------------
    # CORRELATION ENGINE
    # --------------------------------------------------

    CORRELATION_ENABLED = True

    CORRELATION_WINDOW_SECONDS = 300

    MIN_EVENTS_FOR_INCIDENT = 2

    # --------------------------------------------------
    # ALERTING
    # --------------------------------------------------

    ALERT_ENABLED = True

    ALERT_CRITICAL_ONLY = False

    # --------------------------------------------------
    # WEB APPLICATION
    # --------------------------------------------------

    HOST = os.getenv(
        "CYBER_SENTINEL_HOST",
        "0.0.0.0"
    )

    PORT = int(
        os.getenv(
            "CYBER_SENTINEL_PORT",
            "8000"
        )
    )

    DEBUG = False

    # --------------------------------------------------
    # SECURITY
    # --------------------------------------------------

    SECRET_KEY = os.getenv("CYBER_SENTINEL_SECRET") or secrets.token_hex(32)
    if ENVIRONMENT.lower() in ("production", "prod") and not os.getenv("CYBER_SENTINEL_SECRET"):
        raise RuntimeError("Set CYBER_SENTINEL_SECRET before starting in production")

    SESSION_TIMEOUT_MINUTES = 30

    # --------------------------------------------------
    # LOGGING
    # --------------------------------------------------

    LOG_LEVEL = os.getenv(
        "CYBER_SENTINEL_LOG_LEVEL",
        "INFO"
    )

    LOG_FILE = LOG_DIR / "cyber_sentinel_x.log"

    AUDIT_LOG_FILE = LOG_DIR / "audit.log"

    # --------------------------------------------------
    # REPORTING
    # --------------------------------------------------

    REPORT_FORMAT = "PDF"

    REPORT_RETENTION_DAYS = 90

    # --------------------------------------------------
    # SYSTEM INITIALIZATION
    # --------------------------------------------------

    @classmethod
    def create_directories(cls):
        """
        Create required application directories.
        """

        directories = [
            cls.DATA_DIR,
            cls.LOG_DIR,
            cls.PCAP_DIR,
            cls.MODEL_DIR,
            cls.REPORT_DIR,
        ]

        for directory in directories:
            directory.mkdir(
                parents=True,
                exist_ok=True
            )


settings = Settings()

settings.create_directories()
