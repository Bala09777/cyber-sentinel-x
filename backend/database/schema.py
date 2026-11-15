import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
DB_FILE = BASE_DIR / "data" / "cyber_sentinel_x.db"


SCHEMA = """

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    hostname TEXT,
    mac_address TEXT,
    asset_type TEXT,
    operating_system TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    first_seen TEXT,
    last_seen TEXT
);


CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,

    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,

    source_port TEXT,
    destination_port TEXT,

    protocol TEXT,

    packet_count INTEGER NOT NULL DEFAULT 0,
    unique_ports INTEGER NOT NULL DEFAULT 0,

    risk_score INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'NORMAL',

    activity TEXT,

    country TEXT,
    city TEXT,
    organization TEXT,
    asn TEXT,

    anomaly_score REAL DEFAULT 0.0,

    created_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    alert_id TEXT UNIQUE NOT NULL,
    event_id TEXT,

    timestamp TEXT NOT NULL,

    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT,

    source_ip TEXT,
    destination_ip TEXT,

    risk_score INTEGER DEFAULT 0,

    status TEXT NOT NULL DEFAULT 'OPEN',

    acknowledged INTEGER NOT NULL DEFAULT 0,

    created_at TEXT NOT NULL,

    FOREIGN KEY (event_id)
        REFERENCES events(event_id)
);


CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    incident_id TEXT UNIQUE NOT NULL,

    title TEXT NOT NULL,
    description TEXT,

    severity TEXT NOT NULL DEFAULT 'MEDIUM',

    risk_score INTEGER NOT NULL DEFAULT 0,

    status TEXT NOT NULL DEFAULT 'OPEN',

    source_ip TEXT,
    destination_ip TEXT,

    attack_type TEXT,

    mitre_tactic TEXT,
    mitre_technique TEXT,

    assigned_to TEXT,

    first_seen TEXT,
    last_seen TEXT,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    incident_id TEXT NOT NULL,
    event_id TEXT NOT NULL,

    created_at TEXT NOT NULL,

    UNIQUE (
        incident_id,
        event_id
    ),

    FOREIGN KEY (incident_id)
        REFERENCES incidents(incident_id),

    FOREIGN KEY (event_id)
        REFERENCES events(event_id)
);


CREATE TABLE IF NOT EXISTS threat_intelligence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    ip_address TEXT UNIQUE NOT NULL,

    reputation TEXT DEFAULT 'UNKNOWN',

    threat_score INTEGER DEFAULT 0,

    country TEXT,
    city TEXT,

    organization TEXT,
    asn TEXT,

    provider TEXT,

    last_checked TEXT,

    malicious INTEGER DEFAULT 0,

    confidence REAL DEFAULT 0.0
);


CREATE TABLE IF NOT EXISTS detection_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    rule_id TEXT UNIQUE NOT NULL,

    name TEXT NOT NULL,

    description TEXT,

    category TEXT,

    severity TEXT DEFAULT 'SUSPICIOUS',

    threshold INTEGER DEFAULT 0,

    enabled INTEGER NOT NULL DEFAULT 1,

    created_at TEXT NOT NULL,

    updated_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    timestamp TEXT NOT NULL,

    username TEXT,

    action TEXT NOT NULL,

    resource TEXT,

    resource_id TEXT,

    source_ip TEXT,

    details TEXT
);


CREATE TABLE IF NOT EXISTS network_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    status TEXT DEFAULT 'STOPPED',
    active_flows INTEGER DEFAULT 0,
    completed_flows INTEGER DEFAULT 0,
    total_flows_created INTEGER DEFAULT 0,
    total_packets INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    expired_flows INTEGER DEFAULT 0,
    tcp_flows INTEGER DEFAULT 0,
    udp_flows INTEGER DEFAULT 0,
    icmp_flows INTEGER DEFAULT 0,
    other_flows INTEGER DEFAULT 0
);


CREATE TABLE IF NOT EXISTS notification_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL, channel TEXT NOT NULL,
    dedupe_key TEXT NOT NULL, payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING', attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_notification_dedupe ON notification_outbox(dedupe_key, created_at);
CREATE TABLE IF NOT EXISTS auth_detection_cooldowns (
    ip_address TEXT PRIMARY KEY, last_alert_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shadow_ml_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL, flow_id TEXT,
    anomaly_score REAL, method TEXT NOT NULL,
    is_anomaly INTEGER NOT NULL DEFAULT 0,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shadow_event ON shadow_ml_predictions(event_id);

CREATE TABLE IF NOT EXISTS rbac_detection_cooldowns (
    source_ip TEXT NOT NULL,
    username TEXT NOT NULL,
    last_alert_at TEXT NOT NULL,
    PRIMARY KEY (source_ip, username)
);


CREATE TABLE IF NOT EXISTS firewall_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL, username TEXT NOT NULL,
    ip_address TEXT NOT NULL, action TEXT NOT NULL,
    status TEXT NOT NULL, details TEXT
);
CREATE INDEX IF NOT EXISTS idx_firewall_actions_time ON firewall_actions(timestamp);

CREATE TABLE IF NOT EXISTS system_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    timestamp TEXT NOT NULL,

    packets_processed INTEGER DEFAULT 0,

    events_detected INTEGER DEFAULT 0,

    alerts_created INTEGER DEFAULT 0,

    incidents_created INTEGER DEFAULT 0,

    average_risk REAL DEFAULT 0.0,

    engine_status TEXT DEFAULT 'ACTIVE'
);


CREATE INDEX IF NOT EXISTS idx_events_timestamp
ON events(timestamp);


CREATE INDEX IF NOT EXISTS idx_events_source_ip
ON events(source_ip);


CREATE INDEX IF NOT EXISTS idx_events_severity
ON events(severity);


CREATE INDEX IF NOT EXISTS idx_alerts_status
ON alerts(status);


CREATE INDEX IF NOT EXISTS idx_incidents_status
ON incidents(status);


CREATE INDEX IF NOT EXISTS idx_incidents_severity
ON incidents(severity);


CREATE INDEX IF NOT EXISTS idx_threat_ip
ON threat_intelligence(ip_address);

"""


def initialize_database():
    DB_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(DB_FILE)

    try:
        connection.executescript(SCHEMA)
        connection.commit()

    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()

    print("=" * 60)
    print("CYBER SENTINEL X - DATABASE INITIALIZED")
    print("=" * 60)
    print(f"Database: {DB_FILE}")
    print("SOC schema created successfully.")
