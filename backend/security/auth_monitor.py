"""Correlate observed failed authentication attempts across usernames by source IP.

Counts only logged events in the previous 5 minutes. 15-minute source cooldown
keeps one offender from creating an unbounded alert storm.
"""
from datetime import datetime, timedelta, timezone
import ipaddress
from backend.database.manager import db
from backend.core.logger import logger


def detect_failed_logins(source_ip):
    try:
        address = str(ipaddress.ip_address(source_ip))
        now = datetime.now(timezone.utc)
        since = (now - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
        with db.connection() as connection:
            count = connection.execute('''
                SELECT COUNT(*) FROM audit_logs
                WHERE source_ip = ? AND action = 'LOGIN_FAILURE' AND timestamp >= ?
            ''', (address, since)).fetchone()[0]
            if count < 5:
                return None
            last = connection.execute('''
                SELECT last_alert_at FROM auth_detection_cooldowns WHERE ip_address=?
            ''', (address,)).fetchone()
            if last and (now - datetime.fromisoformat(last[0])).total_seconds() < 900:
                return None
            # Transactionally update cooldown before emitting event.
            connection.execute('''
                INSERT INTO auth_detection_cooldowns (ip_address,last_alert_at)
                VALUES (?,?) ON CONFLICT(ip_address) DO UPDATE SET last_alert_at=excluded.last_alert_at
            ''', (address, now.isoformat()))
        from backend.detection.pipeline import pipeline
        from flask import request
        target = request.host.split(":")[0]
        result = pipeline.process_event({
            'source_ip': address,
            'destination_ip': target,  # Flask app target, not assumed attacker host
            'source_port': 0, 'destination_port': 8000,
            'protocol': 'HTTP', 'packet_count': count, 'unique_ports': 1,
            'risk_score': 85,
            'activity': f'AUTH_BRUTE_FORCE: {count} failed logins in 5 minutes',
        })
        logger.warning('AUTH_BRUTE_FORCE_DETECTED | source=%s count=%s' % (address, count))
        return result
    except Exception as exc:
        logger.error('AUTH_DETECTION_ERROR | %s' % type(exc).__name__)
        return None


def detect_rbac_denials(source_ip, username):
    """Detect repeated denied access to privileged operations."""
    try:
        address = str(ipaddress.ip_address(source_ip))
        now = datetime.now(timezone.utc)
        since = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        cutoff = (now - timedelta(minutes=15)).isoformat()

        with db.connection() as conn:
            count = conn.execute("""
                SELECT COUNT(*) FROM audit_logs
                WHERE action='RBAC_DENIED'
                AND source_ip=? AND username=? AND timestamp>=?
            """, (source_ip, username, since)).fetchone()[0]

            if count < 3:
                return None

            claim = conn.execute("""
                INSERT INTO rbac_detection_cooldowns
                (source_ip, username, last_alert_at)
                VALUES (?, ?, ?)
                ON CONFLICT(source_ip, username) DO UPDATE
                SET last_alert_at=excluded.last_alert_at
                WHERE last_alert_at <= ?
            """, (address, username, now.isoformat(), cutoff))

            if claim.rowcount != 1:
                return None

        from backend.detection.pipeline import pipeline
        from flask import request

        result = pipeline.process_event({
            "source_ip": address,
            "destination_ip": request.environ.get("SERVER_NAME", "localhost"),
            "source_port": 0,
            "destination_port": int(request.environ.get("SERVER_PORT", 8000)),
            "protocol": "HTTP",
            "packet_count": count,
            "unique_ports": 1,
            "risk_score": 70,
            "activity": f"RBAC_VIOLATION: {count} denied privileged actions"
        })

        logger.warning(
            f"RBAC_VIOLATION_DETECTED | source={address} | count={count}"
        )
        return result

    except Exception as exc:
        logger.error(f"RBAC_DETECTION_ERROR | {type(exc).__name__}")
        return None
