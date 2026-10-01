from flask import Flask, render_template, jsonify, request
from datetime import datetime, timezone

from backend.api.incident_api import incident_api

from backend.core.config import settings
from backend.core.logger import logger
from backend.security.self_protection import self_protection
from backend.security.security_headers import apply_security_headers
from backend.detection.pipeline import pipeline
from backend.database.manager import db
from backend.pcap.flow_aggregator import flow_aggregator


# ============================================================
# CYBER SENTINEL X
# SECURITY OPERATIONS PLATFORM
# APPLICATION ENTRY POINT
# ============================================================



@app.before_request
def cyber_sentinel_self_protection():
    try:
        source_ip = request.headers.get(
            "X-Forwarded-For",
            request.remote_addr
        )

        request_data = {
            "source_ip": source_ip,
            "method": request.method,
            "path": request.path,
            "query": request.query_string.decode(
                "utf-8",
                errors="ignore"
            ),
            "body": "",
            "user_agent": request.headers.get(
                "User-Agent",
                ""
            ),
        }

        result = self_protection.inspect_request(
            request_data
        )

        if result["severity"] in (
            "SUSPICIOUS",
            "HIGH",
            "CRITICAL",
        ):
            logger.warning(
                "SELF_PROTECTION | "
                f"source={source_ip} | "
                f"path={request.path} | "
                f"severity={result['severity']} | "
                f"risk={result['risk_score']} | "
                f"action={result['action']}"
            )

            # Convert application-security detection into
            # a normal Cyber Sentinel X detection event.
            pipeline.process_event({
                "source_ip": source_ip,
                "destination_ip": request.host.split(":")[0],
                "source_port": 0,
                "destination_port": request.environ.get(
                    "SERVER_PORT", 8000
                ),
                "protocol": "HTTP",
                "packet_count": 1,
                "unique_ports": 1,
                "risk_score": result["risk_score"],
                "activity": (
                    "APPLICATION_SECURITY_" +
                    result["severity"]
                ),
            })

        if result["blocked"]:
            return jsonify({
                "error": "Request blocked by Cyber Sentinel X",
                "severity": result["severity"],
                "risk_score": result["risk_score"],
            }), 403

    except Exception as exc:
        logger.exception(
            f"SELF_PROTECTION_ERROR | {exc}"
        )


def create_app():
    """
    Create and configure the Cyber Sentinel X Flask application.
    """

    app = Flask(
        __name__,
        template_folder=str(
            settings.FRONTEND_DIR / "templates"
        ),
        static_folder=str(
            settings.FRONTEND_DIR / "static"
        )
    )

    app.after_request(apply_security_headers)

    # --------------------------------------------------------
    # APPLICATION CONFIGURATION
    # --------------------------------------------------------

    app.config["SECRET_KEY"] = settings.SECRET_KEY
    app.config["JSON_SORT_KEYS"] = False

    # --------------------------------------------------------
    # BLUEPRINTS
    # --------------------------------------------------------

    app.register_blueprint(incident_api)

    # ========================================================
    # WEB PAGES
    # ========================================================

    @app.route("/")
    def dashboard():
        """
        Main SOC dashboard.
        """
        return render_template("dashboard.html")

    # --------------------------------------------------------

    @app.route("/investigation")
    def investigation():
        """
        Incident investigation workspace.
        """
        return render_template("investigation.html")

    # ========================================================
    # HEALTH API
    # ========================================================

    @app.route("/api/health")
    def health():
        """
        Application health status.
        """

        database_status = "ONLINE"

        try:
            db.health_check()

        except Exception as exc:
            logger.error(
                f"HEALTH_DATABASE_ERROR | error={exc}"
            )

            database_status = "OFFLINE"

        return jsonify({
            "application": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": (
                "ONLINE"
                if database_status == "ONLINE"
                else "DEGRADED"
            ),
            "database": database_status,
            "ml_enabled": settings.ML_ENABLED,
            "environment": settings.ENVIRONMENT,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat()
        })

    # ========================================================
    # SOC SUMMARY API
    # ========================================================

    @app.route("/api/soc/summary")
    def soc_summary():
        """
        Real-time SOC overview.

        Used by the main dashboard for:
        - events
        - alerts
        - incidents
        - assets
        - severity distribution
        - environment risk
        """

        try:

            # ------------------------------------------------
            # GLOBAL COUNTS
            # ------------------------------------------------

            events = db.count("events")

            alerts = db.count("alerts")

            incidents = db.count("incidents")

            assets = db.count("assets")

            # ------------------------------------------------
            # ACTIVE COUNTS
            # ------------------------------------------------

            open_alerts = db.count(
                "alerts",
                "status = ?",
                ("OPEN",)
            )

            open_incidents = db.count(
                "incidents",
                "status IN (?, ?)",
                ("OPEN", "INVESTIGATING")
            )

            active_assets = db.count(
                "assets",
                "status = ?",
                ("ACTIVE",)
            )

            # ------------------------------------------------
            # EVENT SEVERITY
            # ------------------------------------------------

            critical_events = db.count(
                "events",
                "severity = ?",
                ("CRITICAL",)
            )

            high_events = db.count(
                "events",
                "severity = ?",
                ("HIGH",)
            )

            suspicious_events = db.count(
                "events",
                "severity = ?",
                ("SUSPICIOUS",)
            )

            normal_events = db.count(
                "events",
                "severity = ?",
                ("NORMAL",)
            )

            # ------------------------------------------------
            # ENVIRONMENT RISK
            # ------------------------------------------------

            risk_row = db.fetch_one(
                """
                SELECT
                    COALESCE(AVG(risk_score), 0)
                    AS average_risk
                FROM events
                """
            )

            average_risk = 0

            if risk_row:
                average_risk = round(
                    float(
                        risk_row["average_risk"]
                        or 0
                    )
                )

            # ------------------------------------------------
            # RISK CLASSIFICATION
            # ------------------------------------------------

            if average_risk >= 80:
                risk_level = "CRITICAL"

            elif average_risk >= 60:
                risk_level = "HIGH"

            elif average_risk >= 40:
                risk_level = "SUSPICIOUS"

            elif average_risk >= 20:
                risk_level = "MEDIUM"

            else:
                risk_level = "LOW"

            # ------------------------------------------------
            # RESPONSE
            # ------------------------------------------------

            return jsonify({

                # Core SOC metrics
                "events": events,
                "alerts": alerts,
                "incidents": incidents,
                "assets": assets,

                # Active metrics
                "active_alerts": open_alerts,
                "open_incidents": open_incidents,
                "active_assets": active_assets,

                # Environment risk
                "threat_score": average_risk,
                "risk_level": risk_level,

                # Severity distribution
                "severity": {
                    "critical": critical_events,
                    "high": high_events,
                    "suspicious": suspicious_events,
                    "normal": normal_events
                },

                # Platform state
                "platform": {
                    "status": "OPERATIONAL",
                    "ml_enabled": settings.ML_ENABLED,
                    "threat_intelligence": (
                        settings.THREAT_INTELLIGENCE_ENABLED
                    ),
                    "correlation": (
                        settings.CORRELATION_ENABLED
                    )
                },

                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat()
            })

        except Exception as exc:

            logger.exception(
                f"SOC_SUMMARY_ERROR | error={exc}"
            )

            return jsonify({
                "error": "Unable to load SOC summary",
                "status": 500
            }), 500

    # ========================================================
    # RECENT SECURITY EVENTS
    # ========================================================

    @app.route("/api/soc/events")
    def recent_events():
        """
        Return the latest security events.

        Dashboard uses this for the
        Recent Security Activity panel.
        """

        try:

            rows = db.fetch_all(
                """
                SELECT
                    event_id,
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    protocol,
                    severity,
                    risk_score,
                    activity,
                    timestamp,
                    created_at
                FROM events
                ORDER BY
                    id DESC
                LIMIT 20
                """
            )

            events = [
                dict(row)
                for row in rows
            ]

            return jsonify({
                "status": "success",
                "count": len(events),
                "events": events
            })

        except Exception as exc:

            logger.exception(
                f"RECENT_EVENTS_ERROR | error={exc}"
            )

            return jsonify({
                "error": "Unable to load events"
            }), 500

    # ========================================================
    # SECURITY ALERTS
    # ========================================================

    @app.route("/api/soc/alerts")
    def security_alerts():
        """
        Return recent security alerts.
        """

        try:

            rows = db.fetch_all(
                """
                SELECT *
                FROM alerts
                ORDER BY id DESC
                LIMIT 20
                """
            )

            alerts_data = [
                dict(row)
                for row in rows
            ]

            return jsonify({
                "status": "success",
                "count": len(alerts_data),
                "alerts": alerts_data
            })

        except Exception as exc:

            logger.exception(
                f"SECURITY_ALERTS_ERROR | error={exc}"
            )

            return jsonify({
                "error": "Unable to load alerts"
            }), 500

    # ========================================================
    # ASSET OVERVIEW
    # ========================================================

    @app.route("/api/soc/assets")
    def soc_assets():
        """
        Return monitored assets.
        """

        try:

            rows = db.fetch_all(
                """
                SELECT *
                FROM assets
                ORDER BY
                    id DESC
                LIMIT 50
                """
            )

            assets_data = [
                dict(row)
                for row in rows
            ]

            return jsonify({
                "status": "success",
                "count": len(assets_data),
                "assets": assets_data
            })

        except Exception as exc:

            logger.exception(
                f"SOC_ASSETS_ERROR | error={exc}"
            )

            return jsonify({
                "error": "Unable to load assets"
            }), 500

    # ========================================================
    # ENVIRONMENT RISK API
    # ========================================================

    @app.route("/api/soc/risk")
    def environment_risk():
        """
        Calculate current environment risk.
        """

        try:

            row = db.fetch_one(
                """
                SELECT
                    COALESCE(AVG(risk_score), 0)
                    AS average_risk,

                    COALESCE(MAX(risk_score), 0)
                    AS maximum_risk

                FROM events
                """
            )

            average_risk = 0
            maximum_risk = 0

            if row:

                average_risk = round(
                    float(
                        row["average_risk"]
                        or 0
                    )
                )

                maximum_risk = round(
                    float(
                        row["maximum_risk"]
                        or 0
                    )
                )

            if average_risk >= 80:
                level = "CRITICAL"

            elif average_risk >= 60:
                level = "HIGH"

            elif average_risk >= 40:
                level = "SUSPICIOUS"

            elif average_risk >= 20:
                level = "MEDIUM"

            else:
                level = "LOW"

            return jsonify({
                "average_risk": average_risk,
                "maximum_risk": maximum_risk,
                "risk_level": level,
                "scale": 100
            })

        except Exception as exc:

            logger.exception(
                f"ENVIRONMENT_RISK_ERROR | error={exc}"
            )

            return jsonify({
                "error": "Unable to calculate risk"
            }), 500

    # ========================================================
    # SYSTEM INFORMATION
    # ========================================================

    @app.route("/api/system")
    def system_info():
        """
        Cyber Sentinel X platform capabilities.
        """

        return jsonify({

            "name": settings.APP_NAME,

            "version": settings.APP_VERSION,

            "environment": settings.ENVIRONMENT,

            "ml": {
                "enabled": settings.ML_ENABLED,
                "threshold": (
                    settings.ANOMALY_THRESHOLD
                ),
                "model": settings.MODEL_NAME
            },

            "detection": {
                "rules": True,

                "behaviour": True,

                "correlation": (
                    settings.CORRELATION_ENABLED
                ),

                "threat_intelligence": (
                    settings.THREAT_INTELLIGENCE_ENABLED
                )
            },

            "monitoring": {
                "packet_capture": (
                    settings.PACKET_CAPTURE_ENABLED
                ),

                "interface": (
                    settings.NETWORK_INTERFACE
                )
            }
        })

    # ========================================================
    # API 404 HANDLER
    # ========================================================

    @app.errorhandler(404)
    def not_found(error):

        return jsonify({
            "error": "Endpoint not found",
            "status": 404
        }), 404

    # ========================================================
    # API 500 HANDLER
    # ========================================================

    @app.errorhandler(500)
    def internal_error(error):

        logger.error(
            f"APPLICATION_ERROR | error={error}"
        )

        return jsonify({
            "error": "Internal server error",
            "status": 500
        }), 500

    # ========================================================
    # APPLICATION INITIALIZED
    # ========================================================

    logger.info(
        "CYBER_SENTINEL_X | "
        "Flask application initialized"
    )

    return app


# ============================================================
# APPLICATION INSTANCE
# ============================================================

app = create_app()


# ============================================================
# SERVER START
# ============================================================


# ========================================================
# LIVE NETWORK FLOW API
# ========================================================

@app.route("/api/soc/network")
def soc_network():
    try:
        row = db.fetch_one(
            """
            SELECT *
            FROM network_metrics
            ORDER BY id DESC
            LIMIT 1
            """
        )

        if not row:
            return jsonify({
                "status": "STOPPED",
                "active_flows": 0,
                "completed_flows": 0,
                "total_flows_created": 0,
                "total_packets": 0,
                "total_bytes": 0,
                "expired_flows": 0,
                "protocol_distribution": {
                    "TCP": 0,
                    "UDP": 0,
                    "ICMP": 0,
                    "OTHER": 0
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

        data = dict(row)

        return jsonify({
            "status": data.get("status", "STOPPED"),
            "active_flows": data.get("active_flows", 0),
            "completed_flows": data.get("completed_flows", 0),
            "total_flows_created": data.get("total_flows_created", 0),
            "total_packets": data.get("total_packets", 0),
            "total_bytes": data.get("total_bytes", 0),
            "expired_flows": data.get("expired_flows", 0),
            "protocol_distribution": {
                "TCP": data.get("tcp_flows", 0),
                "UDP": data.get("udp_flows", 0),
                "ICMP": data.get("icmp_flows", 0),
                "OTHER": data.get("other_flows", 0)
            },
            "timestamp": data.get(
                "timestamp",
                datetime.now(timezone.utc).isoformat()
            )
        })

    except Exception as exc:
        logger.exception(
            f"SOC_NETWORK_ERROR | error={exc}"
        )
        return jsonify({
            "error": "Network statistics unavailable"
        }), 500


if __name__ == "__main__":

    print("=" * 64)
    print("        CYBER SENTINEL X")
    print("        SECURITY OPERATIONS PLATFORM")
    print("=" * 64)

    print(
        f"Application : {settings.APP_NAME}"
    )

    print(
        f"Version     : {settings.APP_VERSION}"
    )

    print(
        f"Environment : {settings.ENVIRONMENT}"
    )

    print(
        f"Host        : {settings.HOST}"
    )

    print(
        f"Port        : {settings.PORT}"
    )

    print(
        f"Dashboard   : "
        f"http://127.0.0.1:{settings.PORT}/"
    )

    print(
        f"Investigation : "
        f"http://127.0.0.1:{settings.PORT}/investigation"
    )

    print(
        f"Health API  : "
        f"http://127.0.0.1:{settings.PORT}/api/health"
    )

    print("=" * 64)

    app.run(
        host=settings.HOST,
        port=settings.PORT,
        debug=settings.DEBUG
    )
