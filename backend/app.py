from backend.security.auth_service import auth_service
from flask import Flask, render_template, jsonify, request, Response, redirect
from pathlib import Path
import csv
import io
from datetime import datetime, timezone, timedelta

# ============================================================
# API
# ============================================================

from backend.api.incident_api import incident_api
from backend.api.auth_api import auth_api
from backend.api.rule_api import rule_api

# ============================================================
# CORE
# ============================================================

from backend.core.config import settings
from backend.core.logger import logger
from backend.database.manager import db
from backend.database.schema import initialize_database
from backend.pcap.pcap_analyzer import pcap_analyzer
from backend.detection.alert_service import alert_service

# ============================================================
# SECURITY
# ============================================================

from backend.security.self_protection import self_protection
from backend.security.security_headers import apply_security_headers
from backend.security.rate_limiter import rate_limiter
from backend.security.input_validator import input_validator

# ============================================================
# DETECTION
# ============================================================

from backend.detection.pipeline import pipeline
from backend.ml.anomaly_detector import anomaly_detector

# ============================================================
# NETWORK
# ============================================================

from backend.pcap.flow_aggregator import flow_aggregator
from backend.assets.discovery_service import asset_discovery_service


# ============================================================
# CYBER SENTINEL X
# SECURITY OPERATIONS PLATFORM
# APPLICATION ENTRY POINT
# ============================================================


def create_app():
    """
    Create and configure Cyber Sentinel X Flask application.
    """

    # ========================================================
    # FLASK APPLICATION
    # ========================================================

    # CREATE TABLE IF NOT EXISTS preserves existing project data.
    initialize_database()

    app = Flask(
        __name__,
        template_folder=str(
            settings.FRONTEND_DIR / "templates"
        ),
        static_folder=str(
            settings.FRONTEND_DIR / "static"
        )
    )

    # ========================================================
    # APPLICATION CONFIGURATION
    # ========================================================

    app.config["SECRET_KEY"] = settings.SECRET_KEY
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

    # Secure browser session configuration
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # Enable this when deployed behind HTTPS
    if settings.ENVIRONMENT.lower() in (
        "production",
        "prod"
    ):
        app.config["SESSION_COOKIE_SECURE"] = True
    else:
        app.config["SESSION_COOKIE_SECURE"] = False

    # ========================================================
    # SECURITY HEADERS
    # ========================================================

    app.after_request(
        apply_security_headers
    )

    # ========================================================
    # RATE LIMITING
    # ========================================================

    @app.before_request
    def cyber_sentinel_rate_limit():
        """
        Protect application endpoints from
        excessive request rates.
        """

        try:

            # Static files are excluded
            if request.path.startswith("/static/"):
                return None

            source_ip = (
                request.remote_addr
                or "UNKNOWN"
            )

            result = rate_limiter.check(
                source_ip
            )

            if not result["allowed"]:

                logger.warning(
                    "RATE_LIMIT | "
                    f"source={source_ip} | "
                    f"path={request.path} | "
                    f"count={result['request_count']} | "
                    f"retry={result['retry_after']}"
                )

                response = jsonify({
                    "error":
                        "Too many requests",
                    "retry_after":
                        result["retry_after"]
                })

                response.status_code = 429

                response.headers["Retry-After"] = str(
                    result["retry_after"]
                )

                return response

        except Exception as exc:

            logger.exception(
                f"RATE_LIMIT_ERROR | {exc}"
            )

        return None

    # ========================================================
    # INPUT VALIDATION
    # ========================================================

    @app.before_request
    def cyber_sentinel_input_validation():
        """
        Validate incoming HTTP request metadata
        before processing application routes.
        """

        try:

            source_ip = (
                request.remote_addr
                or "UNKNOWN"
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
                )
            }

            result = (
                input_validator.validate_request(
                    request_data
                )
            )

            if not result["valid"]:

                logger.warning(
                    "INPUT_VALIDATION | "
                    f"source={source_ip} | "
                    f"path={request.path} | "
                    f"errors={result['errors']}"
                )

                return jsonify({
                    "error":
                        "Invalid request",
                    "validation_errors":
                        result["errors"]
                }), 400

        except Exception as exc:

            logger.exception(
                f"INPUT_VALIDATION_ERROR | {exc}"
            )

        return None

    # ========================================================
    # SELF PROTECTION
    # ========================================================

    @app.before_request
    def cyber_sentinel_self_protection():
        """
        Inspect incoming requests for suspicious
        application-security activity.
        """

        try:

            # Do not trust arbitrary client X-Forwarded-For headers.
            # A trusted reverse proxy must be explicitly configured.
            import os
            source_ip = request.remote_addr
            trusted_proxies = {
                address.strip() for address in
                os.getenv("CSX_TRUSTED_PROXY_IPS", "").split(",") if address.strip()
            }
            if source_ip in trusted_proxies:
                forwarded = request.headers.get("X-Forwarded-For", "")
                if forwarded:
                    source_ip = forwarded.split(",")[0].strip()

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

            result = (
                self_protection.inspect_request(
                    request_data
                )
            )

            # ------------------------------------------------
            # SECURITY EVENT
            # ------------------------------------------------

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

                # Convert application-security
                # detection into Cyber Sentinel event.
                try:

                    pipeline.process_event({
                        "source_ip": source_ip,
                        "destination_ip":
                            request.host.split(":")[0],
                        "source_port": 0,
                        "destination_port":
                            request.environ.get(
                                "SERVER_PORT",
                                8000
                            ),
                        "protocol": "HTTP",
                        "packet_count": 1,
                        "unique_ports": 1,
                        "risk_score":
                            result["risk_score"],
                        "activity":
                            (
                                "APPLICATION_SECURITY_"
                                + result["severity"]
                            ),
                    })

                except Exception as pipeline_exc:

                    logger.exception(
                        "SELF_PROTECTION_PIPELINE_ERROR | "
                        f"{pipeline_exc}"
                    )

            # ------------------------------------------------
            # BLOCK
            # ------------------------------------------------

            if result["blocked"]:

                logger.error(
                    "SELF_PROTECTION_BLOCK | "
                    f"source={source_ip} | "
                    f"path={request.path} | "
                    f"risk={result['risk_score']}"
                )

                return jsonify({
                    "error":
                        "Request blocked by "
                        "Cyber Sentinel X",
                    "severity":
                        result["severity"],
                    "risk_score":
                        result["risk_score"],
                }), 403

        except Exception as exc:

            logger.exception(
                f"SELF_PROTECTION_ERROR | {exc}"
            )

        return None

    # ========================================================
    # BLUEPRINTS
    # ========================================================

    app.register_blueprint(
        incident_api
    )

    app.register_blueprint(
        rule_api
    )
    app.register_blueprint(
        auth_api
    )

    # ========================================================
    # WEB PAGES
    # ========================================================
    @app.route("/login")
    def login_page():
        return render_template("login.html")
    @app.route("/")
    @auth_service.login_required
    def dashboard():
        """
        Main SOC dashboard.
        """
        return render_template(
            "dashboard_new.html",
            title="Security Command Center",
            breadcrumb="OVERVIEW",
            view="dashboard",
            subtitle="Unified threat visibility, network telemetry and response."
        )

    # --------------------------------------------------------

    @app.route("/rules")
    @auth_service.login_required
    def rules_page():
        """Detection Rule Manager workspace."""
        return render_template("rules.html", title="Detection Rule Manager", breadcrumb="DETECTION RULES", view="rules", subtitle="Manage and tune your defensive detection policies.")

    # --------------------------------------------------------

    @app.route("/investigation")
    @auth_service.login_required
    def investigation():
        """
        Incident investigation workspace.
        """

        if not request.args.get("id"):
            return redirect("/incidents")
        return render_template(
            "investigation.html"
        )

    # ========================================================
    # SOC workspaces — page views are authenticated like the dashboard.
    @app.route("/alerts")
    @auth_service.login_required
    def alerts_page():
        return render_template("alerts.html", title="Security Alert Center", breadcrumb="ALERTS", view="alerts", subtitle="Investigate, acknowledge and close actionable security alerts.")

    @app.route("/incidents")
    @auth_service.login_required
    def incidents_page():
        return render_template("incidents.html", title="Incident Command Center", breadcrumb="INCIDENTS", view="incidents", subtitle="Track and investigate correlated security events.")

    @app.route("/live-network")
    @auth_service.login_required
    def live_network_page():
        return render_template("live_network.html", title="Live Network Monitor", breadcrumb="LIVE NETWORK", view="network", subtitle="Packet and flow statistics from your passive capture service.")

    @app.route("/assets")
    @auth_service.login_required
    def assets_page():
        return render_template("assets.html", title="Asset Intelligence", breadcrumb="ASSETS", view="assets", subtitle="Discover and review devices on your authorized network.")

    @app.route("/threat-sources")
    @auth_service.login_required
    def threat_sources_page():
        return render_template("threat_sources.html", title="Threat Source Analytics", breadcrumb="THREAT SOURCES", view="sources", subtitle="Local event-driven source risk, not external IP reputation.")

    @app.route("/reports")
    @auth_service.login_required
    def reports_page():
        return render_template("reports.html", title="SOC Report Exports", breadcrumb="REPORTS", view="reports", subtitle="Export current alert, event, incident and asset records.")

    @app.route("/pcap")
    @auth_service.login_required
    def pcap_page():
        """PCAP analysis workspace."""
        return render_template("pcap.html", title="Packet Capture Analysis", breadcrumb="PCAP ANALYSIS", view="pcap", subtitle="Inspect offline packet captures and traffic evidence.")


    @app.route("/api/pcap/analyze", methods=["POST"])
    @auth_service.login_required
    def analyze_pcap():
        """Upload and analyze a PCAP file."""

        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:
            return jsonify({"error": "PCAP file is required"}), 400

        allowed_extensions = {".pcap", ".pcapng", ".cap"}
        extension = Path(uploaded_file.filename).suffix.lower()

        if extension not in allowed_extensions:
            return jsonify({"error": "Unsupported capture format"}), 400

        # Validate capture file signature before saving.
        valid_signatures = {
            bytes.fromhex("d4c3b2a1"),
            bytes.fromhex("a1b2c3d4"),
            bytes.fromhex("4d3cb2a1"),
            bytes.fromhex("a1b23c4d"),
            bytes.fromhex("0a0d0d0a"),
        }

        signature = uploaded_file.stream.read(4)
        uploaded_file.stream.seek(0)

        if signature not in valid_signatures:
            return jsonify({"error": "Invalid PCAP file header"}), 400

        pcaps_dir = settings.PCAP_DIR
        pcaps_dir.mkdir(exist_ok=True)

        from uuid import uuid4

        unique_name = f"{uuid4().hex}{extension}"
        file_path = pcaps_dir / unique_name
        uploaded_file.save(file_path)

        try:
            analysis = pcap_analyzer.analyze(file_path)
            file_path.unlink(missing_ok=True)
            return jsonify({
                "status": "success",
                "analysis": analysis
            })

        except Exception as exc:
            logger.error(f"PCAP_ANALYSIS_ERROR | error={exc}")
            file_path.unlink(missing_ok=True)

            from scapy.error import Scapy_Exception

            if isinstance(exc, (ValueError, EOFError, Scapy_Exception)):
                return jsonify({"error": "Invalid or corrupted PCAP file"}), 400

            return jsonify({"error": "PCAP analysis failed"}), 500


    # HEALTH API
    # ========================================================

    @app.route("/api/health")
    def health():
        """
        Application health status.
        """

        database_status = "ONLINE"

        try:
            if not db.health_check():
                database_status = "OFFLINE"

        except Exception as exc:

            logger.error(
                f"HEALTH_DATABASE_ERROR | error={exc}"
            )

            database_status = "OFFLINE"

        return jsonify({

            "application":
                settings.APP_NAME,

            "version":
                settings.APP_VERSION,

            "status":
                (
                    "ONLINE"
                    if database_status == "ONLINE"
                    else "DEGRADED"
                ),

            "database":
                database_status,

            "ml_enabled":
                settings.ML_ENABLED,

            "ml_model_available":
                anomaly_detector.health_check()["model_available"],

            "ml_model_path":
                anomaly_detector.health_check()["model_path"],

            "ml_threshold":
                anomaly_detector.health_check()["threshold"],

            "ml_prediction_mode":
                (
                    "DISABLED"
                    if not settings.ML_ENABLED
                    else (
                        "ML_MODEL"
                        if anomaly_detector.health_check()["model_available"]
                        else "STATISTICAL_BASELINE"
                    )
                ),

            "environment":
                settings.ENVIRONMENT,

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat()
        })

    # ========================================================
    # SOC SUMMARY API
    # ========================================================

    @app.route("/api/soc/summary")
    @auth_service.login_required
    def soc_summary():
        """
        Real-time SOC overview.
        """

        try:

            # ------------------------------------------------
            # GLOBAL COUNTS
            # ------------------------------------------------

            events = db.count(
                "events"
            )

            alerts = db.count(
                "alerts"
            )

            incidents = db.count(
                "incidents"
            )

            assets = db.count(
                "assets"
            )

            # ------------------------------------------------
            # ACTIVE COUNTS
            # ------------------------------------------------

            # An acknowledged but unclosed alert remains active.
            open_alerts = db.count(
                "alerts",
                "status IN (?, ?)",
                ("OPEN", "ACKNOWLEDGED")
            )

            open_incidents = db.count(
                "incidents",
                "status IN (?, ?)",
                (
                    "OPEN",
                    "INVESTIGATING"
                )
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
            # EVENTS IN THE LAST 60 SECONDS (UTC)
            # ------------------------------------------------

            minute_ago = (
                datetime.now(timezone.utc) - timedelta(minutes=1)
            ).strftime("%Y-%m-%d %H:%M:%S")
            events_per_minute = db.count(
                "events", "created_at >= ?", (minute_ago,)
            )

            # ------------------------------------------------
            # ML ANOMALY COUNT
            # ------------------------------------------------

            anomaly_count = db.count(
                "events",
                "anomaly_score >= ?",
                (float(settings.ANOMALY_THRESHOLD),)
            )

            # ------------------------------------------------
            # ENVIRONMENT RISK
            # ------------------------------------------------

            risk_row = db.fetch_one(
                """
                SELECT
                    COALESCE(
                        AVG(risk_score),
                        0
                    ) AS average_risk
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

                "events":
                    events,

                "alerts":
                    alerts,

                "incidents":
                    incidents,

                "assets":
                    assets,

                "active_alerts":
                    open_alerts,

                "open_incidents":
                    open_incidents,

                "active_assets":
                    active_assets,

                "anomaly_count":
                    anomaly_count,

                "events_per_minute":
                    events_per_minute,

                "threat_score":
                    average_risk,

                "risk_level":
                    risk_level,

                "severity": {

                    "critical":
                        critical_events,

                    "high":
                        high_events,

                    "suspicious":
                        suspicious_events,

                    "normal":
                        normal_events
                },

                "platform": {

                    "status":
                        "OPERATIONAL",

                    "ml_enabled":
                        settings.ML_ENABLED,

                    "threat_intelligence":
                        (
                            settings
                            .THREAT_INTELLIGENCE_ENABLED
                        ),

                    "correlation":
                        (
                            settings
                            .CORRELATION_ENABLED
                        )
                },

                "timestamp":
                    datetime.now(
                        timezone.utc
                    ).isoformat()
            })

        except Exception as exc:

            logger.exception(
                f"SOC_SUMMARY_ERROR | error={exc}"
            )

            return jsonify({
                "error":
                    "Unable to load SOC summary"
            }), 500

    # ========================================================
    # RECENT SECURITY EVENTS
    # ========================================================

    @app.route("/api/soc/events")
    @auth_service.login_required
    def recent_events():
        """
        Return latest security events.
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
                ORDER BY id DESC
                LIMIT 20
                """
            )

            events = [
                dict(row)
                for row in rows
            ]

            return jsonify({

                "status":
                    "success",

                "count":
                    len(events),

                "events":
                    events
            })

        except Exception as exc:

            logger.exception(
                f"RECENT_EVENTS_ERROR | error={exc}"
            )

            return jsonify({
                "error":
                    "Unable to load events"
            }), 500

    # ========================================================
    # SECURITY ALERTS
    # ========================================================

    @app.route("/api/soc/alerts")
    @auth_service.login_required
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

                "status":
                    "success",

                "count":
                    len(alerts_data),

                "summary": {
                    "total": db.count("alerts"),
                    "critical": db.count("alerts", "severity = ?", ("CRITICAL",)),
                    "high": db.count("alerts", "severity = ?", ("HIGH",)),
                    "suspicious": db.count("alerts", "severity = ?", ("SUSPICIOUS",))
                },

                "alerts":
                    alerts_data
            })

        except Exception as exc:

            logger.exception(
                f"SECURITY_ALERTS_ERROR | error={exc}"
            )

            return jsonify({
                "error":
                    "Unable to load alerts"
            }), 500

    # ========================================================
    # ALERT TRIAGE — existing Alert Center button endpoints
    # ========================================================

    @app.post("/api/soc/alerts/<int:row_id>/acknowledge")
    @auth_service.login_required
    def acknowledge_soc_alert(row_id):
        row = db.fetch_one("SELECT * FROM alerts WHERE id = ?", (row_id,))
        if row is None:
            return jsonify({"error": "Alert not found"}), 404
        if row["status"] == "CLOSED":
            return jsonify({"error": "Closed alerts cannot be acknowledged"}), 409
        if row["status"] != "ACKNOWLEDGED":
            alert_service.acknowledge_alert(row["alert_id"])
        return jsonify({"status": "ACKNOWLEDGED", "alert_id": row["alert_id"]})

    @app.post("/api/soc/alerts/<int:row_id>/close")
    @auth_service.login_required
    def close_soc_alert(row_id):
        row = db.fetch_one("SELECT * FROM alerts WHERE id = ?", (row_id,))
        if row is None:
            return jsonify({"error": "Alert not found"}), 404
        if row["status"] != "CLOSED":
            alert_service.close_alert(row["alert_id"])
        return jsonify({"status": "CLOSED", "alert_id": row["alert_id"]})

    # ========================================================
    # SOC READ-ONLY REPORT EXPORT / THREAT SOURCE ROLLUP
    # ========================================================

    @app.get("/api/soc/reports/<kind>.csv")
    @auth_service.login_required
    def export_soc_report(kind):
        allowed = {"alerts", "events", "incidents", "assets"}
        if kind not in allowed:
            return jsonify({"error": "Unknown report"}), 404
        # Table names are selected from a strict allowlist (never user SQL).
        rows = db.fetch_all(f"SELECT * FROM {kind} ORDER BY id DESC LIMIT 1000")
        buffer = io.StringIO()
        columns = list(rows[0].keys()) if rows else [
            col["name"] for col in db.fetch_all(f"PRAGMA table_info({kind})")
        ]
        writer = csv.DictWriter(buffer, fieldnames=columns)
        writer.writeheader()
        if rows:
            for row in rows:
                # Avoid spreadsheet formula injection on exported text cells.
                writer.writerow({
                    key: ("'" + value if isinstance(value, str)
                          and value.lstrip().startswith(("=", "+", "-", "@"))
                          else value)
                    for key, value in row.items()
                })
        return Response(
            buffer.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=csx_{kind}.csv",
                     "Cache-Control": "no-store"},
        )

    @app.get("/api/soc/threat-sources")
    @auth_service.login_required
    def threat_sources():
        rows = db.fetch_all("""
            SELECT source_ip, COUNT(*) AS event_count,
                   MAX(risk_score) AS max_risk,
                   MAX(created_at) AS last_seen
            FROM events
            GROUP BY source_ip
            ORDER BY max_risk DESC, event_count DESC
            LIMIT 50
        """)
        from backend.intelligence.geo_service import geo_lookup
        items = []
        for row in rows:
            record = dict(row)
            record["geolocation"] = geo_lookup(record["source_ip"])
            items.append(record)
        return jsonify({"status": "success", "sources": items,
                        "note": "Observed events only; GeoLite2 location is approximate if configured."})

    # ========================================================
    # ASSET OVERVIEW
    # ========================================================

    @app.route("/api/soc/assets/discover", methods=["POST"])
    @auth_service.login_required
    def discover_assets():
        """
        Discover active hosts on an authorized local IPv4 network
        and register/update them in the asset inventory.
        """
        try:
            payload = request.get_json(silent=True) or {}
            network = payload.get("network")

            if not network:
                return jsonify({
                    "status": "error",
                    "error": "Network is required"
                }), 400

            result = asset_discovery_service.discover(network)

            return jsonify({
                "status": "success",
                **result
            })

        except ValueError as exc:
            return jsonify({
                "status": "error",
                "error": str(exc)
            }), 400

        except Exception as exc:
            logger.exception(
                f"ASSET_DISCOVERY_ERROR | error={exc}"
            )

            return jsonify({
                "status": "error",
                "error": "Asset discovery failed"
            }), 500


    @app.route("/api/soc/assets")
    @auth_service.login_required
    def soc_assets():
        """
        Return monitored assets.
        """

        try:

            rows = db.fetch_all(
                """
                SELECT *
                FROM assets
                ORDER BY id DESC
                LIMIT 50
                """
            )

            assets_data = [
                dict(row)
                for row in rows
            ]

            return jsonify({

                "status":
                    "success",

                "count":
                    len(assets_data),

                "assets":
                    assets_data
            })

        except Exception as exc:

            logger.exception(
                f"SOC_ASSETS_ERROR | error={exc}"
            )

            return jsonify({
                "error":
                    "Unable to load assets"
            }), 500

    # ========================================================
    # ENVIRONMENT RISK API
    # ========================================================

    @app.route("/api/soc/risk")
    @auth_service.login_required
    def environment_risk():
        """
        Calculate current environment risk.
        """

        try:

            row = db.fetch_one(
                """
                SELECT
                    COALESCE(
                        AVG(risk_score),
                        0
                    ) AS average_risk,

                    COALESCE(
                        MAX(risk_score),
                        0
                    ) AS maximum_risk

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

                "average_risk":
                    average_risk,

                "maximum_risk":
                    maximum_risk,

                "risk_level":
                    level,

                "scale":
                    100
            })

        except Exception as exc:

            logger.exception(
                f"ENVIRONMENT_RISK_ERROR | error={exc}"
            )

            return jsonify({
                "error":
                    "Unable to calculate risk"
            }), 500

    # ========================================================
    # SYSTEM INFORMATION
    # ========================================================

    @app.route("/api/system")
    @auth_service.login_required
    def system_info():
        """
        Cyber Sentinel X platform capabilities.
        """

        return jsonify({

            "name":
                settings.APP_NAME,

            "version":
                settings.APP_VERSION,

            "environment":
                settings.ENVIRONMENT,

            "ml": {

                "enabled":
                    settings.ML_ENABLED,

                "threshold":
                    settings.ANOMALY_THRESHOLD,

                "model":
                    settings.MODEL_NAME
            },

            "detection": {

                "rules":
                    True,

                "behaviour":
                    True,

                "correlation":
                    settings.CORRELATION_ENABLED,

                "threat_intelligence":
                    settings
                    .THREAT_INTELLIGENCE_ENABLED
            },

            "monitoring": {

                "packet_capture":
                    settings
                    .PACKET_CAPTURE_ENABLED,

                "interface":
                    settings
                    .NETWORK_INTERFACE
            },

            "security": {

                "self_protection":
                    True,

                "rate_limiting":
                    True,

                "input_validation":
                    True,

                "security_headers":
                    True,

                "authentication":
                    True,

                "rbac":
                    True
            }
        })

    # ========================================================
    # PREMIUM V3: RESPONSE & INVESTIGATION EXTENSIONS
    # ========================================================

    @app.get("/firewall")
    @auth_service.login_required
    def firewall_page():
        return render_template("firewall.html", title="Firewall Control",
            breadcrumb="FIREWALL", view="firewall",
            subtitle="Explicit, host-scoped defensive response with preview and rollback.")

    @app.get("/notifications")
    @auth_service.login_required
    def notifications_page():
        return render_template("notifications.html", title="Admin Notifications",
            breadcrumb="NOTIFICATIONS", view="notifications",
            subtitle="Email and voice notification delivery status; never simulated.")

    @app.get("/api/soc/notifications")
    @auth_service.role_required("ADMIN", "SOC_ANALYST")
    def notifications_status():
        from backend.response.notifications import status
        return jsonify(status())

    @app.get("/api/soc/firewall")
    @auth_service.role_required("ADMIN", "SOC_ANALYST")
    def firewall_status():
        from backend.response.firewall import status
        return jsonify(status())

    @app.post("/api/soc/firewall/<operation>")
    @auth_service.role_required("ADMIN")
    def firewall_change(operation):
        # JSON-only & same-origin guard for consequential operations.
        origin = request.headers.get("Origin")
        if origin and origin != request.host_url.rstrip("/"):
            return jsonify({"error":"Cross-origin firewall action denied"}), 403
        if not request.is_json:
            return jsonify({"error":"JSON request required"}), 415
        data = request.get_json(silent=True) or {}
        from backend.response.firewall import action
        user = auth_service.current_user()
        try:
            result = action(data.get("ip"), operation,
                user["username"], confirmed=data.get("confirmation") == "CONFIRM")
            from backend.core.audit import audit
            audit.record(action="FIREWALL_" + operation.upper(),
                username=user["username"], resource="host_firewall",
                source_ip=request.remote_addr, details=result)
            return jsonify(result)
        except ValueError as exc:
            return jsonify({"error":str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"error":str(exc)}), 503

    @app.get("/api/soc/ml/shadow")
    @auth_service.login_required
    def ml_shadow_activity():
        records = db.fetch_all("""SELECT id,event_id,flow_id,anomaly_score,method,
            is_anomaly,timestamp FROM shadow_ml_predictions ORDER BY id DESC LIMIT 50""")
        return jsonify({"mode":"EXPERIMENTAL_SHADOW", "predictions":records,
            "note":"Model results do not trigger alerts, and are not production validated."})

    @app.get("/api/soc/threat-sources/<path:address>/investigate")
    @auth_service.login_required
    def investigate_threat_source(address):
        import ipaddress
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return jsonify({"error":"Invalid IP address"}), 400
        from backend.intelligence.geo_service import source_detail
        return jsonify(source_detail(address))

    # ========================================================
    # API 404 HANDLER
    # ========================================================

    @app.errorhandler(404)
    def not_found(error):

        return jsonify({

            "error":
                "Endpoint not found",

            "status":
                404
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

            "error":
                "Internal server error",

            "status":
                500
        }), 500

    # ========================================================
    # APPLICATION INITIALIZED
    # ========================================================

    # ========================================================
    # ML ANOMALY DETECTOR INITIALIZATION
    # ========================================================

    if settings.ML_ENABLED:
        try:
            anomaly_detector.load_model()

            ml_status = anomaly_detector.health_check()

            mode = (
                "ML_MODEL"
                if ml_status["model_available"]
                else "STATISTICAL_BASELINE"
            )

            logger.info(
                f"ML_STARTUP | "
                f"enabled={ml_status['enabled']} | "
                f"model_available={ml_status['model_available']} | "
                f"mode={mode}"
            )

        except Exception as exc:
            logger.error(
                f"ML_STARTUP_ERROR | error={exc}"
            )

    else:
        logger.info("ML_STARTUP | disabled")

    logger.info(
        "CYBER_SENTINEL_X | "
        "Flask application initialized"
    )

    # ============================================================
    # LIVE NETWORK FLOW API
    # ============================================================

    @app.route("/api/soc/network")
    @auth_service.login_required
    def soc_network():
        """
        Return latest shared network metrics.
        """

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

                    "status":
                        "STOPPED",

                    "capture_fresh": False,

                    "active_flows":
                        0,

                    "completed_flows":
                        0,

                    "total_flows_created":
                        0,

                    "total_packets":
                        0,

                    "total_bytes":
                        0,

                    "expired_flows":
                        0,

                    "protocol_distribution": {

                        "TCP":
                            0,

                        "UDP":
                            0,

                        "ICMP":
                            0,

                        "OTHER":
                            0
                    },

                    "timestamp":
                        datetime.now(
                            timezone.utc
                        ).isoformat()
                })

            data = dict(row)

            # Metrics are written by the separate live capture process.
            # A stale last row must not be mistaken for ongoing capture.
            try:
                last_write = datetime.fromisoformat(data["timestamp"])
                if last_write.tzinfo is None:
                    last_write = last_write.replace(tzinfo=datetime.now().astimezone().tzinfo)
                metrics_age = max(0, (datetime.now(timezone.utc) -
                                      last_write.astimezone(timezone.utc)).total_seconds())
                capture_fresh = metrics_age < 20 and data.get("status") == "RUNNING"
            except (ValueError, TypeError, KeyError):
                metrics_age = None
                capture_fresh = False

            return jsonify({

                "status": "RUNNING" if capture_fresh else "STOPPED",

                "capture_fresh": capture_fresh,
                "metrics_age_seconds": metrics_age,

                "active_flows":
                    data.get(
                        "active_flows",
                        0
                    ),

                "completed_flows":
                    data.get(
                        "completed_flows",
                        0
                    ),

                "total_flows_created":
                    data.get(
                        "total_flows_created",
                        0
                    ),

                "total_packets":
                    data.get(
                        "total_packets",
                        0
                    ),

                "total_bytes":
                    data.get(
                        "total_bytes",
                        0
                    ),

                "expired_flows":
                    data.get(
                        "expired_flows",
                        0
                    ),

                "protocol_distribution": {

                    "TCP":
                        data.get(
                            "tcp_flows",
                            0
                        ),

                    "UDP":
                        data.get(
                            "udp_flows",
                            0
                        ),

                    "ICMP":
                        data.get(
                            "icmp_flows",
                            0
                        ),

                    "OTHER":
                        data.get(
                            "other_flows",
                            0
                        )
                },

                "timestamp":
                    data.get(
                        "timestamp",
                        datetime.now(
                            timezone.utc
                        ).isoformat()
                    )
            })

        except Exception as exc:

            logger.exception(
                f"SOC_NETWORK_ERROR | error={exc}"
            )

            return jsonify({
                "error":
                    "Network statistics unavailable"
            }), 500


    return app


# ============================================================
# APPLICATION INSTANCE
# ============================================================

app = create_app()


# ============================================================
# SERVER START
# ============================================================

if __name__ == "__main__":

    print("=" * 64)

    print(
        "        CYBER SENTINEL X"
    )

    print(
        "        SECURITY OPERATIONS PLATFORM"
    )

    print("=" * 64)

    print(
        f"Application : "
        f"{settings.APP_NAME}"
    )

    print(
        f"Version     : "
        f"{settings.APP_VERSION}"
    )

    print(
        f"Environment : "
        f"{settings.ENVIRONMENT}"
    )

    print(
        f"Host        : "
        f"{settings.HOST}"
    )

    print(
        f"Port        : "
        f"{settings.PORT}"
    )

    print(
        f"Dashboard   : "
        f"http://127.0.0.1:"
        f"{settings.PORT}/"
    )

    print(
        f"Investigation : "
        f"http://127.0.0.1:"
        f"{settings.PORT}/investigation"
    )

    print(
        f"Health API  : "
        f"http://127.0.0.1:"
        f"{settings.PORT}/api/health"
    )

    print(
        f"Auth API    : "
        f"http://127.0.0.1:"
        f"{settings.PORT}/api/auth"
    )

    print("=" * 64)

    app.run(
        host=settings.HOST,
        port=settings.PORT,
        debug=settings.DEBUG
    )
