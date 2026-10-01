from backend.api.incident_api import incident_api

from flask import Flask, render_template, jsonify
from pathlib import Path

from backend.core.config import settings
from backend.core.logger import logger
from backend.database.manager import db


def create_app():
    """
    Create and configure the Cyber Sentinel X Flask application.
    """

    app = Flask(
        __name__,
    app.register_blueprint(incident_api)
        template_folder=str(
            settings.FRONTEND_DIR / "templates"
        ),
        static_folder=str(
            settings.FRONTEND_DIR / "static"
        )
    )

    app.config["SECRET_KEY"] = settings.SECRET_KEY

    # ---------------------------------------------------------
    # DASHBOARD
    # ---------------------------------------------------------

    @app.route("/")
    def dashboard():
        return render_template(
            "dashboard.html"
        )

    # ---------------------------------------------------------
    # HEALTH API
    # ---------------------------------------------------------

    @app.route("/api/health")
    def health():
        database_status = "ONLINE"

        try:
            db.health_check()
        except Exception as exc:
            logger.error(
                f"HEALTH_DATABASE_ERROR | error={exc}"
            )
            database_status = "OFFLINE"

        return jsonify({
            "application": "Cyber Sentinel X",
            "version": settings.APP_VERSION,
            "status": "ONLINE",
            "database": database_status,
            "ml_enabled": settings.ML_ENABLED,
            "environment": settings.ENVIRONMENT
        })

    # ---------------------------------------------------------
    # SOC SUMMARY API
    # ---------------------------------------------------------

    @app.route("/api/soc/summary")
    def soc_summary():

        try:
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

            open_alerts = db.count(
                "alerts",
                "status = ?",
                ("OPEN",)
            )

            open_incidents = db.count(
                "incidents",
                "status = ?",
                ("OPEN",)
            )

            active_assets = db.count(
                "assets",
                "status = ?",
                ("ACTIVE",)
            )

            return jsonify({
                "events": events,
                "alerts": alerts,
                "incidents": incidents,
                "assets": assets,
                "active_alerts": open_alerts,
                "open_incidents": open_incidents,
                "active_assets": active_assets
            })

        except Exception as exc:

            logger.error(
                f"SOC_SUMMARY_ERROR | error={exc}"
            )

            return jsonify({
                "error": "Unable to load SOC summary"
            }), 500

    # ---------------------------------------------------------
    # SYSTEM INFORMATION
    # ---------------------------------------------------------

    @app.route("/api/system")
    def system_info():

        return jsonify({
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
            "ml": {
                "enabled": settings.ML_ENABLED,
                "threshold": settings.ANOMALY_THRESHOLD,
                "model": settings.MODEL_NAME
            },
            "detection": {
                "rules": True,
                "behaviour": True,
                "correlation": settings.CORRELATION_ENABLED,
                "threat_intelligence":
                    settings.THREAT_INTELLIGENCE_ENABLED
            },
            "monitoring": {
                "packet_capture":
                    settings.PACKET_CAPTURE_ENABLED,
                "interface":
                    settings.NETWORK_INTERFACE
            }
        })

    # ---------------------------------------------------------
    # API 404 HANDLER
    # ---------------------------------------------------------

    @app.errorhandler(404)
    def not_found(error):

        return jsonify({
            "error": "Endpoint not found",
            "status": 404
        }), 404

    # ---------------------------------------------------------
    # API ERROR HANDLER
    # ---------------------------------------------------------

    @app.errorhandler(500)
    def internal_error(error):

        logger.error(
            f"APPLICATION_ERROR | error={error}"
        )

        return jsonify({
            "error": "Internal server error",
            "status": 500
        }), 500

    logger.info(
        "CYBER_SENTINEL_X | Flask application initialized"
    )

    return app


app = create_app()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - SOC SERVER")
    print("=" * 60)

    print(
        f"Application : {settings.APP_NAME}"
    )

    print(
        f"Version     : {settings.APP_VERSION}"
    )

    print(
        f"Environment  : {settings.ENVIRONMENT}"
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
        f"Health API  : "
        f"http://127.0.0.1:{settings.PORT}/api/health"
    )

    print("=" * 60)

    app.run(
        host=settings.HOST,
        port=settings.PORT,
        debug=settings.DEBUG
    )
