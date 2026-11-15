from flask import Blueprint, jsonify, request

from backend.incidents.incident_service import incident_service
from backend.security.auth_service import auth_service

incident_api = Blueprint("incident_api", __name__, url_prefix="/api/incidents")


@incident_api.get("")
@auth_service.login_required
def list_incidents():
    return jsonify([
        dict(row)
        for row in incident_service.get_all()
    ])


@incident_api.get("/open")
@auth_service.login_required
def open_incidents():
    return jsonify([
        dict(row)
        for row in incident_service.get_open()
    ])


@incident_api.get("/<incident_id>")
@auth_service.login_required
def get_incident(incident_id):
    incident = incident_service.get_incident(incident_id)

    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    return jsonify(dict(incident))


@incident_api.get("/<incident_id>/timeline")
@auth_service.login_required
def timeline(incident_id):
    return jsonify([
        dict(row)
        for row in incident_service.get_timeline(incident_id)
    ])


@incident_api.get("/<incident_id>/analysis")
@auth_service.login_required
def analysis(incident_id):
    result = incident_service.get_analysis(incident_id)

    if not result:
        return jsonify({"error": "Incident not found"}), 404

    return jsonify(result)


@incident_api.patch("/<incident_id>/status")
@auth_service.role_required("ADMIN", "SOC_ANALYST", "INVESTIGATOR")
def update_status(incident_id):
    data = request.get_json(silent=True) or {}

    status = data.get("status")
    user = auth_service.current_user()["username"]

    if not status:
        return jsonify({"error": "status is required"}), 400

    try:
        updated = incident_service.update_status(
            incident_id,
            status,
            user
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if not updated:
        return jsonify({"error": "Incident not found"}), 404

    return jsonify({
        "status": "updated",
        "incident_id": incident_id,
        "new_status": status.upper()
    })


@incident_api.patch("/<incident_id>/assign")
@auth_service.role_required("ADMIN", "SOC_ANALYST")
def assign_incident(incident_id):
    data = request.get_json(silent=True) or {}

    analyst = data.get("analyst")

    if not analyst:
        return jsonify({"error": "analyst is required"}), 400

    updated = incident_service.assign(
        incident_id,
        analyst,
        actor=auth_service.current_user()["username"]
    )

    if not updated:
        return jsonify({"error": "Incident not found"}), 404

    return jsonify({
        "status": "assigned",
        "incident_id": incident_id,
        "assigned_to": analyst
    })


@incident_api.get("/stats/summary")
@auth_service.login_required
def incident_stats():
    return jsonify(
        incident_service.get_statistics()
    )
