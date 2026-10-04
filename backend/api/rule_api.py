from flask import Blueprint, jsonify, request

from backend.detection.rule_service import rule_service
from backend.security.auth_service import auth_service


rule_api = Blueprint(
    "rule_api",
    __name__,
    url_prefix="/api/soc/rules"
)


@rule_api.get("")
@auth_service.login_required
def list_rules():
    return jsonify([
        dict(rule)
        for rule in rule_service.get_all_rules()
    ])


@rule_api.get("/<rule_id>")
@auth_service.login_required
def get_rule(rule_id):
    rule = rule_service.get_rule(rule_id)

    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    return jsonify(dict(rule))


@rule_api.post("")
@auth_service.login_required
def create_rule():
    data = request.get_json(silent=True) or {}

    try:
        rule = rule_service.create_rule(
            name=data.get("name"),
            description=data.get("description", ""),
            category=data.get("category", "NETWORK_RISK"),
            threshold=data.get("threshold", 0),
            severity=data.get("severity", "MEDIUM"),
            enabled=data.get("enabled", 1)
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "status": "created",
        "rule": dict(rule)
    }), 201


@rule_api.put("/<rule_id>")
@auth_service.login_required
def update_rule(rule_id):
    data = request.get_json(silent=True) or {}

    try:
        rule = rule_service.update_rule(
            rule_id,
            name=data.get("name"),
            description=data.get("description"),
            category=data.get("category"),
            threshold=data.get("threshold"),
            severity=data.get("severity"),
            enabled=data.get("enabled")
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    return jsonify({
        "status": "updated",
        "rule": dict(rule)
    })


@rule_api.patch("/<rule_id>/enable")
@auth_service.login_required
def enable_rule(rule_id):
    rule = rule_service.enable_rule(rule_id)

    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    return jsonify({
        "status": "enabled",
        "rule": dict(rule)
    })


@rule_api.patch("/<rule_id>/disable")
@auth_service.login_required
def disable_rule(rule_id):
    rule = rule_service.disable_rule(rule_id)

    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    return jsonify({
        "status": "disabled",
        "rule": dict(rule)
    })


@rule_api.delete("/<rule_id>")
@auth_service.login_required
def delete_rule(rule_id):
    deleted = rule_service.delete_rule(rule_id)

    if not deleted:
        return jsonify({"error": "Rule not found"}), 404

    return jsonify({
        "status": "deleted",
        "rule_id": rule_id
    })


@rule_api.get("/stats/summary")
@auth_service.login_required
def rule_stats():
    rules = rule_service.get_all_rules()

    return jsonify({
        "total": len(rules),
        "enabled": sum(
            1 for rule in rules
            if int(rule["enabled"]) == 1
        ),
        "disabled": sum(
            1 for rule in rules
            if int(rule["enabled"]) == 0
        )
    })
