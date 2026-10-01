from flask import Blueprint, jsonify, request

from backend.security.auth_service import auth_service
from backend.core.logger import logger


auth_api = Blueprint(
    "auth_api",
    __name__,
    url_prefix="/api/auth"
)


# ---------------------------------------------------------
# INITIALIZE AUTH DATABASE
# ---------------------------------------------------------

auth_service.initialize()


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@auth_api.route("/login", methods=["POST"])
def login():

    try:
        data = request.get_json(
            silent=True
        ) or {}

        username = data.get(
            "username",
            ""
        )

        password = data.get(
            "password",
            ""
        )

        if not username or not password:

            return jsonify({
                "success": False,
                "error": "Username and password are required"
            }), 400

        result = auth_service.login(
            username,
            password
        )

        if not result.get("success"):

            return jsonify(result), 401

        return jsonify(result), 200

    except Exception as exc:

        logger.exception(
            f"AUTH_LOGIN_API_ERROR | {exc}"
        )

        return jsonify({
            "success": False,
            "error": "Authentication service unavailable"
        }), 500


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@auth_api.route("/logout", methods=["POST"])
def logout():

    try:

        result = auth_service.logout()

        return jsonify(result), 200

    except Exception as exc:

        logger.exception(
            f"AUTH_LOGOUT_API_ERROR | {exc}"
        )

        return jsonify({
            "success": False,
            "error": "Logout failed"
        }), 500


# ---------------------------------------------------------
# CURRENT USER
# ---------------------------------------------------------

@auth_api.route("/me", methods=["GET"])
def current_user():

    try:

        user = auth_service.current_user()

        if not user:

            return jsonify({
                "authenticated": False
            }), 401

        return jsonify({
            "authenticated": True,
            "user": {
                "user_id":
                    user["user_id"],
                "username":
                    user["username"],
                "role":
                    user["role"],
                "expires_at":
                    user["expires_at"],
            }
        }), 200

    except Exception as exc:

        logger.exception(
            f"AUTH_ME_API_ERROR | {exc}"
        )

        return jsonify({
            "authenticated": False,
            "error": "Authentication status unavailable"
        }), 500


# ---------------------------------------------------------
# AUTHENTICATION STATUS
# ---------------------------------------------------------

@auth_api.route("/status", methods=["GET"])
def auth_status():

    try:

        user = auth_service.current_user()

        statistics = (
            auth_service.statistics()
        )

        return jsonify({
            "authenticated":
                user is not None,
            "user":
                {
                    "user_id":
                        user["user_id"],
                    "username":
                        user["username"],
                    "role":
                        user["role"],
                }
                if user
                else None,
            "statistics":
                statistics,
        }), 200

    except Exception as exc:

        logger.exception(
            f"AUTH_STATUS_API_ERROR | {exc}"
        )

        return jsonify({
            "error":
                "Authentication status unavailable"
        }), 500


# ---------------------------------------------------------
# ADMIN: CREATE USER
# ---------------------------------------------------------

@auth_api.route("/users", methods=["POST"])
def create_user():

    try:

        current = auth_service.current_user()

        if not current:

            return jsonify({
                "error":
                    "Authentication required"
            }), 401

        if current["role"] != "ADMIN":

            return jsonify({
                "error":
                    "Admin privileges required"
            }), 403

        data = request.get_json(
            silent=True
        ) or {}

        username = data.get(
            "username",
            ""
        )

        password = data.get(
            "password",
            ""
        )

        role = data.get(
            "role",
            "VIEWER"
        )

        user = auth_service.create_user(
            username=username,
            password=password,
            role=role
        )

        return jsonify({
            "success": True,
            "user": user
        }), 201

    except ValueError as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 400

    except Exception as exc:

        logger.exception(
            f"AUTH_CREATE_USER_API_ERROR | {exc}"
        )

        return jsonify({
            "success": False,
            "error": "Unable to create user"
        }), 500


# ---------------------------------------------------------
# ADMIN: LIST USERS
# ---------------------------------------------------------

@auth_api.route("/users", methods=["GET"])
def list_users():

    try:

        current = auth_service.current_user()

        if not current:

            return jsonify({
                "error":
                    "Authentication required"
            }), 401

        if current["role"] != "ADMIN":

            return jsonify({
                "error":
                    "Admin privileges required"
            }), 403

        users = auth_service.get_all_users()

        return jsonify({
            "users": [
                dict(user)
                for user in users
            ]
        }), 200

    except Exception as exc:

        logger.exception(
            f"AUTH_LIST_USERS_API_ERROR | {exc}"
        )

        return jsonify({
            "error":
                "Unable to retrieve users"
        }), 500

