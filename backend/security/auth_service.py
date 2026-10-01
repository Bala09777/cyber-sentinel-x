from datetime import datetime, timedelta, timezone
from functools import wraps
import secrets
import threading

from flask import jsonify, session, request
from werkzeug.security import generate_password_hash, check_password_hash

from backend.database.manager import db
from backend.core.logger import logger
from backend.core.audit import audit


class AuthenticationService:

    ROLES = {
        "ADMIN",
        "SOC_ANALYST",
        "INVESTIGATOR",
        "VIEWER",
    }

    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15
    SESSION_HOURS = 8

    def __init__(self):
        self.lock = threading.Lock()
        self.failed_attempts = {}
        self.locked_until = {}

    # ---------------------------------------------------------
    # DATABASE
    # ---------------------------------------------------------

    def initialize(self):

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'VIEWER',
                active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login TEXT,
                last_failed_login TEXT
            )
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                source_ip TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER DEFAULT 0
            )
            """
        )

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_auth_sessions_token
            ON auth_sessions(session_token)
            """
        )

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
            ON auth_sessions(user_id)
            """
        )

        logger.info("AUTH_DATABASE_INITIALIZED")

    # ---------------------------------------------------------
    # HELPERS
    # ---------------------------------------------------------

    def _now(self):
        return datetime.now(timezone.utc)

    def _timestamp(self):
        return self._now().isoformat()

    def _generate_user_id(self):
        return (
            "USR-"
            + self._now().strftime("%Y%m%d%H%M%S")
            + "-"
            + secrets.token_hex(4).upper()
        )

    def _generate_session_token(self):
        return secrets.token_urlsafe(48)

    # ---------------------------------------------------------
    # USER MANAGEMENT
    # ---------------------------------------------------------

    def create_user(
        self,
        username,
        password,
        role="VIEWER",
    ):

        if not username:
            raise ValueError("Username is required")

        if not password or len(password) < 10:
            raise ValueError(
                "Password must contain at least 10 characters"
            )

        username = str(username).strip()
        role = str(role).upper()

        if role not in self.ROLES:
            raise ValueError(
                f"Invalid role: {role}"
            )

        existing = db.fetch_one(
            """
            SELECT *
            FROM auth_users
            WHERE username = ?
            """,
            (username,)
        )

        if existing:
            raise ValueError(
                "Username already exists"
            )

        user_id = self._generate_user_id()

        password_hash = generate_password_hash(
            password,
            method="scrypt"
        )

        db.insert(
            "auth_users",
            {
                "user_id": user_id,
                "username": username,
                "password_hash": password_hash,
                "role": role,
                "active": 1,
                "created_at": self._timestamp(),
                "last_login": None,
                "last_failed_login": None,
            }
        )

        audit.record(
            action="USER_CREATED",
            username=username,
            resource="auth_users",
            resource_id=user_id,
            source_ip=request.remote_addr,
            details={
                "role": role
            }
        )

        logger.info(
            f"AUTH_USER_CREATED | "
            f"user={username} | role={role}"
        )

        return {
            "user_id": user_id,
            "username": username,
            "role": role,
        }

    def get_user(self, username):

        return db.fetch_one(
            """
            SELECT
                id,
                user_id,
                username,
                role,
                active,
                created_at,
                last_login,
                last_failed_login
            FROM auth_users
            WHERE username = ?
            """,
            (username,)
        )

    def get_all_users(self):

        return db.fetch_all(
            """
            SELECT
                id,
                user_id,
                username,
                role,
                active,
                created_at,
                last_login,
                last_failed_login
            FROM auth_users
            ORDER BY id DESC
            """
        )

    # ---------------------------------------------------------
    # ACCOUNT LOCKOUT
    # ---------------------------------------------------------

    def _is_locked(self, username):

        with self.lock:

            locked_until = self.locked_until.get(username)

            if not locked_until:
                return False

            if self._now() >= locked_until:

                self.locked_until.pop(
                    username,
                    None
                )

                self.failed_attempts.pop(
                    username,
                    None
                )

                return False

            return True

    def _record_failed_login(self, username):

        with self.lock:

            count = (
                self.failed_attempts.get(
                    username,
                    0
                ) + 1
            )

            self.failed_attempts[username] = count

            if count >= self.MAX_FAILED_ATTEMPTS:

                self.locked_until[username] = (
                    self._now()
                    + timedelta(
                        minutes=self.LOCKOUT_MINUTES
                    )
                )

                logger.warning(
                    f"AUTH_ACCOUNT_LOCKED | "
                    f"user={username}"
                )

            return count

    def _reset_failed_login(self, username):

        with self.lock:

            self.failed_attempts.pop(
                username,
                None
            )

            self.locked_until.pop(
                username,
                None
            )

    # ---------------------------------------------------------
    # LOGIN
    # ---------------------------------------------------------

    def login(self, username, password):

        username = str(
            username or ""
        ).strip()

        if self._is_locked(username):

            audit.record(
                action="LOGIN_BLOCKED_LOCKED_ACCOUNT",
                username=username,
                source_ip=request.remote_addr,
            )

            return {
                "success": False,
                "error": "ACCOUNT_LOCKED"
            }

        user = db.fetch_one(
            """
            SELECT *
            FROM auth_users
            WHERE username = ?
            """,
            (username,)
        )

        if not user:

            audit.record(
                action="LOGIN_FAILURE",
                username=username,
                source_ip=request.remote_addr,
                details={
                    "reason": "USER_NOT_FOUND"
                }
            )

            return {
                "success": False,
                "error": "INVALID_CREDENTIALS"
            }

        user = dict(user)

        if not user["active"]:

            return {
                "success": False,
                "error": "ACCOUNT_DISABLED"
            }

        valid_password = check_password_hash(
            user["password_hash"],
            password or ""
        )

        if not valid_password:

            attempts = self._record_failed_login(
                username
            )

            db.update(
                "auth_users",
                {
                    "last_failed_login":
                        self._timestamp()
                },
                "user_id = ?",
                (user["user_id"],)
            )

            audit.record(
                action="LOGIN_FAILURE",
                username=username,
                source_ip=request.remote_addr,
                details={
                    "attempts": attempts
                }
            )

            return {
                "success": False,
                "error": "INVALID_CREDENTIALS"
            }

        self._reset_failed_login(username)

        token = self._generate_session_token()

        now = self._now()

        expires = (
            now
            + timedelta(
                hours=self.SESSION_HOURS
            )
        )

        db.insert(
            "auth_sessions",
            {
                "session_token": token,
                "user_id": user["user_id"],
                "username": user["username"],
                "role": user["role"],
                "source_ip": request.remote_addr,
                "created_at": now.isoformat(),
                "expires_at": expires.isoformat(),
                "revoked": 0,
            }
        )

        db.update(
            "auth_users",
            {
                "last_login":
                    now.isoformat()
            },
            "user_id = ?",
            (user["user_id"],)
        )

        session.clear()

        session["authenticated"] = True
        session["session_token"] = token
        session["user_id"] = user["user_id"]
        session["username"] = user["username"]
        session["role"] = user["role"]

        audit.record(
            action="LOGIN_SUCCESS",
            username=username,
            source_ip=request.remote_addr,
            details={
                "role": user["role"]
            }
        )

        logger.info(
            f"AUTH_LOGIN_SUCCESS | "
            f"user={username} | "
            f"role={user['role']}"
        )

        return {
            "success": True,
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "expires_at": expires.isoformat(),
        }

    # ---------------------------------------------------------
    # SESSION
    # ---------------------------------------------------------

    def current_user(self):

        token = session.get(
            "session_token"
        )

        if not token:
            return None

        row = db.fetch_one(
            """
            SELECT *
            FROM auth_sessions
            WHERE session_token = ?
              AND revoked = 0
            """,
            (token,)
        )

        if not row:
            return None

        row = dict(row)

        try:

            expires = datetime.fromisoformat(
                row["expires_at"]
            )

        except Exception:

            return None

        if self._now() >= expires:

            self.logout()
            return None

        return row

    def logout(self):

        token = session.get(
            "session_token"
        )

        if token:

            db.update(
                "auth_sessions",
                {
                    "revoked": 1
                },
                "session_token = ?",
                (token,)
            )

        username = session.get(
            "username"
        )

        if username:

            audit.record(
                action="LOGOUT",
                username=username,
                source_ip=request.remote_addr,
            )

        session.clear()

        return {
            "success": True
        }

    # ---------------------------------------------------------
    # AUTHORIZATION
    # ---------------------------------------------------------

    def is_authenticated(self):

        return (
            self.current_user()
            is not None
        )

    def has_role(self, required_roles):

        user = self.current_user()

        if not user:
            return False

        if isinstance(
            required_roles,
            str
        ):
            required_roles = {
                required_roles
            }

        return user["role"] in {
            str(role).upper()
            for role in required_roles
        }

    # ---------------------------------------------------------
    # LOGIN REQUIRED
    # ---------------------------------------------------------

    def login_required(self, function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            user = self.current_user()

            if not user:

                return jsonify({
                    "error":
                        "Authentication required"
                }), 401

            return function(
                *args,
                **kwargs
            )

        return wrapper

    # ---------------------------------------------------------
    # ROLE REQUIRED
    # ---------------------------------------------------------

    def role_required(self, *roles):

        required = {
            str(role).upper()
            for role in roles
        }

        def decorator(function):

            @wraps(function)
            def wrapper(
                *args,
                **kwargs
            ):

                user = self.current_user()

                if not user:

                    return jsonify({
                        "error":
                            "Authentication required"
                    }), 401

                if user["role"] not in required:

                    audit.record(
                        action="RBAC_DENIED",
                        username=user["username"],
                        source_ip=request.remote_addr,
                        details={
                            "required_roles":
                                list(required),
                            "actual_role":
                                user["role"],
                            "path":
                                request.path,
                        }
                    )

                    return jsonify({
                        "error":
                            "Insufficient privileges"
                    }), 403

                return function(
                    *args,
                    **kwargs
                )

            return wrapper

        return decorator

    # ---------------------------------------------------------
    # STATISTICS
    # ---------------------------------------------------------

    def statistics(self):

        active_sessions = db.fetch_one(
            """
            SELECT COUNT(*) AS count
            FROM auth_sessions
            WHERE revoked = 0
            """
        )

        users = db.fetch_one(
            """
            SELECT COUNT(*) AS count
            FROM auth_users
            """
        )

        return {
            "users": (
                dict(users)["count"]
                if users
                else 0
            ),
            "active_sessions": (
                dict(active_sessions)["count"]
                if active_sessions
                else 0
            ),
            "roles": sorted(
                self.ROLES
            ),
        }


auth_service = AuthenticationService()
