import ipaddress
import re


class InputValidator:
    """Defensive validation for Cyber Sentinel X application inputs."""

    MAX_PATH_LENGTH = 2048
    MAX_QUERY_LENGTH = 4096
    MAX_BODY_LENGTH = 65536
    MAX_USER_AGENT_LENGTH = 1024

    SAFE_METHODS = {
        "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
    }

    def validate_ip(self, value):
        if not value:
            return False

        try:
            ipaddress.ip_address(str(value))
            return True
        except ValueError:
            return False

    def validate_method(self, method):
        return str(method or "").upper() in self.SAFE_METHODS

    def validate_text_length(self, value, maximum):
        if value is None:
            return True
        return len(str(value)) <= maximum

    def validate_request(self, request_data):
        errors = []

        method = request_data.get("method", "GET")
        source_ip = request_data.get("source_ip")
        path = request_data.get("path", "")
        query = request_data.get("query", "")
        body = request_data.get("body", "")
        user_agent = request_data.get("user_agent", "")

        if not self.validate_method(method):
            errors.append("INVALID_METHOD")

        if source_ip and not self.validate_ip(source_ip):
            errors.append("INVALID_SOURCE_IP")

        if not self.validate_text_length(
            path, self.MAX_PATH_LENGTH
        ):
            errors.append("PATH_TOO_LARGE")

        if not self.validate_text_length(
            query, self.MAX_QUERY_LENGTH
        ):
            errors.append("QUERY_TOO_LARGE")

        if not self.validate_text_length(
            body, self.MAX_BODY_LENGTH
        ):
            errors.append("BODY_TOO_LARGE")

        if not self.validate_text_length(
            user_agent, self.MAX_USER_AGENT_LENGTH
        ):
            errors.append("USER_AGENT_TOO_LARGE")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
        }


input_validator = InputValidator()
