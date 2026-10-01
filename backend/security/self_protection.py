from datetime import datetime, timezone
from collections import defaultdict, deque
import re
import threading
import time


class SelfProtectionEngine:
    """
    Cyber Sentinel X application self-protection engine.

    Monitors incoming application requests and identifies
    common suspicious request patterns without executing
    the supplied payload.
    """

    def __init__(self):
        self.request_history = defaultdict(deque)
        self.blocked_ips = set()
        self.lock = threading.Lock()

        self.window_seconds = 60
        self.rate_limit = 120

        self.rules = {
            "SQL_INJECTION": [
                r"\bunion\s+select\b",
                r"\bselect\s+.+\s+from\b",
                r"\bor\s+1\s*=\s*1\b",
                r"\band\s+1\s*=\s*1\b",
                r"'\s*or\s*'",
                r"--\s*$",
            ],
            "XSS": [
                r"<\s*script\b",
                r"javascript\s*:",
                r"onerror\s*=",
                r"onload\s*=",
                r"<\s*iframe\b",
            ],
            "PATH_TRAVERSAL": [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e/",
            ],
            "COMMAND_INJECTION": [
                r";\s*(whoami|id|uname|cat|curl|wget)\b",
                r"\|\s*(whoami|id|uname|cat|curl|wget)\b",
                r"\$\([^)]*\)",
                r"`[^`]+`",
            ],
        }

    def _utc_now(self):
        return datetime.now(timezone.utc).isoformat()

    def _normalize(self, value):
        if value is None:
            return ""

        return str(value).lower()

    def _detect_patterns(self, request_data):
        """
        Inspect request metadata and input values.
        Payloads are never executed.
        """

        combined = " ".join([
            self._normalize(request_data.get("path")),
            self._normalize(request_data.get("query")),
            self._normalize(request_data.get("body")),
            self._normalize(request_data.get("user_agent")),
        ])

        findings = []

        for category, patterns in self.rules.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, combined, re.IGNORECASE):
                        findings.append({
                            "category": category,
                            "pattern": pattern,
                        })
                        break
                except re.error:
                    continue

        return findings

    def _rate_check(self, source_ip):
        now = time.time()

        with self.lock:
            history = self.request_history[source_ip]

            while history and now - history[0] > self.window_seconds:
                history.popleft()

            history.append(now)

            count = len(history)

        return count

    def inspect_request(self, request_data):
        """
        Inspect one incoming application request.

        Returns:
            security decision + risk + findings.
        """

        source_ip = (
            request_data.get("source_ip")
            or request_data.get("ip")
            or "UNKNOWN"
        )

        method = (
            request_data.get("method")
            or "GET"
        )

        path = (
            request_data.get("path")
            or "/"
        )

        findings = self._detect_patterns(request_data)
        request_count = self._rate_check(source_ip)

        risk_score = 0
        severity = "NORMAL"

        if findings:
            categories = {
                item["category"]
                for item in findings
            }

            if "SQL_INJECTION" in categories:
                risk_score += 40

            if "XSS" in categories:
                risk_score += 30

            if "PATH_TRAVERSAL" in categories:
                risk_score += 40

            if "COMMAND_INJECTION" in categories:
                risk_score += 50

        if request_count >= self.rate_limit:
            risk_score += 30
            findings.append({
                "category": "RATE_ANOMALY",
                "pattern": "request_rate_threshold"
            })

        risk_score = min(risk_score, 100)

        if risk_score >= 80:
            severity = "CRITICAL"
        elif risk_score >= 60:
            severity = "HIGH"
        elif risk_score >= 40:
            severity = "SUSPICIOUS"
        elif risk_score >= 20:
            severity = "MEDIUM"

        blocked = source_ip in self.blocked_ips

        if severity == "CRITICAL":
            with self.lock:
                self.blocked_ips.add(source_ip)
            blocked = True

        return {
            "timestamp": self._utc_now(),
            "source_ip": source_ip,
            "method": method,
            "path": path,
            "request_count_60s": request_count,
            "findings": findings,
            "risk_score": risk_score,
            "severity": severity,
            "blocked": blocked,
            "action": "BLOCK" if blocked else "ALLOW",
        }

    def is_blocked(self, source_ip):
        with self.lock:
            return source_ip in self.blocked_ips

    def unblock(self, source_ip):
        with self.lock:
            self.blocked_ips.discard(source_ip)

    def get_statistics(self):
        with self.lock:
            return {
                "tracked_sources": len(self.request_history),
                "blocked_sources": len(self.blocked_ips),
                "blocked_ips": list(self.blocked_ips),
                "window_seconds": self.window_seconds,
                "rate_limit": self.rate_limit,
            }


self_protection = SelfProtectionEngine()
