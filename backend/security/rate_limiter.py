from collections import defaultdict, deque
from datetime import datetime, timezone
import threading
import time


class RateLimiter:
    """
    Application-level request rate limiter.

    Tracks request timestamps per source IP.
    """

    def __init__(self, max_requests=120, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds

        self.requests = defaultdict(deque)
        self.lock = threading.Lock()

    def _cleanup(self, history, now):
        cutoff = now - self.window_seconds

        while history and history[0] <= cutoff:
            history.popleft()

    def check(self, source_ip):
        now = time.time()

        with self.lock:
            history = self.requests[source_ip]

            self._cleanup(history, now)

            if len(history) >= self.max_requests:
                retry_after = max(
                    1,
                    int(
                        self.window_seconds
                        - (now - history[0])
                    )
                )

                return {
                    "allowed": False,
                    "request_count": len(history),
                    "retry_after": retry_after,
                }

            history.append(now)

            return {
                "allowed": True,
                "request_count": len(history),
                "retry_after": 0,
            }

    def reset(self, source_ip):
        with self.lock:
            self.requests.pop(source_ip, None)

    def statistics(self):
        with self.lock:
            return {
                "tracked_sources": len(self.requests),
                "max_requests": self.max_requests,
                "window_seconds": self.window_seconds,
            }


rate_limiter = RateLimiter()
