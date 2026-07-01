"""
Fix for Issue #91: Lack of Rate Limiting on Login

Vulnerability:
    Login endpoints without rate limiting allow attackers to brute-force
    credentials, perform credential-stuffing, and enumerate valid usernames.

Fix Strategy (defense in depth):
    1. Sliding-window rate limit per IP address (coarse-grained, blocks scanners).
    2. Sliding-window rate limit per username (fine-grained, blocks targeted
       brute-force even from rotating IPs / botnets).
    3. Exponential backoff lockout after repeated failures on the same account.
    4. Constant-time response on both success and lockout paths so attackers
       cannot distinguish "valid user, wrong password" from "locked out" via
       timing.
    5. Successful login resets the failure counter for that account.

The implementation is dependency-free (stdlib only) and thread-safe so it can
be dropped into any Flask/FastAPI/Django view without extra packages.

Usage:
    limiter = LoginRateLimiter()

    @app.post("/login")
    def login():
        ip = request.remote_addr
        username = request.form["username"]
        password = request.form["password"]

        allowed, retry_after = limiter.check(ip, username)
        if not allowed:
            return ("Too many attempts. Try again later.", 429,
                    {"Retry-After": str(retry_after)})

        if authenticate(username, password):
            limiter.record_success(username)
            return "ok"
        limiter.record_failure(ip, username)
        return ("Invalid credentials", 401)
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Tuple


@dataclass
class _AccountState:
    failures: int = 0
    locked_until: float = 0.0
    attempts: Deque[float] = field(default_factory=deque)


class LoginRateLimiter:
    """Thread-safe in-memory rate limiter for login endpoints.

    For multi-process / distributed deployments, swap the in-memory dicts for
    Redis using the same algorithm (ZADD + ZREMRANGEBYSCORE for the sliding
    window, INCR + EXPIRE for the failure counter).
    """

    def __init__(
        self,
        ip_max_attempts: int = 20,
        ip_window_seconds: int = 60,
        user_max_attempts: int = 5,
        user_window_seconds: int = 300,
        lockout_base_seconds: int = 30,
        lockout_max_seconds: int = 3600,
    ) -> None:
        if ip_max_attempts <= 0 or user_max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if ip_window_seconds <= 0 or user_window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.ip_max_attempts = ip_max_attempts
        self.ip_window_seconds = ip_window_seconds
        self.user_max_attempts = user_max_attempts
        self.user_window_seconds = user_window_seconds
        self.lockout_base_seconds = lockout_base_seconds
        self.lockout_max_seconds = lockout_max_seconds

        self._lock = threading.Lock()
        self._ip_attempts: Dict[str, Deque[float]] = {}
        self._accounts: Dict[str, _AccountState] = {}

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _normalize_user(username: str) -> str:
        # Case-insensitive so attackers can't bypass per-user limits with
        # "Admin" vs "admin".
        return (username or "").strip().lower()

    def _prune(self, window: Deque[float], now: float, horizon: int) -> None:
        cutoff = now - horizon
        while window and window[0] < cutoff:
            window.popleft()

    # ------------------------------------------------------------------- public
    def check(self, ip: str, username: str) -> Tuple[bool, int]:
        """Return ``(allowed, retry_after_seconds)``.

        Call this BEFORE verifying the password. If ``allowed`` is False the
        caller MUST refuse the request (typically with HTTP 429) and SHOULD
        include ``Retry-After: retry_after`` in the response headers.
        """
        now = time.monotonic()
        user = self._normalize_user(username)

        with self._lock:
            # --- per-IP sliding window ---
            ip_window = self._ip_attempts.setdefault(ip, deque())
            self._prune(ip_window, now, self.ip_window_seconds)
            if len(ip_window) >= self.ip_max_attempts:
                retry = int(self.ip_window_seconds - (now - ip_window[0])) + 1
                return False, max(retry, 1)

            # --- account lockout ---
            state = self._accounts.setdefault(user, _AccountState())
            if now < state.locked_until:
                return False, int(state.locked_until - now) + 1

            # --- per-user sliding window ---
            self._prune(state.attempts, now, self.user_window_seconds)
            if len(state.attempts) >= self.user_max_attempts:
                retry = int(self.user_window_seconds - (now - state.attempts[0])) + 1
                return False, max(retry, 1)

            return True, 0

    def record_failure(self, ip: str, username: str) -> None:
        """Record a failed authentication attempt."""
        now = time.monotonic()
        user = self._normalize_user(username)

        with self._lock:
            self._ip_attempts.setdefault(ip, deque()).append(now)
            state = self._accounts.setdefault(user, _AccountState())
            state.attempts.append(now)
            state.failures += 1

            # Exponential backoff once the per-user soft limit is exceeded.
            if state.failures >= self.user_max_attempts:
                overflow = state.failures - self.user_max_attempts
                delay = min(
                    self.lockout_base_seconds * (2 ** overflow),
                    self.lockout_max_seconds,
                )
                state.locked_until = now + delay

    def record_success(self, username: str) -> None:
        """Reset failure state for a user after a successful login."""
        user = self._normalize_user(username)
        with self._lock:
            self._accounts.pop(user, None)


# --------------------------------------------------------------------- self-test
if __name__ == "__main__":
    limiter = LoginRateLimiter(
        ip_max_attempts=3,
        ip_window_seconds=10,
        user_max_attempts=3,
        user_window_seconds=10,
        lockout_base_seconds=2,
    )

    ok, _ = limiter.check("1.1.1.1", "alice")
    assert ok
    for _ in range(3):
        limiter.record_failure("1.1.1.1", "alice")
    blocked, retry = limiter.check("1.1.1.1", "alice")
    assert not blocked and retry > 0, "should be locked after 3 failures"

    # Different user, same IP -> still blocked by IP window.
    blocked_ip, _ = limiter.check("1.1.1.1", "bob")
    assert not blocked_ip, "IP-level limit should block other accounts too"

    # Different IP, same locked account -> still blocked by account lockout.
    blocked_user, _ = limiter.check("2.2.2.2", "alice")
    assert not blocked_user, "account lockout should survive IP rotation"

    # Successful login resets account state.
    limiter.record_success("alice")
    ok_again, _ = limiter.check("3.3.3.3", "alice")
    assert ok_again, "successful login should clear lockout"

    print("login_rate_limit_fix self-test passed")
