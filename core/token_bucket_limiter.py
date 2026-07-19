"""
token_bucket_limiter.py
WhisperWard OSINT — Rate Limiting Module
Pixora Inc. | Phase 4 Milestone 1
"""

import random
import time
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from threading import Lock
from typing import Callable, Optional

import pybreaker
import structlog
from requests.exceptions import HTTPError

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────
# Platform configuration
# ─────────────────────────────────────────────
@dataclass
class PlatformConfig:
    requests_per_window: int = 10
    window_seconds: int = 60
    backoff_base: float = 1.0
    backoff_max: float = 60.0
    circuit_fail_threshold: int = 5
    circuit_recovery_timeout: int = 30


PLATFORM_CONFIGS = {
    "roblox": PlatformConfig(backoff_max=30.0),
    "discord": PlatformConfig(backoff_max=30.0),
    "sherlock": PlatformConfig(backoff_base=2.0, backoff_max=60.0, circuit_fail_threshold=3, circuit_recovery_timeout=60),
    "default": PlatformConfig(),
}


# ─────────────────────────────────────────────
# Token bucket
# ─────────────────────────────────────────────
class TokenBucket:
    def __init__(self, config: PlatformConfig):
        self.config = config
        self.tokens = float(config.requests_per_window)
        self.max_tokens = float(config.requests_per_window)
        self.refill_rate = config.requests_per_window / config.window_seconds
        self.last_refill = time.monotonic()
        self._lock = Lock()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        new_tokens = elapsed * self.refill_rate
        self.tokens = min(self.max_tokens, self.tokens + new_tokens)
        self.last_refill = now

    def acquire(self, timeout: float = 120.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                self._refill()
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
            wait_time = 1.0 / self.refill_rate
            time.sleep(min(wait_time, deadline - time.monotonic()))
        return False

    @property
    def available_tokens(self) -> float:
        with self._lock:
            self._refill()
            return self.tokens


# ─────────────────────────────────────────────
# Backoff
# ─────────────────────────────────────────────
def exponential_backoff(attempt: int, base: float = 1.0, max_wait: float = 60.0, jitter: bool = True) -> float:
    wait = min(base * (2 ** attempt), max_wait)
    if jitter:
        wait = wait * (0.5 + random.random() * 0.5)
    return wait


def retry_on_rate_limit(max_retries: int = 3, platform: str = "default"):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            config = PLATFORM_CONFIGS.get(platform, PLATFORM_CONFIGS["default"])
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except HTTPError as e:
                    if getattr(e.response, 'status_code', None) == 429 and attempt < max_retries:
                        wait_time = exponential_backoff(attempt, base=config.backoff_base, max_wait=config.backoff_max)
                        logger.warning("rate_limit_hit", platform=platform, attempt=attempt+1, wait_seconds=round(wait_time, 2))
                        time.sleep(wait_time)
                        continue
                    raise
                except Exception:
                    raise
            return None
        return wrapper
    return decorator


# ─────────────────────────────────────────────
# Rate Limiter (simplified circuit breaker)
# ─────────────────────────────────────────────
class RateLimiter:
    def __init__(self, configs: Optional[dict] = None):
        self._configs = configs or PLATFORM_CONFIGS
        self._buckets: dict[str, TokenBucket] = {}
        self._breakers: dict[str, pybreaker.CircuitBreaker] = {}
        self._lock = Lock()

    def _get_bucket(self, platform: str) -> TokenBucket:
        if platform not in self._buckets:
            with self._lock:
                if platform not in self._buckets:
                    config = self._configs.get(platform, self._configs["default"])
                    self._buckets[platform] = TokenBucket(config)
        return self._buckets[platform]

    def _get_breaker(self, platform: str) -> pybreaker.CircuitBreaker:
        if platform not in self._breakers:
            with self._lock:
                if platform not in self._breakers:
                    config = self._configs.get(platform, self._configs["default"])
                    self._breakers[platform] = pybreaker.CircuitBreaker(
                        fail_max=config.circuit_fail_threshold,
                        reset_timeout=config.circuit_recovery_timeout,
                        name=f"whisperward_{platform}",
                    )
        return self._breakers[platform]

    @contextmanager
    def acquire(self, platform: str, timeout: float = 120.0):
        bucket = self._get_bucket(platform)
        breaker = self._get_breaker(platform)

        if breaker.current_state == "open":
            logger.error("circuit_breaker_open", platform=platform)
            raise pybreaker.CircuitBreakerError(f"Circuit breaker open for {platform}")

        acquired = bucket.acquire(timeout=timeout)
        if not acquired:
            raise TimeoutError(f"Rate limit token timeout for {platform}")

        try:
            yield
            # pybreaker tracks success/failure via decorator or .call()
            # For manual context we just let it run (failures are caught by exceptions)
        except Exception as e:
            logger.warning("platform_request_failed", platform=platform, error=str(e))
            raise

    def limit(self, platform: str, timeout: float = 120.0):
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                with self.acquire(platform, timeout=timeout):
                    return func(*args, **kwargs)
            return wrapper
        return decorator

    def get_status(self) -> dict:
        status = {}
        for platform in list(self._buckets.keys()):
            bucket = self._buckets[platform]
            breaker = self._breakers.get(platform)
            status[platform] = {
                "available_tokens": round(bucket.available_tokens, 2),
                "max_tokens": bucket.max_tokens,
                "circuit_state": breaker.current_state if breaker else "no_breaker",
                "circuit_fail_count": getattr(breaker, 'fail_counter', 0),
            }
        return status


# Global instance
rate_limiter = RateLimiter()