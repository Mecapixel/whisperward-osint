# modules/rate_limiter.py
import asyncio
import time

class RateLimiter:
    def __init__(self, calls_per_minute: int = 20):
        self.calls_per_minute = calls_per_minute
        self.semaphore = asyncio.Semaphore(calls_per_minute)
        self.last_reset = time.time()

    async def __aenter__(self):
        await self.semaphore.acquire()
        if time.time() - self.last_reset > 60:
            self.semaphore = asyncio.Semaphore(self.calls_per_minute)
            self.last_reset = time.time()
        return self

    async def __aexit__(self, *args):
        self.semaphore.release()

    async def acquire(self):
        await self.semaphore.acquire()

    def release(self):
        self.semaphore.release()

api_limiter = RateLimiter(calls_per_minute=20)