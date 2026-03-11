import redis.asyncio as aioredis
from app.core.config import settings

_redis_client = None


async def get_redis():
    global _redis_client
    if _redis_client is None:
        _redis_client = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis_client


async def blacklist_token(token: str, expires_in_seconds: int):
    client = await get_redis()
    await client.setex(f"blacklist:{token}", expires_in_seconds, "1")


async def is_token_blacklisted(token: str) -> bool:
    client = await get_redis()
    result = await client.get(f"blacklist:{token}")
    return result is not None


async def log_failed_attempt(identifier: str):
    """Log a failed login attempt for audit trail."""
    client = await get_redis()
    key = f"failed_attempts:{identifier}"
    await client.incr(key)
    await client.expire(key, 3600)  # reset count after 1 hour


async def get_failed_attempts(identifier: str) -> int:
    client = await get_redis()
    result = await client.get(f"failed_attempts:{identifier}")
    return int(result) if result else 0