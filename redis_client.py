import redis
from redis.client import Redis
from config import REDIS_URL

# Initialize Redis client
redis_client: Redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)
