from typing import Final
from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()


DATABASE_URL: Final = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set")

REDIS_URL: Final = os.getenv("REDIS_URL")

if not REDIS_URL:
    raise ValueError("DATABASE_URL environment variable is not set")


SECRET_KEY: Final = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is not set")

ALGORITHM: Final = os.getenv("ALGORITHM")

if not ALGORITHM:
    raise ValueError("ALGORITHM environment variable is not set")

ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")

if not ACCESS_TOKEN_EXPIRE_MINUTES:
    ACCESS_TOKEN_EXPIRE_MINUTES=15
