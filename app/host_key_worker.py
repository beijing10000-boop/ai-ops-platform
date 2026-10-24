"""Separate RQ worker so large key-discovery batches do not block AI diagnostics."""

import logging

from redis import Redis
from rq import Queue, Worker

from .main import REDIS_URL

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    redis = Redis.from_url(REDIS_URL)
    Worker([Queue("ai-host-keys", connection=redis)], connection=redis).work()
