"""RQ Worker entry point for background scan jobs."""
import sys
import os

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from redis import Redis
from rq import Worker, Queue, Connection
from app.config import settings
from app.database import init_db

QUEUES = ["default"]


def main():
    """Start the RQ worker."""
    print("=" * 60)
    print("  OWASP TOP 10 ONLINE SCANNER — Worker")
    print("=" * 60)
    print(f"  Redis: {settings.REDIS_URL}")
    print(f"  Nuclei: {settings.NUCLEI_BIN}")
    print(f"  Templates: {settings.NUCLEI_TEMPLATES}")
    print(f"  Output dir: {settings.SCAN_OUTPUT_DIR}")
    print("=" * 60)

    # Initialize database tables
    init_db()

    # Connect to Redis
    redis_conn = Redis.from_url(settings.REDIS_URL)

    # Start worker
    with Connection(redis_conn):
        worker = Worker(list(map(Queue, QUEUES)))
        print(f"\n  Listening on queues: {', '.join(QUEUES)}")
        print("  Press Ctrl+C to stop.\n")
        worker.work(with_scheduler=False)


if __name__ == "__main__":
    main()
