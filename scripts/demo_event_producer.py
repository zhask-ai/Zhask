import argparse
import random
import time
from datetime import datetime, timezone
from uuid import uuid4

import redis


def build_event() -> dict[str, str]:
    scenario_roll = random.randint(1, 100)
    event = {
        "event_id": str(uuid4()),
        "source_ip": f"10.42.0.{random.randint(2, 245)}",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    if scenario_roll <= 34:
        event.update(
            {
                "bytes_out": str(random.randint(11_000_000, 20_000_000)),
                "off_hours": "false",
                "unknown_endpoint": "false",
            }
        )
    elif scenario_roll <= 67:
        event.update(
            {
                "bytes_out": str(random.randint(1000, 250000)),
                "off_hours": "true",
                "unknown_endpoint": "false",
            }
        )
    else:
        event.update(
            {
                "bytes_out": str(random.randint(1000, 250000)),
                "off_hours": "false",
                "unknown_endpoint": "true",
            }
        )
    return event


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish demo events to Redis Stream.")
    parser.add_argument("--redis-url", default="redis://localhost:6379/0")
    parser.add_argument("--stream-key", default="integrishield:api_call_events")
    parser.add_argument("--interval", type=float, default=1.0, help="seconds between events")
    parser.add_argument("--count", type=int, default=0, help="0 means run forever")
    args = parser.parse_args()

    client = redis.from_url(args.redis_url)
    sent = 0
    print(f"Producing to stream={args.stream_key} redis={args.redis_url}")

    while True:
        payload = build_event()
        entry_id = client.xadd(args.stream_key, payload)
        sent += 1
        print(f"[{sent}] XADD id={entry_id.decode() if isinstance(entry_id, bytes) else entry_id}")

        if args.count > 0 and sent >= args.count:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
