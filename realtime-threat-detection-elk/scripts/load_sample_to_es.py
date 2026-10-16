#!/usr/bin/env python3
"""Bulk-load EVE JSON (for example the synthetic demo file) into a local Elasticsearch.

Usage: python scripts/load_sample_to_es.py data/demo-eve.json [--es http://127.0.0.1:9200]
Only loopback / private Elasticsearch hosts are accepted. Uses the standard library only.
"""

import argparse
import ipaddress
import json
from pathlib import Path
import socket
import sys
from urllib.parse import urlparse
from urllib.request import Request, urlopen

INDEX = "threatwatch-eve-demo"


def local_host(url: str) -> bool:
    host = urlparse(url).hostname or ""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except (OSError, ValueError):
        return False
    return ip.is_private or ip.is_loopback


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("eve", type=Path)
    parser.add_argument("--es", default="http://127.0.0.1:9200")
    args = parser.parse_args()
    if not local_host(args.es):
        print("error: refusing to send events to a non-private host", file=sys.stderr)
        return 1
    lines, skipped = [], 0
    for raw in args.eve.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(raw)
            event["@timestamp"] = event.pop("timestamp")
        except (ValueError, KeyError, AttributeError):
            skipped += 1
            continue
        lines.append(json.dumps({"index": {"_index": INDEX}}))
        lines.append(json.dumps(event))
    body = ("\n".join(lines) + "\n").encode()
    request = Request(f"{args.es}/_bulk", data=body, headers={"Content-Type": "application/x-ndjson"}, method="POST")
    with urlopen(request, timeout=30) as response:
        result = json.load(response)
    failed = sum(1 for item in result["items"] if item["index"].get("error"))
    print(f"indexed {len(result['items']) - failed} events into {INDEX}; {failed} failed; {skipped} malformed lines skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
