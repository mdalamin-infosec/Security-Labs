#!/usr/bin/env python3
"""Create the data view, saved searches and a triage dashboard in a local Kibana 8.x.

Usage: python kibana/setup_kibana.py [--kibana http://127.0.0.1:5601]
Idempotent: objects use fixed ids and are overwritten on re-run. Standard library only.
Charts (Lens) are not created here; follow docs/KIBANA_GUIDE.md to add them.
"""

import argparse
import json
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

DATA_VIEW_ID = "threatwatch-eve"
SEARCHES = [
    ("tw-alerts", "TW - All alerts", 'event_type : "alert"', ["src_ip", "dest_ip", "dest_port", "alert.signature", "alert.severity"]),
    ("tw-high", "TW - High severity (Suricata 1)", 'event_type : "alert" and alert.severity : 1', ["src_ip", "dest_ip", "alert.signature"]),
    ("tw-ssh", "TW - SSH brute force (sid 9000001)", "alert.signature_id : 9000001", ["@timestamp", "src_ip", "dest_ip", "alert.signature"]),
    ("tw-web", "TW - Web attacks (sid 9000004, 9000007)", "alert.signature_id : (9000004 or 9000007)", ["@timestamp", "src_ip", "dest_ip", "alert.signature"]),
    ("tw-dns", "TW - DNS anomalies (sid 9000006)", "alert.signature_id : 9000006", ["@timestamp", "src_ip", "dest_ip", "alert.signature"]),
    ("tw-flows-external", "TW - Outbound flows (beacon hunting)", 'event_type : "flow" and not dest_ip : (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)', ["@timestamp", "src_ip", "dest_ip", "dest_port", "flow.pkts_toserver"]),
]


def call(base: str, method: str, path: str, payload: dict | None = None) -> dict:
    request = Request(base + path, method=method, data=json.dumps(payload).encode() if payload is not None else None,
                      headers={"kbn-xsrf": "threatwatch", "Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        raise SystemExit(f"Kibana returned {error.code} for {path}: {error.read().decode()[:300]}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kibana", default="http://127.0.0.1:5601")
    base = parser.parse_args().kibana.rstrip("/")
    call(base, "POST", "/api/data_views/data_view", {"override": True, "data_view": {
        "id": DATA_VIEW_ID, "title": "threatwatch-eve-*", "name": "ThreatWatch EVE", "timeFieldName": "@timestamp"}})
    for sid, title, query, columns in SEARCHES:
        call(base, "POST", f"/api/saved_objects/search/{sid}?overwrite=true", {
            "attributes": {"title": title, "columns": columns, "sort": [["@timestamp", "desc"]], "description": "",
                           "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": query}, "filter": [],
                                                                                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})}},
            "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DATA_VIEW_ID}]})
    panels, refs = [], []
    for number, (sid, *_rest) in enumerate(SEARCHES, 1):
        panels.append({"version": "8.15.3", "type": "search", "panelIndex": str(number), "panelRefName": f"panel_{number}", "embeddableConfig": {},
                       "gridData": {"x": 0 if number % 2 else 24, "y": ((number - 1) // 2) * 15, "w": 24, "h": 15, "i": str(number)}})
        refs.append({"name": f"panel_{number}", "type": "search", "id": sid})
    call(base, "POST", "/api/saved_objects/dashboard/tw-triage?overwrite=true", {
        "attributes": {"title": "ThreatWatch - Alert triage", "description": "Saved searches for analyst triage.", "panelsJSON": json.dumps(panels),
                       "optionsJSON": json.dumps({"useMargins": True}), "timeRestore": False,
                       "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})}},
        "references": refs})
    print(f"Created data view, {len(SEARCHES)} saved searches and dashboard 'ThreatWatch - Alert triage'.")
    print(f"Open {base}/app/dashboards and select the dashboard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
