"""IP -> ASN/org/geo enrichment via the free ip-api.com batch endpoint.

Best-effort, cached in-memory with a TTL, and skips private/reserved IPs.
For production-grade or higher-volume use, replace with a local MaxMind
GeoLite2 (mmdb) lookup via the `geoip2` package instead of network calls.
"""
from __future__ import annotations

import ipaddress
import time
from typing import Dict, List

import requests

_CACHE: Dict[str, tuple[float, dict]] = {}
_BATCH_URL = "http://ip-api.com/batch?fields=query,country,city,isp,org,as"


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


def lookup_batch(ips: List[str], ttl_seconds: int = 86400) -> Dict[str, dict]:
    now = time.time()
    result: Dict[str, dict] = {}
    to_query: List[str] = []

    for ip in dict.fromkeys(ips):  # de-dup, preserve order
        if not _is_public_ip(ip):
            continue
        cached = _CACHE.get(ip)
        if cached and (now - cached[0]) < ttl_seconds:
            result[ip] = cached[1]
        else:
            to_query.append(ip)

    # ip-api.com batch endpoint accepts up to 100 entries per request
    for i in range(0, len(to_query), 100):
        chunk = to_query[i : i + 100]
        try:
            resp = requests.post(_BATCH_URL, json=chunk, timeout=5)
            resp.raise_for_status()
            for entry in resp.json():
                ip = entry.get("query")
                if not ip:
                    continue
                data = {
                    "as": entry.get("as"),
                    "org": entry.get("org") or entry.get("isp"),
                    "country": entry.get("country"),
                    "city": entry.get("city"),
                }
                _CACHE[ip] = (now, data)
                result[ip] = data
        except requests.RequestException:
            continue  # best-effort; leave these hops without geo data

    return result
