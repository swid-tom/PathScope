"""IP -> BGP origin ASN and GeoIP enrichment.

Team Cymru supplies BGP origin/prefix data; ip-api.com supplies location data.
Lookups are best-effort, cached in-memory with a TTL, and skip non-global IPs.
For production-grade or higher-volume use, replace the GeoIP lookup with a local
MaxMind GeoLite2 (mmdb) database instead of network calls.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import time
from typing import Dict, List

import requests

log = logging.getLogger(__name__)
_CACHE: Dict[str, tuple[float, dict]] = {}
_BATCH_URL = "http://ip-api.com/batch?fields=query,country,city,isp,org,as"
_CYMRU_WHOIS_HOST = "whois.cymru.com"
_CYMRU_WHOIS_PORT = 43
_LOOKUP_TIMEOUT_SECONDS = 5


def _is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _parse_cymru_response(response: str) -> Dict[str, dict]:
    records: Dict[str, dict] = {}
    origins: Dict[str, list[str]] = {}
    prefixes: Dict[str, list[str]] = {}
    names: Dict[str, list[str]] = {}

    for line in response.splitlines():
        fields = [field.strip() for field in line.split("|")]
        if len(fields) < 3:
            continue

        as_number = fields[0].upper().removeprefix("AS")
        try:
            address = ipaddress.ip_address(fields[1])
            network = ipaddress.ip_network(fields[2], strict=False)
        except ValueError:
            continue
        if not as_number.isascii() or not as_number.isdecimal() or address not in network:
            continue

        ip = str(address)
        asn = f"AS{as_number}"
        origin_list = origins.setdefault(ip, [])
        if asn not in origin_list:
            origin_list.append(asn)
        prefix_list = prefixes.setdefault(ip, [])
        if str(network) not in prefix_list:
            prefix_list.append(str(network))
        if len(fields) > 6 and fields[6]:
            name_list = names.setdefault(ip, [])
            if fields[6] not in name_list:
                name_list.append(fields[6])

    for ip, ip_origins in origins.items():
        records[ip] = {
            "as": ", ".join(ip_origins),
            "bgp_prefix": ", ".join(prefixes[ip]),
            "asn_source": "Team Cymru",
        }
        if names.get(ip):
            records[ip]["org"] = "; ".join(names[ip])

    return records


def _lookup_cymru_batch(ips: List[str]) -> Dict[str, dict]:
    if not ips:
        return {}

    payload = "\n".join(("begin", "verbose", *ips, "end", ""))
    try:
        with socket.create_connection(
            (_CYMRU_WHOIS_HOST, _CYMRU_WHOIS_PORT),
            timeout=_LOOKUP_TIMEOUT_SECONDS,
        ) as connection:
            connection.settimeout(_LOOKUP_TIMEOUT_SECONDS)
            connection.sendall(payload.encode("ascii"))
            chunks = []
            while True:
                try:
                    chunk = connection.recv(4096)
                except socket.timeout:
                    response = b"".join(chunks).decode("utf-8", errors="replace")
                    records = _parse_cymru_response(response)
                    if set(ips) - records.keys():
                        log.warning(
                            "Team Cymru lookup timed out with results for %d of %d hop IPs",
                            len(records),
                            len(ips),
                        )
                    return records
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError as error:
        log.warning("Team Cymru IP-to-ASN lookup failed: %s", error)
        return {}

    response = b"".join(chunks).decode("utf-8", errors="replace")
    return _parse_cymru_response(response)


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

    geo_data: Dict[str, dict] = {}
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
                geo_data[ip] = {
                    "as": entry.get("as"),
                    "org": entry.get("org") or entry.get("isp"),
                    "country": entry.get("country"),
                    "city": entry.get("city"),
                    "asn_source": "ip-api.com" if entry.get("as") else None,
                }
        except (requests.RequestException, ValueError) as error:
            log.warning("ip-api.com hop enrichment failed: %s", error)

    bgp_data = _lookup_cymru_batch(to_query) if to_query else {}
    for ip in to_query:
        data = {**geo_data.get(ip, {}), **bgp_data.get(ip, {})}
        if data:
            _CACHE[ip] = (now, data)
            result[ip] = data

    return result
