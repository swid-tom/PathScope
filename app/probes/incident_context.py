"""Best-effort external context for local path and service incidents."""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
import socket
from urllib.parse import urlsplit

import requests

log = logging.getLogger(__name__)

_RIPESTAT_BGPLAY_URL = "https://stat.ripe.net/data/bgplay/data.json"
_RIPESTAT_RPKI_URL = "https://stat.ripe.net/data/rpki-validation/data.json"
_RIPE_RESPONSE_LIMIT = 2 * 1024 * 1024
_STATUS_RESPONSE_LIMIT = 512 * 1024
_KNOWN_STATUS_PAGES = {
    "github.com": ("www.githubstatus.com", "GitHub Status"),
    "cloudflare.com": ("www.cloudflarestatus.com", "Cloudflare Status"),
    "discord.com": ("discordstatus.com", "Discord Status"),
    "fastly.com": ("status.fastly.com", "Fastly Status"),
    "zoom.us": ("status.zoom.us", "Zoom Status"),
    "atlassian.com": ("status.atlassian.com", "Atlassian Status"),
}


def normalize_status_page_url(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None

    url = value.strip()
    parsed = urlsplit(url)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "status_page_url must be a public HTTPS JSON URL on port 443 without credentials or query parameters"
        )
    return url


def _normalized_target_host(value: str | None) -> str | None:
    if not value:
        return None
    host = value.strip().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass

    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = host.split(".")
    if len(labels) < 2 or len(host) > 253:
        return None
    if any(
        not label
        or len(label) > 63
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        return None
    return host


def _discover_status_page(target_host: str | None, manual_url: str | None) -> dict:
    if manual_url and manual_url.strip():
        return {
            "status": "candidate",
            "url": normalize_status_page_url(manual_url),
            "source": "Manual configuration",
            "provider": "Configured status page",
            "confidence": "high",
        }

    host = _normalized_target_host(target_host)
    if host is None:
        return {
            "status": "not_found",
            "url": None,
            "source": "No recognized provider or conventional endpoint matched",
            "provider": None,
            "confidence": "none",
        }

    for domain, (status_host, provider) in _KNOWN_STATUS_PAGES.items():
        if host == domain or host.endswith(f".{domain}"):
            return {
                "status": "candidate",
                "url": f"https://{status_host}/api/v2/summary.json",
                "source": "Known provider mapping",
                "provider": provider,
                "confidence": "high",
            }

    if host.endswith(".statuspage.io"):
        return {
            "status": "candidate",
            "url": f"https://{host}/api/v2/summary.json",
            "source": "Atlassian Statuspage hostname",
            "provider": "Atlassian Statuspage",
            "confidence": "high",
        }

    if host.startswith("status."):
        status_host = host
        source = "Target uses a status hostname"
        confidence = "medium"
    else:
        base_host = host[4:] if host.startswith("www.") else host
        if len(base_host.split(".")) != 2:
            return {
                "status": "not_found",
                "url": None,
                "source": "No recognized provider or conventional endpoint matched",
                "provider": None,
                "confidence": "none",
            }
        status_host = f"status.{base_host}"
        source = "Conventional status subdomain"
        confidence = "medium"

    return {
        "status": "candidate",
        "url": f"https://{status_host}/api/v2/summary.json",
        "source": source,
        "provider": "Statuspage-compatible summary API",
        "confidence": confidence,
    }


def _ripe_stat_json(url: str, params: dict) -> dict:
    response = requests.get(
        url,
        params=params,
        timeout=(3, 6),
        allow_redirects=False,
        stream=True,
    )
    try:
        if 300 <= response.status_code < 400:
            raise ValueError("RIPEstat redirects are not followed")
        response.raise_for_status()
        body = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            body.extend(chunk)
            if len(body) > _RIPE_RESPONSE_LIMIT:
                raise ValueError("RIPEstat response is too large")
        payload = json.loads(body)
    finally:
        response.close()
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        raise ValueError("RIPEstat returned an invalid response")
    return payload


def _origin_from_path(path) -> str | None:
    if isinstance(path, str):
        path = path.split()
    if not isinstance(path, list) or not path:
        return None
    origin = str(path[-1]).upper().removeprefix("AS")
    return origin if origin.isascii() and origin.isdecimal() else None


def _event_timestamp(value) -> str | None:
    if isinstance(value, (int, float)):
        return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat()
    return value if isinstance(value, str) else None


def _fetch_bgp_context(prefix: str, event_time: dt.datetime) -> dict:
    end = dt.datetime.now(dt.timezone.utc)
    start = event_time.replace(tzinfo=dt.timezone.utc) - dt.timedelta(minutes=15)
    payload = _ripe_stat_json(
        _RIPESTAT_BGPLAY_URL,
        {
            "resource": prefix,
            "starttime": start.isoformat(timespec="seconds"),
            "endtime": end.isoformat(timespec="seconds"),
        },
    )
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("RIPEstat BGPlay response is missing data")

    initial_state = data.get("initial_state") or []
    initial_origins = sorted(
        {
            origin
            for route in initial_state
            if isinstance(route, dict)
            for origin in [_origin_from_path(route.get("path"))]
            if origin
        }
    )
    raw_events = data.get("events") or []
    events = []
    announcements = 0
    withdrawals = 0
    for event in raw_events:
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or "").upper()
        if event_type in ("A", "ANNOUNCEMENT", "ANNOUNCE"):
            announcements += 1
        elif event_type in ("W", "WITHDRAWAL", "WITHDRAW"):
            withdrawals += 1
        if len(events) >= 8:
            continue
        attrs = event.get("attrs") if isinstance(event.get("attrs"), dict) else {}
        path = attrs.get("path")
        events.append(
            {
                "timestamp": _event_timestamp(event.get("timestamp")),
                "type": event_type or "unknown",
                "source": str(attrs.get("source_id") or event.get("source_id") or ""),
                "origin_asn": _origin_from_path(path),
            }
        )

    return {
        "status": "available",
        "prefix": prefix,
        "collector_routes": len(initial_state),
        "observed_origins": initial_origins,
        "event_count": len(raw_events),
        "announcements": announcements,
        "withdrawals": withdrawals,
        "events": events,
        "window_minutes": 15,
    }


def _fetch_rpki_context(prefix: str, origin_asns: list[str]) -> list[dict]:
    results = []
    for origin in dict.fromkeys(origin_asns):
        asn = origin.upper().removeprefix("AS")
        if not asn.isascii() or not asn.isdecimal():
            continue
        payload = _ripe_stat_json(
            _RIPESTAT_RPKI_URL,
            {"resource": asn, "prefix": prefix},
        )
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("RIPEstat RPKI response is missing data")
        results.append(
            {
                "asn": f"AS{asn}",
                "prefix": prefix,
                "status": str(data.get("status") or "unknown"),
            }
        )
    return results


def _assert_public_status_host(host: str) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            resolved = {
                ipaddress.ip_address(record[4][0])
                for record in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            }
        except OSError as error:
            raise ValueError("status page host could not be resolved") from error
        if not resolved:
            raise ValueError("status page host has no addresses")
        addresses = resolved
    else:
        addresses = {address}

    if any(not address.is_global for address in addresses):
        raise ValueError("status page host must resolve only to public IP addresses")


def _fetch_status_page(url: str, require_status_shape: bool = False) -> dict:
    normalized = normalize_status_page_url(url)
    if normalized is None:
        return {"status": "not_configured"}
    host = urlsplit(normalized).hostname
    if host is None:
        raise ValueError("status page URL has no host")
    _assert_public_status_host(host)

    response = requests.get(
        normalized,
        timeout=(3, 6),
        allow_redirects=False,
        stream=True,
    )
    try:
        if 300 <= response.status_code < 400:
            raise ValueError("status page redirects are not followed")
        response.raise_for_status()
        body = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            body.extend(chunk)
            if len(body) > _STATUS_RESPONSE_LIMIT:
                raise ValueError("status page response is too large")
        payload = json.loads(body)
    finally:
        response.close()

    if not isinstance(payload, dict):
        raise ValueError("status page JSON must be an object")

    status_data = payload.get("status")
    status_data = status_data if isinstance(status_data, dict) else {}
    if require_status_shape and not any(
        isinstance(status_data.get(key), str) and status_data[key]
        for key in ("indicator", "description")
    ):
        raise ValueError("JSON does not match the supported status-summary format")
    page_data = payload.get("page")
    page_data = page_data if isinstance(page_data, dict) else {}
    active_incidents = []
    for incident in payload.get("incidents") or []:
        if not isinstance(incident, dict):
            continue
        if str(incident.get("status") or "").lower() in ("resolved", "completed"):
            continue
        active_incidents.append(
            {
                "name": str(incident.get("name") or "Unlabeled incident"),
                "status": str(incident.get("status") or "unknown"),
                "updated_at": incident.get("updated_at"),
            }
        )

    return {
        "status": "available",
        "indicator": str(status_data.get("indicator") or "unknown"),
        "description": str(status_data.get("description") or "No status description"),
        "page_updated_at": page_data.get("updated_at") or payload.get("updated_at"),
        "active_incidents": active_incidents[:10],
        "url": normalized,
    }


def collect_incident_context(
    *,
    event_time: dt.datetime,
    trigger_reasons: list[str],
    local: dict,
    prefix: str | None,
    origin_asns: list[str],
    status_page_url: str | None,
) -> dict:
    context = {
        "event_timestamp": event_time.isoformat() + "Z",
        "trigger_reasons": trigger_reasons,
        "local": local,
        "bgp": {"status": "not_available"},
        "rpki": [],
        "rpki_status": "not_available",
        "status_page": {"status": "not_configured"},
        "status_page_discovery": {
            "status": "not_found",
            "url": None,
            "source": "No recognized provider or conventional endpoint matched",
            "provider": None,
            "confidence": "none",
        },
        "assessment": {"confidence": "inconclusive", "summary": ""},
        "sources": ["Local PathScope probes"],
    }

    normalized_prefix = None
    if prefix:
        try:
            network = ipaddress.ip_network(prefix, strict=False)
            if not network.network_address.is_global:
                raise ValueError("BGP prefix is not globally routable")
            normalized_prefix = str(network)
        except ValueError as error:
            log.warning("Invalid BGP prefix for incident context %s: %s", prefix, error)

    if normalized_prefix:
        try:
            context["bgp"] = _fetch_bgp_context(normalized_prefix, event_time)
            context["sources"].append("RIPEstat BGPlay")
        except (ValueError, requests.RequestException) as error:
            log.warning("RIPEstat BGPlay context lookup failed for %s: %s", normalized_prefix, error)
            context["bgp"] = {"status": "unavailable"}

        try:
            context["rpki"] = _fetch_rpki_context(normalized_prefix, origin_asns)
            context["rpki_status"] = "available" if context["rpki"] else "not_available"
            if context["rpki"]:
                context["sources"].append("RIPEstat RPKI validation")
        except (ValueError, requests.RequestException) as error:
            log.warning("RIPEstat RPKI lookup failed for %s: %s", normalized_prefix, error)
            context["rpki_status"] = "unavailable"

    discovery = _discover_status_page(local.get("target"), status_page_url)
    context["status_page_discovery"] = discovery
    if discovery["url"]:
        try:
            context["status_page"] = _fetch_status_page(
                discovery["url"],
                require_status_shape=discovery["source"] != "Manual configuration",
            )
            discovery["status"] = "verified"
            context["status_page"]["discovery"] = dict(discovery)
            if discovery["source"] == "Manual configuration":
                context["sources"].append("Configured public status page")
            else:
                context["sources"].append(discovery["provider"])
        except (ValueError, OSError, requests.RequestException) as error:
            log.warning("Status page lookup failed for %s: %s", discovery["url"], error)
            discovery["status"] = "unavailable"
            context["status_page"] = {
                "status": "unavailable",
                "url": discovery["url"],
                "discovery": dict(discovery),
            }
    elif not status_page_url:
        context["status_page"]["status"] = "not_found" if local.get("target") else "not_configured"
        context["status_page"]["discovery"] = dict(discovery)

    local_failure = any(
        reason in trigger_reasons
        for reason in ("dns_failure", "mtr_failure", "endpoint_failure", "endpoint_loss", "service_failure")
    )
    active_status_incidents = context["status_page"].get("active_incidents", [])
    provider_reports_issue = str(context["status_page"].get("indicator") or "").lower() in {
        "minor",
        "major",
        "critical",
        "maintenance",
    }
    if local_failure and (active_status_incidents or provider_reports_issue):
        context["assessment"] = {
            "confidence": "corroborated",
            "summary": "A local probe failure coincides with a provider-reported degraded status or active incident; this supports, but does not prove, a service-side relationship.",
        }
    elif local.get("path_changed") and context["bgp"].get("event_count", 0):
        context["assessment"] = {
            "confidence": "suggestive",
            "summary": "RIPEstat observed BGP updates for the destination prefix during the lookback window. This is correlated evidence, not proof that the updates caused the local path change.",
        }
    else:
        context["assessment"] = {
            "confidence": "inconclusive",
            "summary": "The local event is recorded, but available public data does not establish a cause. A missing BGP update or status-page incident is not proof that no wider issue exists.",
        }

    context["collected_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    return context
