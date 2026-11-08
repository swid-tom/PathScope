"""Application configuration loader."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

import yaml

CONFIG_PATH = os.environ.get("PATHSCOPE_CONFIG", "config.yaml")


@dataclass
class TargetConfig:
    host: str
    label: str
    tcp_ports: List[int] = field(default_factory=list)
    mtr_protocol: str | None = None
    mtr_port: int | None = None
    alert_latency_ms: float | None = None
    alert_jitter_ms: float | None = None
    alert_loss_pct: float | None = None
    alert_path_change: bool | None = None
    endpoint_probe_enabled: bool | None = None
    endpoint_probe_protocol: str | None = None
    endpoint_probe_count: int | None = None
    endpoint_probe_port: int | None = None
    dscp: int | None = None


@dataclass
class AppConfig:
    targets: List[TargetConfig]
    mtr_count: int
    mtr_protocol: str
    mtr_port: int
    interval_seconds: int
    retention_days: int
    port_timeout_seconds: int
    endpoint_probe_enabled: bool
    endpoint_probe_protocol: str
    endpoint_probe_count: int
    endpoint_probe_port: int | None
    tls_enabled: bool
    stun_enabled: bool
    stun_port: int
    geoip_enabled: bool
    geoip_cache_ttl_seconds: int
    dns_sinkhole_ranges: List[str]
    baseline_days: int
    alert_enabled: bool
    alert_webhook_url: str | None
    alert_latency_ms: float
    alert_jitter_ms: float
    alert_loss_pct: float
    alert_path_change: bool
    admin_auth_enabled: bool
    admin_auth_username: str
    admin_auth_password_sha256: str | None


def load_config(path: str = CONFIG_PATH) -> AppConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    targets = [
        TargetConfig(
            host=t["host"],
            label=t.get("label", t["host"]),
            tcp_ports=t.get("tcp_ports", []),
            mtr_protocol=t.get("mtr_protocol"),
            mtr_port=t.get("mtr_port"),
            alert_latency_ms=t.get("alert_latency_ms"),
            alert_jitter_ms=t.get("alert_jitter_ms"),
            alert_loss_pct=t.get("alert_loss_pct"),
            alert_path_change=t.get("alert_path_change"),
            endpoint_probe_enabled=t.get("endpoint_probe_enabled"),
            endpoint_probe_protocol=t.get("endpoint_probe_protocol"),
            endpoint_probe_count=t.get("endpoint_probe_count"),
            endpoint_probe_port=t.get("endpoint_probe_port"),
            dscp=t.get("dscp"),
        )
        for t in raw.get("targets", [])
    ]

    mtr = raw.get("mtr", {})
    endpoint_probe = raw.get("endpoint_probe", {})
    tls = raw.get("tls", {})
    stun = raw.get("stun", {})
    geoip = raw.get("geoip", {})
    baseline = raw.get("baseline", {})
    alerts = raw.get("alerts", {})
    admin_auth = raw.get("admin_auth", {})

    return AppConfig(
        targets=targets,
        mtr_count=mtr.get("count", 5),
        mtr_protocol=mtr.get("protocol", "tcp"),
        mtr_port=mtr.get("port", 443),
        interval_seconds=mtr.get("interval_seconds", 60),
        retention_days=raw.get("retention_days", 30),
        port_timeout_seconds=raw.get("port_timeout_seconds", 3),
        endpoint_probe_enabled=endpoint_probe.get("enabled", True),
        endpoint_probe_protocol=endpoint_probe.get("protocol", "tcp"),
        endpoint_probe_count=endpoint_probe.get("count", 5),
        endpoint_probe_port=endpoint_probe.get("port"),
        tls_enabled=tls.get("enabled", True),
        stun_enabled=stun.get("enabled", False),
        stun_port=stun.get("port", 3478),
        geoip_enabled=geoip.get("enabled", True),
        geoip_cache_ttl_seconds=geoip.get("cache_ttl_seconds", 86400),
        dns_sinkhole_ranges=raw.get("dns_sinkhole_ranges", []),
        baseline_days=baseline.get("days", 7),
        alert_enabled=alerts.get("enabled", True),
        alert_webhook_url=alerts.get("webhook_url"),
        alert_latency_ms=alerts.get("latency_ms", 250),
        alert_jitter_ms=alerts.get("jitter_ms", 50),
        alert_loss_pct=alerts.get("loss_pct", 2),
        alert_path_change=alerts.get("path_change", True),
        admin_auth_enabled=os.environ.get("PATHSCOPE_ADMIN_AUTH_ENABLED", str(admin_auth.get("enabled", False))).lower() in ("1", "true", "yes", "on"),
        admin_auth_username=os.environ.get("PATHSCOPE_ADMIN_USERNAME", admin_auth.get("username", "admin")),
        admin_auth_password_sha256=os.environ.get("PATHSCOPE_ADMIN_PASSWORD_SHA256", admin_auth.get("password_sha256")),
    )
