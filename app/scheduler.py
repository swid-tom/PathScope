"""Scheduled jobs: run probes for each target and prune old data."""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
from typing import Optional

import requests
from apscheduler.jobstores.base import JobLookupError
from apscheduler.schedulers.background import BackgroundScheduler

from app.config import AppConfig, TargetConfig
from app.db import AlertEvent, Hop, PortCheck, Run, SessionLocal
from app.probes import dns_probe, endpoint_probe, geoip, mtr_probe, port_probe, tls_probe
from app.queries import effective_path_hop

log = logging.getLogger("pathscope.scheduler")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _sinkhole_range_for_ip(ip: str, ranges: list[str]) -> Optional[str]:
    try:
        address = ipaddress.ip_address(ip)
        for cidr in ranges:
            if address in ipaddress.ip_network(cidr, strict=False):
                return cidr
    except ValueError:
        return None
    return None


def _path_hosts_from_hubs(hubs: list[dict]) -> list[str]:
    return [h.get("host") or "???" for h in hubs if h.get("host") and h.get("host") != "???"]


def _path_signature_from_hubs(hubs: list[dict]) -> str:
    return "|".join(_path_hosts_from_hubs(hubs))


def _record_alert(session, cfg: AppConfig, run: Run, severity: str, kind: str, message: str, details: Optional[dict] = None) -> None:
    if not cfg.alert_enabled:
        return
    event = AlertEvent(
        target=run.target,
        run_id=run.id,
        severity=severity,
        kind=kind,
        message=message,
        details=json.dumps(details or {}, sort_keys=True),
    )
    session.add(event)
    if cfg.alert_webhook_url:
        try:
            response = requests.post(
                cfg.alert_webhook_url,
                json={"target": run.target, "severity": severity, "kind": kind, "message": message, "run_id": run.id, "details": details or {}},
                timeout=5,
            )
            response.raise_for_status()
        except requests.RequestException:
            log.exception("alert webhook failed for %s", run.target)


def _evaluate_alerts(session, cfg: AppConfig, target: TargetConfig, run: Run) -> None:
    if not cfg.alert_enabled:
        return

    previous_run = (
        session.query(Run)
        .filter(Run.target == run.target, Run.id < run.id)
        .order_by(Run.id.desc())
        .first()
    )
    if not run.success:
        if previous_run is None or previous_run.success:
            message = run.error or "Network path probe failed"
            _record_alert(
                session,
                cfg,
                run,
                "critical",
                "probe_failure",
                f"Probe failed: {message}",
                {"error": message, "previous_run_id": previous_run.id if previous_run else None},
            )
        return

    if previous_run is not None and not previous_run.success:
        _record_alert(
            session,
            cfg,
            run,
            "info",
            "probe_recovery",
            "Probe recovered",
            {"previous_run_id": previous_run.id, "previous_error": previous_run.error},
        )

    hop = effective_path_hop(session, run.id)
    if not hop:
        return
    latency_ms = target.alert_latency_ms if target.alert_latency_ms is not None else cfg.alert_latency_ms
    jitter_ms = target.alert_jitter_ms if target.alert_jitter_ms is not None else cfg.alert_jitter_ms
    loss_pct = target.alert_loss_pct if target.alert_loss_pct is not None else cfg.alert_loss_pct
    path_change = target.alert_path_change if target.alert_path_change is not None else cfg.alert_path_change
    effective_avg = run.endpoint_avg_ms if run.endpoint_avg_ms is not None else hop.avg_ms
    effective_jitter = run.endpoint_jitter_ms if run.endpoint_jitter_ms is not None else hop.stdev_ms
    effective_loss = run.endpoint_loss_pct if run.endpoint_loss_pct is not None else hop.loss_pct

    if path_change and run.path_changed:
        previous = (
            session.query(Run)
            .filter(Run.target == run.target, Run.id != run.id, Run.success.is_(True), Run.path_signature.isnot(None))
            .order_by(Run.timestamp.desc())
            .first()
        )
        previous_path = previous.path_signature.split("|") if previous and previous.path_signature else []
        current_path = run.path_signature.split("|") if run.path_signature else []
        details = {
            "previous_run_id": previous.id if previous else None,
            "previous_timestamp": previous.timestamp.isoformat() + "Z" if previous else None,
            "previous_path": previous_path,
            "current_path": current_path,
            "added_hops": [hop for hop in current_path if hop not in previous_path],
            "removed_hops": [hop for hop in previous_path if hop not in current_path],
            "previous_hop_count": len(previous_path),
            "current_hop_count": len(current_path),
        }
        _record_alert(session, cfg, run, "warning", "path_change", "Network path changed from previous successful run", details)
    if effective_avg is not None and effective_avg >= latency_ms:
        _record_alert(session, cfg, run, "critical", "latency", f"Endpoint latency {effective_avg:.1f} ms >= {latency_ms:.1f} ms", {
            "measured_ms": effective_avg,
            "threshold_ms": latency_ms,
            "source": "endpoint" if run.endpoint_avg_ms is not None else "mtr_effective_hop",
            "endpoint_probe_protocol": run.endpoint_probe_protocol,
            "endpoint_avg_ms": run.endpoint_avg_ms,
            "mtr_effective_hop": {"hop_num": hop.hop_num, "host": hop.host, "avg_ms": hop.avg_ms, "loss_pct": hop.loss_pct, "jitter_ms": hop.stdev_ms},
        })
    if effective_jitter is not None and effective_jitter >= jitter_ms:
        _record_alert(session, cfg, run, "warning", "jitter", f"Endpoint jitter {effective_jitter:.1f} ms >= {jitter_ms:.1f} ms", {
            "measured_ms": effective_jitter,
            "threshold_ms": jitter_ms,
            "source": "endpoint" if run.endpoint_jitter_ms is not None else "mtr_effective_hop",
            "endpoint_probe_protocol": run.endpoint_probe_protocol,
            "endpoint_jitter_ms": run.endpoint_jitter_ms,
            "mtr_effective_hop": {"hop_num": hop.hop_num, "host": hop.host, "avg_ms": hop.avg_ms, "loss_pct": hop.loss_pct, "jitter_ms": hop.stdev_ms},
        })
    if effective_loss is not None and effective_loss >= loss_pct:
        _record_alert(session, cfg, run, "critical", "loss", f"Endpoint loss {effective_loss:.1f}% >= {loss_pct:.1f}%", {
            "measured_pct": effective_loss,
            "threshold_pct": loss_pct,
            "source": "endpoint" if run.endpoint_loss_pct is not None else "mtr_effective_hop",
            "endpoint_probe_protocol": run.endpoint_probe_protocol,
            "endpoint_loss_pct": run.endpoint_loss_pct,
            "mtr_effective_hop": {"hop_num": hop.hop_num, "host": hop.host, "avg_ms": hop.avg_ms, "loss_pct": hop.loss_pct, "jitter_ms": hop.stdev_ms},
        })


def probe_target(target: TargetConfig, cfg: AppConfig) -> None:
    session = SessionLocal()
    try:
        tos = (target.dscp << 2) if target.dscp is not None else None
        ips, dns_ms, dns_err = dns_probe.resolve(target.host)
        resolved_ip = ips[0] if ips else None
        sinkhole_range = _sinkhole_range_for_ip(resolved_ip, cfg.dns_sinkhole_ranges) if resolved_ip else None

        run = Run(
            target=target.host,
            timestamp=dt.datetime.utcnow(),
            resolved_ip=resolved_ip,
            dns_ms=dns_ms,
            success=bool(resolved_ip),
            error=dns_err,
            dns_sinkhole_match=bool(sinkhole_range),
            dns_sinkhole_range=sinkhole_range,
            dns_validation_warning=f"Resolved IP is in configured DNS sinkhole/security range {sinkhole_range}" if sinkhole_range else None,
        )
        session.add(run)
        session.flush()

        if resolved_ip:
            mtr_protocol = target.mtr_protocol or cfg.mtr_protocol
            mtr_port = target.mtr_port or cfg.mtr_port
            hubs, mtr_err = mtr_probe.run_mtr(
                target.host,
                count=cfg.mtr_count,
                protocol=mtr_protocol,
                port=mtr_port,
                tos=tos,
            )
            if hubs:
                signature = _path_signature_from_hubs(hubs)
                previous = (
                    session.query(Run)
                    .filter(Run.target == target.host, Run.id != run.id, Run.success.is_(True), Run.path_signature.isnot(None))
                    .order_by(Run.timestamp.desc())
                    .first()
                )
                run.path_signature = signature
                run.path_changed = bool(previous and previous.path_signature != signature)

                hop_ips = [h.get("host") for h in hubs if h.get("host") and _is_ip(h["host"])]
                geo_map = geoip.lookup_batch(hop_ips, cfg.geoip_cache_ttl_seconds) if cfg.geoip_enabled else {}

                for hub in hubs:
                    host = hub.get("host") or "???"
                    geo = geo_map.get(host, {})
                    session.add(
                        Hop(
                            run_id=run.id,
                            hop_num=hub.get("count"),
                            host=host,
                            loss_pct=hub.get("Loss%"),
                            sent=hub.get("Snt"),
                            last_ms=hub.get("Last"),
                            avg_ms=hub.get("Avg"),
                            best_ms=hub.get("Best"),
                            worst_ms=hub.get("Wrst"),
                            stdev_ms=hub.get("StDev"),
                            asn=geo.get("as"),
                            org=geo.get("org"),
                            country=geo.get("country"),
                            city=geo.get("city"),
                        )
                    )
            else:
                run.error = mtr_err
                run.success = False

            endpoint_enabled = target.endpoint_probe_enabled if target.endpoint_probe_enabled is not None else cfg.endpoint_probe_enabled
            if endpoint_enabled:
                protocol = (target.endpoint_probe_protocol or cfg.endpoint_probe_protocol).lower().strip()
                endpoint_count = target.endpoint_probe_count or cfg.endpoint_probe_count
                endpoint_port = target.endpoint_probe_port or cfg.endpoint_probe_port or (target.tcp_ports[0] if target.tcp_ports else 443)
                if protocol == "icmp":
                    ok, avg_ms, loss_pct, jitter_ms, err = endpoint_probe.icmp_ping(
                        resolved_ip, count=endpoint_count, timeout=cfg.port_timeout_seconds, tos=tos
                    )
                    run.endpoint_probe_protocol = "icmp"
                else:
                    ok, avg_ms, loss_pct, jitter_ms, err = endpoint_probe.tcp_probe(
                        resolved_ip, port=endpoint_port, count=endpoint_count, timeout=cfg.port_timeout_seconds, tos=tos
                    )
                    run.endpoint_probe_protocol = f"tcp/{endpoint_port}"
                run.endpoint_avg_ms = avg_ms
                run.endpoint_loss_pct = loss_pct
                run.endpoint_jitter_ms = jitter_ms
                run.endpoint_error = None if ok else err

            for tcp_port in target.tcp_ports:
                ok, ms, err = port_probe.tcp_check(resolved_ip, tcp_port, timeout=cfg.port_timeout_seconds, tos=tos)
                session.add(
                    PortCheck(run_id=run.id, protocol="tcp", port=tcp_port, success=ok, latency_ms=ms, error=err)
                )
                if cfg.tls_enabled:
                    tls_ok, tls_ms, tls_err = tls_probe.tls_check(target.host, resolved_ip, tcp_port, timeout=cfg.port_timeout_seconds, tos=tos)
                    session.add(
                        PortCheck(run_id=run.id, protocol="tls", port=tcp_port, success=tls_ok, latency_ms=tls_ms, error=tls_err)
                    )

            if cfg.stun_enabled:
                ok, ms, err = port_probe.stun_check(resolved_ip, cfg.stun_port, timeout=cfg.port_timeout_seconds, tos=tos)
                session.add(
                    PortCheck(
                        run_id=run.id, protocol="udp-stun", port=cfg.stun_port, success=ok, latency_ms=ms, error=err
                    )
                )

            session.flush()
        _evaluate_alerts(session, cfg, target, run)
        session.commit()
    except Exception:
        log.exception("probe_target failed for %s", target.host)
        session.rollback()
    finally:
        session.close()


def prune_old_data(cfg: AppConfig) -> None:
    session = SessionLocal()
    try:
        retention_days = cfg.retention_days
        cutoff = dt.datetime.utcnow() - dt.timedelta(days=retention_days)
        deleted = session.query(Run).filter(Run.timestamp < cutoff).delete(synchronize_session=False)
        session.commit()
        if deleted:
            log.info("pruned %d runs older than %d days", deleted, retention_days)
    except Exception:
        log.exception("prune_old_data failed")
        session.rollback()
    finally:
        session.close()


def start_scheduler(cfg: AppConfig) -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="UTC")
    target_count = max(len(cfg.targets), 1)
    probe_spacing = max(1, int(cfg.interval_seconds / target_count))

    for index, target in enumerate(cfg.targets):
        schedule_target_probe(scheduler, cfg, target, delay_seconds=index * probe_spacing)

    scheduler.add_job(
        prune_old_data,
        "interval",
        hours=6,
        args=[cfg],
        id="prune_old_data",
        max_instances=1,
    )

    scheduler.start()
    return scheduler


def schedule_target_probe(
    scheduler: BackgroundScheduler,
    cfg: AppConfig,
    target: TargetConfig,
    delay_seconds: int = 0,
) -> None:
    scheduler.add_job(
        probe_target,
        "interval",
        seconds=cfg.interval_seconds,
        args=[target, cfg],
        id=f"probe:{target.host}",
        next_run_time=dt.datetime.utcnow() + dt.timedelta(seconds=delay_seconds),
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )


def unschedule_target_probe(scheduler: BackgroundScheduler, host: str) -> None:
    try:
        scheduler.remove_job(f"probe:{host}")
    except JobLookupError:
        pass
