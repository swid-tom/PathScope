"""FastAPI app: REST API + dashboard for latency/path history."""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json
import logging
import os
import secrets
from typing import List, Optional

import yaml
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import text
from starlette.requests import Request

from app.config import CONFIG_PATH, TargetConfig, load_config
from app.db import AlertEvent, DB_PATH, Hop, PortCheck, Run, SessionLocal, engine, init_db
from app.scheduler import schedule_target_probe, start_scheduler, unschedule_target_probe

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(title="PathScope — Network Path & Edge Monitor")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
security = HTTPBasic(auto_error=False)

cfg = load_config()
scheduler = None


class TargetCreate(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    label: Optional[str] = Field(default=None, max_length=100)
    tcp_ports: List[int] = Field(default_factory=list)
    mtr_protocol: Optional[str] = Field(default=None, pattern="^(tcp|udp|icmp)$")
    mtr_port: Optional[int] = Field(default=None, ge=1, le=65535)
    alert_latency_ms: Optional[float] = Field(default=None, ge=0)
    alert_jitter_ms: Optional[float] = Field(default=None, ge=0)
    alert_loss_pct: Optional[float] = Field(default=None, ge=0, le=100)
    alert_path_change: Optional[bool] = None
    endpoint_probe_enabled: Optional[bool] = None
    endpoint_probe_protocol: Optional[str] = Field(default=None, pattern="^(tcp|icmp)$")
    endpoint_probe_count: Optional[int] = Field(default=None, ge=1, le=50)
    endpoint_probe_port: Optional[int] = Field(default=None, ge=1, le=65535)
    dscp: Optional[int] = Field(default=None, ge=0, le=63)


class RetentionSettings(BaseModel):
    retention_days: int = Field(ge=1, le=3650)


def require_admin(credentials: HTTPBasicCredentials | None = Depends(security)) -> None:
    if not cfg.admin_auth_enabled:
        return
    if credentials is None or not cfg.admin_auth_password_sha256:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )

    supplied_hash = hashlib.sha256(credentials.password.encode("utf-8")).hexdigest()
    username_ok = secrets.compare_digest(credentials.username, cfg.admin_auth_username)
    password_ok = secrets.compare_digest(supplied_hash, cfg.admin_auth_password_sha256)
    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


@app.on_event("startup")
def on_startup() -> None:
    global scheduler
    init_db()
    scheduler = start_scheduler(cfg)


@app.get("/")
def dashboard(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "targets": [{"host": t.host, "label": t.label} for t in cfg.targets]},
    )


@app.get("/admin")
def admin(request: Request, _auth: None = Depends(require_admin)):
    return templates.TemplateResponse("admin.html", {"request": request})


@app.get("/alerts")
def alerts(request: Request):
    return templates.TemplateResponse("alerts.html", {"request": request})


def _window_start(window: str) -> dt.datetime:
    now = dt.datetime.utcnow()
    mapping = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30}
    hours = mapping.get(window, 24)
    return now - dt.timedelta(hours=hours)


def _parse_client_datetime(value: Optional[str]) -> Optional[dt.datetime]:
    if not value:
        return None
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        return parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return parsed


def _time_range(window: str, start: Optional[str], end: Optional[str]) -> tuple[dt.datetime, Optional[dt.datetime]]:
    if window == "custom":
        start_dt = _parse_client_datetime(start)
        if start_dt is None:
            raise HTTPException(status_code=400, detail="custom window requires start")
        return start_dt, _parse_client_datetime(end)
    return _window_start(window), None


def _effective_path_hop(session, run_id: int):
    hops = session.query(Hop).filter(Hop.run_id == run_id).order_by(Hop.hop_num.desc()).all()
    for hop in hops:
        if hop.host != "???" and hop.avg_ms is not None and not (hop.loss_pct == 100.0 and hop.avg_ms == 0.0):
            return hop
    return hops[0] if hops else None


def _has_successful_port_check(session, run_id: int) -> bool:
    return session.query(PortCheck).filter(PortCheck.run_id == run_id, PortCheck.success.is_(True)).first() is not None


def _baseline_for_target(session, target: str, before: dt.datetime) -> dict:
    since = before - dt.timedelta(days=cfg.baseline_days)
    runs = (
        session.query(Run)
        .filter(Run.target == target, Run.timestamp >= since, Run.timestamp < before, Run.success.is_(True))
        .order_by(Run.timestamp.asc())
        .all()
    )
    latencies = []
    jitters = []
    losses = []
    for run in runs:
        hop = _effective_path_hop(session, run.id)
        if not hop:
            continue
        if hop.avg_ms is not None:
            latencies.append(hop.avg_ms)
        if hop.stdev_ms is not None:
            jitters.append(hop.stdev_ms)
        if hop.loss_pct is not None:
            losses.append(hop.loss_pct)

    return {
        "samples": len(latencies),
        "latency_ms": sum(latencies) / len(latencies) if latencies else None,
        "jitter_ms": sum(jitters) / len(jitters) if jitters else None,
        "loss_pct": sum(losses) / len(losses) if losses else None,
    }


def _pct_delta(value: float | None, baseline: float | None) -> float | None:
    if value is None or baseline is None or baseline == 0:
        return None
    return ((value - baseline) / baseline) * 100


def _json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except ValueError:
        return []


def _quality_score(run: Run, hop, ports: list[PortCheck]) -> dict:
    score = 100.0
    reasons = []

    if not run.success:
        return {"score": 0, "grade": "Down", "reasons": [run.error or "probe failed"]}

    latency = run.endpoint_avg_ms if run.endpoint_avg_ms is not None else hop.avg_ms if hop else None
    jitter = run.endpoint_jitter_ms if run.endpoint_jitter_ms is not None else hop.stdev_ms if hop else None
    loss = run.endpoint_loss_pct if run.endpoint_loss_pct is not None else hop.loss_pct if hop else None

    if latency is not None:
        if latency > 300:
            score -= 30
            reasons.append(f"high latency {latency:.0f} ms")
        elif latency > 200:
            score -= 18
            reasons.append(f"elevated latency {latency:.0f} ms")
        elif latency > 150:
            score -= 10
            reasons.append(f"latency above preferred {latency:.0f} ms")

    if jitter is not None:
        if jitter > 60:
            score -= 25
            reasons.append(f"high jitter {jitter:.0f} ms")
        elif jitter > 35:
            score -= 14
            reasons.append(f"elevated jitter {jitter:.0f} ms")
        elif jitter > 20:
            score -= 7
            reasons.append(f"jitter above preferred {jitter:.0f} ms")

    if loss is not None:
        if loss >= 5:
            score -= 35
            reasons.append(f"packet loss {loss:.1f}%")
        elif loss >= 2:
            score -= 22
            reasons.append(f"packet loss {loss:.1f}%")
        elif loss > 0:
            score -= 10
            reasons.append(f"minor loss {loss:.1f}%")

    if run.path_changed:
        score -= 8
        reasons.append("path changed")

    if run.dns_ms is not None and run.dns_ms > 250:
        score -= 5
        reasons.append(f"slow DNS {run.dns_ms:.0f} ms")

    failed_ports = [p for p in ports if not p.success]
    if failed_ports:
        score -= min(30, 15 * len(failed_ports))
        reasons.append("one or more port/TLS checks failed")

    score = max(0, min(100, round(score)))
    if score >= 90:
        grade = "Excellent"
    elif score >= 75:
        grade = "Good"
    elif score >= 60:
        grade = "Degraded"
    else:
        grade = "Poor"

    return {"score": score, "grade": grade, "reasons": reasons or ["all measured signals healthy"]}


@app.get("/api/targets")
def api_targets():
    return [_target_to_dict(t) for t in cfg.targets]


@app.post("/api/targets", status_code=201)
def api_add_target(target: TargetCreate, _auth: None = Depends(require_admin)):
    host = target.host.strip().lower()
    label = (target.label or host).strip()
    tcp_ports = sorted(set(target.tcp_ports or []))

    if any(port < 1 or port > 65535 for port in tcp_ports):
        raise HTTPException(status_code=400, detail="tcp_ports must be between 1 and 65535")
    if any(existing.host == host for existing in cfg.targets):
        raise HTTPException(status_code=409, detail="target already exists")

    new_target = TargetConfig(
        host=host,
        label=label,
        tcp_ports=tcp_ports,
        mtr_protocol=target.mtr_protocol,
        mtr_port=target.mtr_port,
        alert_latency_ms=target.alert_latency_ms,
        alert_jitter_ms=target.alert_jitter_ms,
        alert_loss_pct=target.alert_loss_pct,
        alert_path_change=target.alert_path_change,
        endpoint_probe_enabled=target.endpoint_probe_enabled,
        endpoint_probe_protocol=target.endpoint_probe_protocol,
        endpoint_probe_count=target.endpoint_probe_count,
        endpoint_probe_port=target.endpoint_probe_port,
        dscp=target.dscp,
    )
    cfg.targets.append(new_target)
    _save_targets_to_config()

    if scheduler is not None:
        schedule_target_probe(scheduler, cfg, new_target)

    return _target_to_dict(new_target)


@app.put("/api/targets/{host}")
def api_update_target(host: str, target: TargetCreate, _auth: None = Depends(require_admin)):
    normalized_host = host.strip().lower()
    existing = next((item for item in cfg.targets if item.host == normalized_host), None)
    if existing is None:
        raise HTTPException(status_code=404, detail="target not found")

    tcp_ports = sorted(set(target.tcp_ports or []))
    if any(port < 1 or port > 65535 for port in tcp_ports):
        raise HTTPException(status_code=400, detail="tcp_ports must be between 1 and 65535")

    existing.label = (target.label or existing.host).strip()
    existing.tcp_ports = tcp_ports
    existing.mtr_protocol = target.mtr_protocol
    existing.mtr_port = target.mtr_port
    existing.alert_latency_ms = target.alert_latency_ms
    existing.alert_jitter_ms = target.alert_jitter_ms
    existing.alert_loss_pct = target.alert_loss_pct
    existing.alert_path_change = target.alert_path_change
    existing.endpoint_probe_enabled = target.endpoint_probe_enabled
    existing.endpoint_probe_protocol = target.endpoint_probe_protocol
    existing.endpoint_probe_count = target.endpoint_probe_count
    existing.endpoint_probe_port = target.endpoint_probe_port
    existing.dscp = target.dscp
    _save_targets_to_config()

    if scheduler is not None:
        schedule_target_probe(scheduler, cfg, existing)

    return _target_to_dict(existing)


@app.delete("/api/targets/{host}")
def api_delete_target(host: str, delete_history: bool = Query(False), _auth: None = Depends(require_admin)):
    normalized_host = host.strip().lower()
    existing = next((target for target in cfg.targets if target.host == normalized_host), None)
    if existing is None:
        raise HTTPException(status_code=404, detail="target not found")

    cfg.targets = [target for target in cfg.targets if target.host != normalized_host]
    _save_targets_to_config()

    if scheduler is not None:
        unschedule_target_probe(scheduler, normalized_host)

    deleted_runs = _delete_target_history(normalized_host) if delete_history else 0

    return {"removed": normalized_host, "history_deleted": deleted_runs}


@app.get("/api/settings/retention")
def api_get_retention_settings(_auth: None = Depends(require_admin)):
    return {"retention_days": cfg.retention_days, "prune_interval_hours": 6}


@app.put("/api/settings/retention")
def api_update_retention_settings(settings: RetentionSettings, _auth: None = Depends(require_admin)):
    cfg.retention_days = settings.retention_days
    _save_retention_to_config()
    return api_get_retention_settings()


@app.get("/api/maintenance/stats")
def api_maintenance_stats():
    session = SessionLocal()
    try:
        return {
            "runs": session.query(Run).count(),
            "hops": session.query(Hop).count(),
            "port_checks": session.query(PortCheck).count(),
            "db_path": DB_PATH,
            "db_size_bytes": os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0,
        }
    finally:
        session.close()


@app.post("/api/maintenance/prune")
def api_maintenance_prune(retention_days: int = Query(30, ge=1, le=3650), _auth: None = Depends(require_admin)):
    session = SessionLocal()
    try:
        cutoff = dt.datetime.utcnow() - dt.timedelta(days=retention_days)
        run_ids = [run_id for (run_id,) in session.query(Run.id).filter(Run.timestamp < cutoff).all()]
        deleted = _delete_runs_by_id(session, run_ids)
        session.commit()
        return {"deleted_runs": deleted, "retention_days": retention_days}
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@app.post("/api/maintenance/vacuum")
def api_maintenance_vacuum(_auth: None = Depends(require_admin)):
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
        conn.execute(text("VACUUM"))
    return {"vacuumed": True, "db_size_bytes": os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0}


def _delete_target_history(host: str) -> int:
    session = SessionLocal()
    try:
        run_ids = [run_id for (run_id,) in session.query(Run.id).filter(Run.target == host).all()]
        deleted = _delete_runs_by_id(session, run_ids)
        session.commit()
        return deleted
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _delete_runs_by_id(session, run_ids: List[int]) -> int:
    if not run_ids:
        return 0
    session.query(PortCheck).filter(PortCheck.run_id.in_(run_ids)).delete(synchronize_session=False)
    session.query(Hop).filter(Hop.run_id.in_(run_ids)).delete(synchronize_session=False)
    deleted = session.query(Run).filter(Run.id.in_(run_ids)).delete(synchronize_session=False)
    return deleted


def _save_targets_to_config() -> None:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    raw["targets"] = [_target_to_config(target) for target in cfg.targets]

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(raw, f, sort_keys=False)


def _save_retention_to_config() -> None:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    raw["retention_days"] = cfg.retention_days

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(raw, f, sort_keys=False)


def _target_to_dict(target: TargetConfig) -> dict:
    return {
        "host": target.host,
        "label": target.label,
        "tcp_ports": target.tcp_ports,
        "mtr_protocol": target.mtr_protocol,
        "mtr_port": target.mtr_port,
        "alert_latency_ms": target.alert_latency_ms,
        "alert_jitter_ms": target.alert_jitter_ms,
        "alert_loss_pct": target.alert_loss_pct,
        "alert_path_change": target.alert_path_change,
        "endpoint_probe_enabled": target.endpoint_probe_enabled,
        "endpoint_probe_protocol": target.endpoint_probe_protocol,
        "endpoint_probe_count": target.endpoint_probe_count,
        "endpoint_probe_port": target.endpoint_probe_port,
        "dscp": target.dscp,
        "tos_byte": (target.dscp << 2) if target.dscp is not None else None,
        "effective_alerts": {
            "latency_ms": target.alert_latency_ms if target.alert_latency_ms is not None else cfg.alert_latency_ms,
            "jitter_ms": target.alert_jitter_ms if target.alert_jitter_ms is not None else cfg.alert_jitter_ms,
            "loss_pct": target.alert_loss_pct if target.alert_loss_pct is not None else cfg.alert_loss_pct,
            "path_change": target.alert_path_change if target.alert_path_change is not None else cfg.alert_path_change,
        },
        "effective_mtr": {
            "protocol": target.mtr_protocol if target.mtr_protocol is not None else cfg.mtr_protocol,
            "port": target.mtr_port if target.mtr_port is not None else cfg.mtr_port,
        },
        "effective_endpoint_probe": {
            "enabled": target.endpoint_probe_enabled if target.endpoint_probe_enabled is not None else cfg.endpoint_probe_enabled,
            "protocol": target.endpoint_probe_protocol if target.endpoint_probe_protocol is not None else cfg.endpoint_probe_protocol,
            "count": target.endpoint_probe_count if target.endpoint_probe_count is not None else cfg.endpoint_probe_count,
            "port": target.endpoint_probe_port if target.endpoint_probe_port is not None else cfg.endpoint_probe_port,
        },
    }


def _target_to_config(target: TargetConfig) -> dict:
    data = {"host": target.host, "label": target.label, "tcp_ports": target.tcp_ports}
    if target.mtr_protocol is not None:
        data["mtr_protocol"] = target.mtr_protocol
    if target.mtr_port is not None:
        data["mtr_port"] = target.mtr_port
    if target.alert_latency_ms is not None:
        data["alert_latency_ms"] = target.alert_latency_ms
    if target.alert_jitter_ms is not None:
        data["alert_jitter_ms"] = target.alert_jitter_ms
    if target.alert_loss_pct is not None:
        data["alert_loss_pct"] = target.alert_loss_pct
    if target.alert_path_change is not None:
        data["alert_path_change"] = target.alert_path_change
    if target.endpoint_probe_enabled is not None:
        data["endpoint_probe_enabled"] = target.endpoint_probe_enabled
    if target.endpoint_probe_protocol is not None:
        data["endpoint_probe_protocol"] = target.endpoint_probe_protocol
    if target.endpoint_probe_count is not None:
        data["endpoint_probe_count"] = target.endpoint_probe_count
    if target.endpoint_probe_port is not None:
        data["endpoint_probe_port"] = target.endpoint_probe_port
    if target.dscp is not None:
        data["dscp"] = target.dscp
    return data


@app.get("/api/status")
def api_status(
    target: str,
    latency_warning_ms: float = Query(150.0),
    latency_critical_ms: float = Query(300.0),
    loss_warning_pct: float = Query(2.0),
    loss_critical_pct: float = Query(10.0),
):
    """RAG (green/amber/red) rollup for a target, for external monitoring dashboards."""
    session = SessionLocal()
    try:
        run = session.query(Run).filter(Run.target == target).order_by(Run.timestamp.desc()).first()
        if not run:
            return {"status": "unknown", "status_text": "No data yet", "target": target}

        if not run.success:
            return {
                "status": "red",
                "status_text": run.error or "DNS/probe failure",
                "target": target,
                "timestamp": run.timestamp.isoformat() + "Z",
            }

        last_hop = _effective_path_hop(session, run.id)
        avg_ms = last_hop.avg_ms if last_hop else None
        loss_pct = last_hop.loss_pct if last_hop else None
        jitter_ms = last_hop.stdev_ms if last_hop else None
        port_reachable = _has_successful_port_check(session, run.id)
        ports = session.query(PortCheck).filter(PortCheck.run_id == run.id).all()
        quality = _quality_score(run, last_hop, ports)

        status = "green"
        reasons = []
        if not port_reachable:
            status = "red"
            reasons.append("service port unreachable")
        elif loss_pct is not None and loss_pct >= loss_critical_pct:
            status = "red"
            reasons.append(f"{loss_pct:.1f}% loss")
        elif avg_ms is not None and avg_ms >= latency_critical_ms:
            status = "red"
            reasons.append(f"{avg_ms:.0f}ms latency")
        elif loss_pct is not None and loss_pct >= loss_warning_pct:
            status = "amber"
            reasons.append(f"{loss_pct:.1f}% loss")
        elif avg_ms is not None and avg_ms >= latency_warning_ms:
            status = "amber"
            reasons.append(f"{avg_ms:.0f}ms latency")

        status_text = "OK" if status == "green" else "; ".join(reasons)

        return {
            "status": status,
            "status_text": status_text,
            "target": target,
            "resolved_ip": run.resolved_ip,
            "reverse_dns_name": run.reverse_dns_name,
            "reverse_dns_match": run.reverse_dns_match,
            "reverse_dns_error": run.reverse_dns_error,
            "public_dns_ips": _json_list(run.public_dns_ips),
            "public_dns_status": run.public_dns_status,
            "dns_validation_warning": run.dns_validation_warning,
            "dns_sinkhole_match": run.dns_sinkhole_match,
            "dns_sinkhole_range": run.dns_sinkhole_range,
            "dest_avg_ms": avg_ms,
            "dest_loss_pct": loss_pct,
            "dest_jitter_ms": jitter_ms,
            "endpoint_probe_protocol": run.endpoint_probe_protocol,
            "endpoint_avg_ms": run.endpoint_avg_ms,
            "endpoint_loss_pct": run.endpoint_loss_pct,
            "endpoint_jitter_ms": run.endpoint_jitter_ms,
            "service_reachable": port_reachable,
            "quality": quality,
            "path_changed": bool(run.path_changed),
            "hop_count": last_hop.hop_num if last_hop else None,
            "timestamp": run.timestamp.isoformat() + "Z",
        }
    finally:
        session.close()


@app.get("/api/latest")
def api_latest():
    session = SessionLocal()
    try:
        out = []
        for t in cfg.targets:
            run = (
                session.query(Run)
                .filter(Run.target == t.host)
                .order_by(Run.timestamp.desc())
                .first()
            )
            if not run:
                out.append({"target": t.host, "label": t.label, "status": "no data"})
                continue

            last_hop = _effective_path_hop(session, run.id)
            baseline = _baseline_for_target(session, t.host, run.timestamp)
            ports = session.query(PortCheck).filter(PortCheck.run_id == run.id).all()
            quality = _quality_score(run, last_hop, ports)
            out.append(
                {
                    "target": t.host,
                    "label": t.label,
                    "timestamp": run.timestamp.isoformat() + "Z",
                    "resolved_ip": run.resolved_ip,
                    "reverse_dns_name": run.reverse_dns_name,
                    "reverse_dns_match": run.reverse_dns_match,
                    "reverse_dns_error": run.reverse_dns_error,
                    "public_dns_ips": _json_list(run.public_dns_ips),
                    "public_dns_status": run.public_dns_status,
                    "dns_validation_warning": run.dns_validation_warning,
                    "dns_sinkhole_match": run.dns_sinkhole_match,
                    "dns_sinkhole_range": run.dns_sinkhole_range,
                    "dns_ms": run.dns_ms,
                    "success": run.success,
                    "error": run.error,
                    "hop_count": last_hop.hop_num if last_hop else None,
                    "dest_avg_ms": last_hop.avg_ms if last_hop else None,
                    "dest_loss_pct": last_hop.loss_pct if last_hop else None,
                    "dest_jitter_ms": last_hop.stdev_ms if last_hop else None,
                    "endpoint_probe_protocol": run.endpoint_probe_protocol,
                    "endpoint_avg_ms": run.endpoint_avg_ms,
                    "endpoint_loss_pct": run.endpoint_loss_pct,
                    "endpoint_jitter_ms": run.endpoint_jitter_ms,
                    "endpoint_error": run.endpoint_error,
                    "quality": quality,
                    "path_changed": bool(run.path_changed),
                    "baseline": baseline,
                    "latency_deviation_pct": _pct_delta(last_hop.avg_ms if last_hop else None, baseline["latency_ms"]),
                    "jitter_deviation_pct": _pct_delta(last_hop.stdev_ms if last_hop else None, baseline["jitter_ms"]),
                    "ports": [
                        {
                            "protocol": p.protocol,
                            "port": p.port,
                            "success": p.success,
                            "latency_ms": p.latency_ms,
                            "error": p.error,
                        }
                        for p in ports
                    ],
                }
            )
        return out
    finally:
        session.close()


@app.get("/api/alerts")
def api_alerts(limit: int = Query(50, ge=1, le=500), recent_minutes: Optional[int] = Query(None, ge=1, le=10080)):
    session = SessionLocal()
    try:
        query = session.query(AlertEvent)
        if recent_minutes is not None:
            cutoff = dt.datetime.utcnow() - dt.timedelta(minutes=recent_minutes)
            query = query.filter(AlertEvent.timestamp >= cutoff)
        events = query.order_by(AlertEvent.timestamp.desc()).limit(limit).all()
        return [
            {
                "id": event.id,
                "target": event.target,
                "timestamp": event.timestamp.isoformat() + "Z",
                "severity": event.severity,
                "kind": event.kind,
                "message": event.message,
                "details": json.loads(event.details) if event.details else {},
                "run_id": event.run_id,
            }
            for event in events
        ]
    finally:
        session.close()


@app.delete("/api/alerts")
def api_clear_alerts(_auth: None = Depends(require_admin)):
    session = SessionLocal()
    try:
        deleted = session.query(AlertEvent).delete(synchronize_session=False)
        session.commit()
        return {"deleted_alerts": deleted}
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@app.get("/api/summary")
def api_summary(target: str, window: str = "24h", start: Optional[str] = None, end: Optional[str] = None):
    """Time series of destination (last hop) latency + loss for charting."""
    session = SessionLocal()
    try:
        since, until = _time_range(window, start, end)
        query = session.query(Run).filter(Run.target == target, Run.timestamp >= since)
        if until is not None:
            query = query.filter(Run.timestamp <= until)
        runs = query.order_by(Run.timestamp.asc()).all()
        points = []
        for run in runs:
            last_hop = _effective_path_hop(session, run.id)
            points.append(
                {
                    "timestamp": run.timestamp.isoformat() + "Z",
                    "dns_ms": run.dns_ms,
                    "hop_count": last_hop.hop_num if last_hop else None,
                    "avg_ms": last_hop.avg_ms if last_hop else None,
                    "loss_pct": last_hop.loss_pct if last_hop else None,
                    "jitter_ms": last_hop.stdev_ms if last_hop else None,
                    "endpoint_avg_ms": run.endpoint_avg_ms,
                    "endpoint_loss_pct": run.endpoint_loss_pct,
                    "endpoint_jitter_ms": run.endpoint_jitter_ms,
                    "success": run.success,
                }
            )
        return points
    finally:
        session.close()


@app.get("/api/runs")
def api_runs(target: str, window: str = "24h", limit: int = 200, start: Optional[str] = None, end: Optional[str] = None):
    session = SessionLocal()
    try:
        since, until = _time_range(window, start, end)
        query = session.query(Run).filter(Run.target == target, Run.timestamp >= since)
        if until is not None:
            query = query.filter(Run.timestamp <= until)
        runs = query.order_by(Run.timestamp.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() + "Z",
                "resolved_ip": r.resolved_ip,
                "reverse_dns_name": r.reverse_dns_name,
                "reverse_dns_match": r.reverse_dns_match,
                "reverse_dns_error": r.reverse_dns_error,
                "public_dns_ips": _json_list(r.public_dns_ips),
                "public_dns_status": r.public_dns_status,
                "dns_validation_warning": r.dns_validation_warning,
                "dns_sinkhole_match": r.dns_sinkhole_match,
                "dns_sinkhole_range": r.dns_sinkhole_range,
                "dns_ms": r.dns_ms,
                "success": r.success,
                "error": r.error,
                "endpoint_probe_protocol": r.endpoint_probe_protocol,
                "endpoint_avg_ms": r.endpoint_avg_ms,
                "endpoint_loss_pct": r.endpoint_loss_pct,
                "endpoint_jitter_ms": r.endpoint_jitter_ms,
            }
            for r in runs
        ]
    finally:
        session.close()


@app.get("/api/runs/{run_id}/hops")
def api_run_hops(run_id: int):
    session = SessionLocal()
    try:
        run = session.get(Run, run_id)
        if not run:
            raise HTTPException(status_code=404, detail="run not found")
        hops = session.query(Hop).filter(Hop.run_id == run_id).order_by(Hop.hop_num.asc()).all()
        return [
            {
                "hop_num": h.hop_num,
                "host": h.host,
                "loss_pct": h.loss_pct,
                "sent": h.sent,
                "last_ms": h.last_ms,
                "avg_ms": h.avg_ms,
                "best_ms": h.best_ms,
                "worst_ms": h.worst_ms,
                "stdev_ms": h.stdev_ms,
                "asn": h.asn,
                "org": h.org,
                "country": h.country,
                "city": h.city,
            }
            for h in hops
        ]
    finally:
        session.close()


@app.get("/api/export.csv")
def api_export_csv(target: str, window: str = "24h", start: Optional[str] = None, end: Optional[str] = None):
    session = SessionLocal()
    try:
        since, until = _time_range(window, start, end)
        query = session.query(Run).filter(Run.target == target, Run.timestamp >= since)
        if until is not None:
            query = query.filter(Run.timestamp <= until)
        runs = query.order_by(Run.timestamp.asc()).all()

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "timestamp", "target", "resolved_ip", "dns_sinkhole_match", "dns_sinkhole_range", "dns_validation_warning", "dns_ms", "success", "error", "hop_count",
                "dest_avg_ms", "dest_loss_pct", "dest_jitter_ms", "endpoint_probe_protocol",
                "endpoint_avg_ms", "endpoint_loss_pct", "endpoint_jitter_ms",
            ]
        )
        for run in runs:
            last_hop = _effective_path_hop(session, run.id)
            writer.writerow(
                [
                    run.timestamp.isoformat() + "Z",
                    run.target,
                    run.resolved_ip,
                    run.dns_sinkhole_match if run.dns_sinkhole_match is not None else "",
                    run.dns_sinkhole_range or "",
                    run.dns_validation_warning or "",
                    run.dns_ms,
                    run.success,
                    run.error or "",
                    last_hop.hop_num if last_hop else "",
                    last_hop.avg_ms if last_hop else "",
                    last_hop.loss_pct if last_hop else "",
                    last_hop.stdev_ms if last_hop else "",
                    run.endpoint_probe_protocol or "",
                    run.endpoint_avg_ms if run.endpoint_avg_ms is not None else "",
                    run.endpoint_loss_pct if run.endpoint_loss_pct is not None else "",
                    run.endpoint_jitter_ms if run.endpoint_jitter_ms is not None else "",
                ]
            )

        buf.seek(0)
        filename = f"{target}_{window}.csv"
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    finally:
        session.close()
