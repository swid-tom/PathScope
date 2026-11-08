"""Shared database queries for effective path measurements."""
from __future__ import annotations

import datetime as dt

from app.db import Hop, PortCheck, Run


def effective_path_hop(session, run_id: int) -> Hop | None:
    return effective_path_hops(session, [run_id]).get(run_id)


def effective_path_hops(session, run_ids: list[int]) -> dict[int, Hop]:
    if not run_ids:
        return {}

    grouped: dict[int, list[Hop]] = {}
    for offset in range(0, len(run_ids), 900):
        run_id_batch = run_ids[offset : offset + 900]
        hops = (
            session.query(Hop)
            .filter(Hop.run_id.in_(run_id_batch))
            .order_by(Hop.run_id.asc(), Hop.hop_num.desc())
            .all()
        )
        for hop in hops:
            grouped.setdefault(hop.run_id, []).append(hop)

    effective: dict[int, Hop] = {}
    for run_id, run_hops in grouped.items():
        effective[run_id] = next(
            (
                hop
                for hop in run_hops
                if hop.host != "???"
                and hop.avg_ms is not None
                and not (hop.loss_pct == 100.0 and hop.avg_ms == 0.0)
            ),
            run_hops[0],
        )
    return effective


def service_reachability(run: Run, ports: list[PortCheck]) -> bool | None:
    if ports:
        return any(port.success for port in ports)
    if run.endpoint_probe_protocol:
        return run.endpoint_avg_ms is not None and run.endpoint_error is None
    return None


def classify_status(
    avg_ms: float | None,
    loss_pct: float | None,
    reachable: bool | None,
    latency_warning_ms: float,
    latency_critical_ms: float,
    loss_warning_pct: float,
    loss_critical_pct: float,
) -> tuple[str, list[str]]:
    status = "green"
    reasons = []
    if reachable is False:
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
    return status, reasons


def baseline_for_target(
    session, target: str, before: dt.datetime, baseline_days: int
) -> dict[str, int | float | None]:
    since = before - dt.timedelta(days=baseline_days)
    runs = (
        session.query(Run)
        .filter(
            Run.target == target,
            Run.timestamp >= since,
            Run.timestamp < before,
            Run.success.is_(True),
        )
        .order_by(Run.timestamp.asc())
        .all()
    )
    hops = effective_path_hops(session, [run.id for run in runs])
    latencies = []
    jitters = []
    losses = []
    for run in runs:
        hop = hops.get(run.id)
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


def quality_score(run: Run, hop: Hop | None, ports: list[PortCheck]) -> dict:
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

    failed_ports = [port for port in ports if not port.success]
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
