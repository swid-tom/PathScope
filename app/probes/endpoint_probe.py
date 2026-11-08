"""Final-destination endpoint probes independent of MTR path discovery."""
from __future__ import annotations

import re
import statistics
import subprocess
from typing import Optional, Tuple

from app.probes.port_probe import tcp_check


PingResult = Tuple[bool, Optional[float], Optional[float], Optional[float], Optional[str]]


def icmp_ping(ip: str, count: int = 5, timeout: float = 3.0, tos: int | None = None) -> PingResult:
    """Return (success, avg_ms, loss_pct, jitter_ms, error). Linux ping parser."""
    cmd = ["ping", "-c", str(count), "-W", str(int(timeout)), ip]
    if tos is not None:
        cmd[1:1] = ["-Q", str(tos)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max(timeout * count + 2, 5), check=False)
    except subprocess.TimeoutExpired:
        return False, None, 100.0, None, "ping timed out"
    except FileNotFoundError:
        return False, None, None, None, "ping binary not found"

    output = result.stdout + result.stderr
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", output)
    loss_pct = float(loss_match.group(1)) if loss_match else None

    rtt_match = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", output)
    avg_ms = float(rtt_match.group(2)) if rtt_match else None
    jitter_ms = float(rtt_match.group(4)) if rtt_match else None

    success = avg_ms is not None and (loss_pct is None or loss_pct < 100)
    error = None if success else (output.strip().splitlines()[-1] if output.strip() else "no ping response")
    return success, avg_ms, loss_pct, jitter_ms, error


def tcp_probe(ip: str, port: int = 443, count: int = 5, timeout: float = 3.0, tos: int | None = None) -> PingResult:
    """Return (success, avg_ms, loss_pct, jitter_ms, error) from repeated TCP connects."""
    samples: list[float] = []
    errors: list[str] = []

    for _ in range(count):
        ok, latency_ms, error = tcp_check(ip, port, timeout=timeout, tos=tos)
        if ok and latency_ms is not None:
            samples.append(latency_ms)
        elif error:
            errors.append(error)

    sent = max(count, 1)
    lost = sent - len(samples)
    loss_pct = (lost / sent) * 100
    avg_ms = statistics.mean(samples) if samples else None
    jitter_ms = statistics.pstdev(samples) if len(samples) > 1 else 0.0 if samples else None
    success = bool(samples)
    return success, avg_ms, loss_pct, jitter_ms, None if success else "; ".join(errors[-2:]) or "no TCP responses"
