"""Run mtr in report/JSON mode and parse hop statistics."""
from __future__ import annotations

import json
import subprocess
from typing import List, Optional, Tuple

Hub = dict


def run_mtr(
    host: str,
    count: int = 5,
    timeout: int = 60,
    protocol: str = "tcp",
    port: int = 443,
    tos: int | None = None,
) -> Tuple[Optional[List[Hub]], Optional[str]]:
    """Return (hops, error). hops is a list of mtr 'hubs' dicts, or None on failure."""
    cmd = ["mtr", "--report", "--report-cycles", str(count), "--json", "--no-dns"]
    if protocol == "tcp":
        cmd.extend(["--tcp", "-P", str(port)])
    elif protocol == "udp":
        cmd.extend(["--udp", "-P", str(port)])
    elif protocol == "icmp":
        pass
    if tos is not None:
        cmd.extend(["-Q", str(tos)])
    cmd.append(host)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return None, f"mtr timed out after {timeout}s"
    except FileNotFoundError:
        return None, "mtr binary not found (install mtr-tiny in the container)"

    if result.returncode != 0 and not result.stdout.strip():
        return None, result.stderr.strip() or f"mtr exited with code {result.returncode}"

    try:
        data = json.loads(result.stdout)
        hubs = data["report"]["hubs"]
    except (json.JSONDecodeError, KeyError) as e:
        return None, f"failed to parse mtr output: {e}"

    return hubs, None
