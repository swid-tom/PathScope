"""DNS resolution timing."""
from __future__ import annotations

import socket
import time
from typing import List, Optional, Tuple


def resolve(host: str) -> Tuple[List[str], Optional[float], Optional[str]]:
    """Return (ip_list, elapsed_ms, error)."""
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        elapsed_ms = (time.perf_counter() - start) * 1000
        ips = sorted({info[4][0] for info in infos})
        return ips, elapsed_ms, None
    except socket.gaierror as e:
        return [], None, str(e)

