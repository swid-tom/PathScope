"""TLS connect + handshake timing."""
from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional, Tuple


def tls_check(hostname: str, ip: str, port: int = 443, timeout: float = 3.0, tos: int | None = None) -> Tuple[bool, Optional[float], Optional[str]]:
    start = time.perf_counter()
    context = ssl.create_default_context()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if tos is not None:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
            sock.connect((ip, port))
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                elapsed_ms = (time.perf_counter() - start) * 1000
                expiry = cert.get("notAfter") if cert else None
                if expiry:
                    expires_at = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expires_at - datetime.now(timezone.utc)).days
                    if days_left < 14:
                        return True, elapsed_ms, f"certificate expires in {days_left} days"
                return True, elapsed_ms, None
    except (OSError, ssl.SSLError, ValueError) as e:
        return False, None, str(e)
