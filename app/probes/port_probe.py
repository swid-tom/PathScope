"""TCP connect-timing and best-effort UDP reachability via STUN (RFC 5389)."""
from __future__ import annotations

import os
import socket
import struct
import time
from typing import Optional, Tuple

STUN_MAGIC_COOKIE = 0x2112A442


def _apply_tos(sock: socket.socket, tos: int | None) -> None:
    if tos is not None:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)


def tcp_check(ip: str, port: int, timeout: float = 3.0, tos: int | None = None) -> Tuple[bool, Optional[float], Optional[str]]:
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            _apply_tos(sock, tos)
            sock.connect((ip, port))
        return True, (time.perf_counter() - start) * 1000, None
    except (socket.timeout, OSError) as e:
        return False, None, str(e)


def _build_stun_binding_request() -> bytes:
    msg_type = 0x0001  # Binding Request
    msg_len = 0
    transaction_id = os.urandom(12)
    return struct.pack("!HHI12s", msg_type, msg_len, STUN_MAGIC_COOKIE, transaction_id)


def stun_check(ip: str, port: int = 3478, timeout: float = 2.0, tos: int | None = None) -> Tuple[bool, Optional[float], Optional[str]]:
    """Send a real STUN Binding Request over UDP and measure round-trip time.

    Only meaningful if the target actually speaks STUN/TURN on this port.
    """
    request = _build_stun_binding_request()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    _apply_tos(sock, tos)
    start = time.perf_counter()
    try:
        sock.sendto(request, (ip, port))
        data, _ = sock.recvfrom(2048)
        if len(data) < 20:
            return False, None, "malformed STUN response"
        elapsed_ms = (time.perf_counter() - start) * 1000
        return True, elapsed_ms, None
    except socket.timeout:
        return False, None, "timeout (no STUN response)"
    except OSError as e:
        return False, None, str(e)
    finally:
        sock.close()
