"""SSRF-safe target validation: localhost/lab-only, DNS+IP checks, redirect revalidation."""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


def _env_allow_list() -> list[str]:
    raw = os.getenv("ALLOWED_TARGETS", "http://127.0.0.1:8001,http://localhost:8001")
    return [x.strip() for x in raw.split(",") if x.strip()]


def _allow_private() -> bool:
    return os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() in ("1", "true", "yes")


def _is_loopback_or_allowed_host(host: str) -> bool:
    h = (host or "").lower().strip().lstrip("[").rstrip("]")
    if h in ("localhost", "127.0.0.1", "::1"):
        return True
    for allowed in _env_allow_list():
        try:
            ah = (urlparse(allowed).hostname or "").lower()
            if ah and ah == h:
                return True
        except Exception:
            continue
    return False


def _ip_blocked(ip: ipaddress._BaseAddress, allow_private: bool) -> bool:
    if ip.is_loopback:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    # link-local 169.254.x.x (cloud metadata) always blocked
    try:
        if ip.is_link_local:
            return True
    except Exception:
        pass
    if not allow_private and (
        ip.is_private
        or getattr(ip, "is_global", False) is False
        and not ip.is_loopback
    ):
        # Conservative: anything non-loopback is blocked unless explicitly allowed
        # when ALLOW_PRIVATE_TARGETS=false. Public scans require explicit opt-in too.
        return True
    return False


def validate_base_url(url: str) -> tuple[str, str]:
    """Validate the scan's base target. Returns (normalized_base, host).

    Raises ValueError with a safe-alternative hint on failure.
    """
    if not url or not isinstance(url, str):
        raise ValueError("target_base_url is required (e.g. http://127.0.0.1:8001)")
    u = url.strip()
    p = urlparse(u)
    if p.scheme not in ("http", "https"):
        raise ValueError("target must use http(s); got %r. Use http://127.0.0.1:8001 for local labs." % p.scheme)
    if not p.hostname:
        raise ValueError("target URL must include a host, e.g. http://127.0.0.1:8001")
    if p.username or p.password:
        raise ValueError("credentials must not be embedded in the target URL")
    host = p.hostname
    if not _is_loopback_or_allowed_host(host):
        raise ValueError(
            f"target host {host!r} is not permitted. Scanning is restricted to localhost and "
            f"ALLOWED_TARGETS={_env_allow_list()}. Add your isolated lab host to ALLOWED_TARGETS "
            "only if you are authorized to test it."
        )
    allow_private = _allow_private()
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80))
    except socket.gaierror as e:
        raise ValueError(f"cannot resolve target host {host!r}: {e}") from e
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str.lstrip("[").rstrip("]"))
        except ValueError:
            raise ValueError(f"unparsable DNS result {ip_str!r} for {host!r}; refusing to scan")
        if _ip_blocked(ip, allow_private):
            raise ValueError(
                f"resolved IP {ip} for {host!r} is blocked (SSRF protection). "
                "Use 127.0.0.1/localhost or set ALLOW_PRIVATE_TARGETS=true only for an isolated lab."
            )
    normalized = f"{p.scheme}://{host}"
    if p.port:
        normalized += f":{p.port}"
    return normalized.rstrip("/"), host


def validate_request_url(full_url: str, base: str) -> str:
    """Revalidate each outgoing request URL (redirect/SSRF guard)."""
    p = urlparse(full_url)
    b = urlparse(base)
    if p.scheme not in ("http", "https"):
        raise ValueError(f"blocked non-http(s) request destination: {p.scheme}")
    if (p.hostname or "").lower() != (b.hostname or "").lower() or p.scheme != b.scheme:
        raise ValueError(
            f"redirect/off-base request to {full_url!r} blocked: only {base} is approved for this scan"
        )
    # re-resolve IP for DNS-rebinding protection
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or 80)
        allow_private = _allow_private()
        for info in infos:
            ip = ipaddress.ip_address(info[4][0].lstrip("[").rstrip("]"))
            if _ip_blocked(ip, allow_private):
                raise ValueError(f"request IP {ip} blocked (DNS rebinding guard)")
    except socket.gaierror as e:
        raise ValueError(f"cannot resolve {p.hostname!r}: {e}") from e
    return full_url
