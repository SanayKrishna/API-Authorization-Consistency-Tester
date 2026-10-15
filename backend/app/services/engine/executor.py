"""HTTP execution with timeouts, SSRF revalidation, no auto-redirect to foreign hosts."""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

import httpx

from app.schemas.policy import AuthState
from app.security.redaction import redact_dict, redact_headers
from app.security.target_validator import validate_request_url


def build_headers(identity_auth: str, token: Optional[str], extra: Dict[str, str]) -> Dict[str, str]:
    h = dict(extra or {})
    if identity_auth == AuthState.MISSING.value:
        h.pop("Authorization", None)
        return h
    if identity_auth == AuthState.INVALID.value:
        h["Authorization"] = "Bearer invalid-token-for-testing"
        return h
    if identity_auth == AuthState.EXPIRED.value:
        h["Authorization"] = "Bearer expired-token-for-testing"
        return h
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


async def execute_one(
    client: httpx.AsyncClient,
    base: str,
    method: str,
    path_rendered: str,
    headers: Dict[str, str],
    params: Dict[str, str],
    payload: Optional[Dict[str, Any]],
    timeout_secs: float,
) -> Dict[str, Any]:
    url = base.rstrip("/") + "/" + path_rendered.lstrip("/")
    try:
        validate_request_url(url, base)
    except ValueError as e:
        return {"status": None, "body": "", "body_keys": [], "error": f"blocked: {e}", "duration_ms": 0}
    t0 = time.perf_counter()
    try:
        resp = await client.request(
            method, url, headers=headers, params=params or None,
            json=payload if method in ("POST", "PUT", "PATCH") else None,
            timeout=timeout_secs, follow_redirects=False,
        )
        # Manual same-origin redirect handling (max 2), revalidated
        hops = 0
        while resp.status_code in (301, 302, 303, 307, 308) and hops < 2:
            loc = resp.headers.get("location", "")
            if not loc:
                break
            nxt = loc if loc.startswith("http") else base.rstrip("/") + "/" + loc.lstrip("/")
            try:
                validate_request_url(nxt, base)
            except ValueError as e:
                return {"status": resp.status_code, "body": "", "body_keys": [],
                        "error": f"redirect blocked: {e}", "duration_ms": int((time.perf_counter() - t0) * 1000)}
            resp = await client.request(method, nxt, headers=headers, timeout=timeout_secs, follow_redirects=False)
            hops += 1
        dur = int((time.perf_counter() - t0) * 1000)
        ctype = resp.headers.get("content-type", "")
        body_text = resp.text[:4000] if resp.text else ""
        keys: list[str] = []
        try:
            if "json" in ctype:
                j = resp.json()
                red = redact_dict(j)
                import json as _json
                body_text = _json.dumps(red)[:4000]
                if isinstance(j, dict):
                    keys = sorted(list(j.keys()))[:20]
        except Exception:
            pass
        return {"status": resp.status_code, "body": body_text, "body_keys": keys,
                "error": "", "duration_ms": dur,
                "safe_headers": redact_headers(dict(resp.headers))}
    except httpx.TimeoutException:
        return {"status": None, "body": "", "body_keys": [], "error": "timeout", "duration_ms": int((time.perf_counter() - t0) * 1000)}
    except httpx.ConnectError as e:
        return {"status": None, "body": "", "body_keys": [], "error": f"connection failed: {type(e).__name__}", "duration_ms": int((time.perf_counter() - t0) * 1000)}
    except Exception as e:
        return {"status": None, "body": "", "body_keys": [], "error": f"{type(e).__name__}: {str(e)[:200]}", "duration_ms": int((time.perf_counter() - t0) * 1000)}
