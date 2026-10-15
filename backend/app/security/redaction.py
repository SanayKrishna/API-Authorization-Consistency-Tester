"""Redact secrets from logs, evidence, and reports."""
from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEYS = {
    "authorization", "token", "access_token", "refresh_token", "password",
    "secret", "api_key", "apikey", "set-cookie", "cookie", "jwt",
}

BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/=]+", re.IGNORECASE)


def redact_headers(headers: dict) -> dict:
    out: dict[str, Any] = {}
    for k, v in (headers or {}).items():
        if k.lower() in SENSITIVE_KEYS:
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out


def redact_text(text: str) -> str:
    if not text:
        return text
    red = BEARER_RE.sub(r"\1***REDACTED***", text)
    # redact long jwt-looking blobs
    red = re.sub(r"eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}", "***REDACTED-JWT***", red)
    return red[:2000]


def redact_dict(d: Any) -> Any:
    if isinstance(d, dict):
        return {k: ("***REDACTED***" if k.lower() in SENSITIVE_KEYS else redact_dict(v)) for k, v in d.items()}
    if isinstance(d, list):
        return [redact_dict(x) for x in d]
    if isinstance(d, str):
        return redact_text(d)
    return d
