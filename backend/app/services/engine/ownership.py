"""Verdict + ownership-leak detection. Status codes alone are not proof."""
from __future__ import annotations

import json
from typing import Tuple


def body_shows_resource(body: str, resource_id: str | None, identity_name: str | None) -> bool:
    if not body or not resource_id or resource_id == "unknown-id":
        return False
    # direct id presence in redacted body is evidence of data disclosure
    if resource_id in body:
        return True
    try:
        j = json.loads(body)
        blob = json.dumps(j).lower()
        if resource_id.lower() in blob:
            return True
        # owner fields present at all suggests record disclosure
        if isinstance(j, dict) and any(k in j for k in ("owner_id", "owner", "user_id", "email", "profile")):
            return True
        if isinstance(j, list) and j:
            return True
    except Exception:
        pass
    return False


def decide_verdict(expected: str, status: int | None, error: str, leak: bool) -> Tuple[str, str]:
    """Returns (verdict, reason). Never mark incomplete tests as passed."""
    if error and error.startswith("blocked:"):
        return "inconclusive", error
    if status is None:
        return "inconclusive", error or "no response"
    if expected == "allow":
        if 200 <= status < 300:
            return "pass", f"allowed as expected (HTTP {status})"
        if status == 404:
            return "inconclusive", "resource not found (HTTP 404) — check fixture IDs; cannot determine authZ outcome"
        if status in (401, 403):
            return "fail", f"denied (HTTP {status}) but policy expects allow — authN vs authZ to triage"
        return "fail", f"unexpected HTTP {status} for allowed request"
    # expected deny
    if status in (401, 403):
        return "pass", f"denied as expected (HTTP {status})"
    if status == 404:
        # 404 can be hiding existence — treat as pass only if no leak, else suspicious
        if leak:
            return "fail", "HTTP 404 but response body discloses protected data"
        return "pass", "denied/hidden as expected (HTTP 404)"
    if 200 <= status < 300:
        if leak:
            return "fail", f"unexpected access (HTTP {status}) with protected data disclosure"
        return "fail", f"unexpected access (HTTP {status}) — policy expects deny"
    if status >= 500:
        return "inconclusive", f"server error HTTP {status}; cannot determine authZ outcome"
    return "fail", f"unexpected HTTP {status} for denied request"
