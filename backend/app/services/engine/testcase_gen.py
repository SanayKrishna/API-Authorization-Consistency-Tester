"""Deterministic test-case expansion: endpoint x identity x auth-state x resource."""
from __future__ import annotations

from typing import Any, Dict, List

from app.schemas.policy import EndpointPolicy, IdentityConfig


def _has_id_param(path: str) -> bool:
    return "{id}" in path or "{user_id}" in path or "{order_id}" in path or "{resource_id}" in path


def expected_outcome(ep: EndpointPolicy, ident: IdentityConfig) -> str:
    """Compute expected allow/deny purely from configured policy (no hardcoding of roles)."""
    auth = ident.auth_state.value
    if ep.requires_auth and auth in ("missing", "invalid", "expired"):
        return "deny"
    if ep.requires_auth and ident.role in ("none", "anonymous", ""):
        return "deny"
    if not ep.requires_auth and auth in ("invalid", "expired"):
        # invalid creds on public endpoint: still allow (public), but auth-specific
        # tests treat these as informational — policy says public, so allow.
        return "allow"
    if ep.allowed_roles and ident.role not in ep.allowed_roles:
        # 'none' role never allowed on protected endpoints
        return "deny"
    return "allow"


def render_path(path: str, own_id: str | None, other_id: str | None, variant: str) -> str:
    rid = own_id if variant == "own" else other_id
    out = path
    for token in ("{id}", "{user_id}", "{order_id}", "{resource_id}"):
        if token in out:
            out = out.replace(token, rid or "unknown-id")
    return out


def _ids_for(endpoint_id: str, ident: IdentityConfig, variant: str) -> tuple[str | None, str | None, str]:
    """Per-endpoint override wins, else generic own/other ids."""
    over = (ident.resources or {}).get(endpoint_id, {})
    own = over.get("own", ident.own_resource_id)
    other = over.get("other", ident.other_resource_id)
    return own, other, variant


def expand_cases(
    endpoints: List[EndpointPolicy],
    identities: List[IdentityConfig],
    include_destructive: bool,
) -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    for ep in endpoints:
        is_write = ep.method in ("POST", "PUT", "PATCH", "DELETE")
        if is_write and not include_destructive:
            continue  # destructive tests require explicit opt-in
        for ident in identities:
            own_id, other_id, _ = _ids_for(ep.id, ident, "x")
            variants = ["n/a"]
            if _has_id_param(ep.path) and (own_id or other_id):
                variants = []
                if own_id:
                    variants.append("own")
                if other_id:
                    variants.append("other")
                if not variants:
                    variants = ["n/a"]
            for variant in variants:
                # ownership rule: non-admin accessing other's resource on ownership endpoints -> deny
                exp = expected_outcome(ep, ident)
                if (
                    ep.ownership_required
                    and variant == "other"
                    and ident.role != "admin"
                    and exp == "allow"
                ):
                    exp = "deny"
                own_v, other_v, _ = _ids_for(ep.id, ident, variant)
                path_rendered = render_path(ep.path, own_v, other_v, variant)
                test_id = f"{ep.id}::{ep.method}::{ident.name}:{ident.auth_state.value}::{variant}"
                cases.append(
                    {
                        "test_id": test_id,
                        "endpoint": ep,
                        "identity": ident,
                        "variant": variant,
                        "path_rendered": path_rendered,
                        "expected": exp,
                    }
                )
    return cases
