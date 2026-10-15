"""Finding builders + cross-endpoint consistency analysis (policy-aware, not naive diff)."""
from __future__ import annotations

import hashlib
from typing import Dict, List

from app.schemas.policy import Finding, TestResult
from app.services.engine.severity import classify


def fingerprint(endpoint_id: str, method: str, category: str, identity: str, variant: str) -> str:
    raw = f"{endpoint_id}|{method}|{category}|{identity}|{variant}".encode()
    return hashlib.sha256(raw).hexdigest()[:12]


def finding_from_failure(
    r: TestResult, category: str, sensitivity: str, path: str,
) -> Finding:
    sev, conf, remediation = classify(category, sensitivity, r.method, r.auth_state, r.leak_detected)
    fid = f"{category[:4].upper()}-{r.test_id[-6:]}-{fingerprint(r.endpoint_id, r.method, category, r.identity, r.resource_variant)[:4].upper()}"
    # category enum mapping
    cat_map = {
        "BOLA": "BOLA", "IDOR": "IDOR", "BrokenAccessControl": "BrokenAccessControl",
        "Authentication": "Authentication", "RoleEnforcement": "RoleEnforcement",
        "Consistency": "Consistency", "InfoExposure": "InfoExposure",
    }
    expected_txt = f"Policy expects DENY for {r.identity} ({r.role}/{r.auth_state}) on {r.method} {path}"
    if r.expected == "allow":
        expected_txt = f"Policy expects ALLOW for {r.identity} ({r.role}/{r.auth_state}) on {r.method} {path}"
    actual_txt = f"HTTP {r.actual_status}" if r.actual_status else f"No response ({r.error or 'unknown'})"
    if r.leak_detected:
        actual_txt += " + protected data in body"
    return Finding(
        finding_id=fid,
        endpoint_id=r.endpoint_id,
        method=r.method,
        path=path,
        category=cat_map.get(category, "BrokenAccessControl"),  # type: ignore
        severity=sev,  # type: ignore
        confidence=conf,  # type: ignore
        expected=expected_txt,
        actual=actual_txt,
        explanation=_explain(category, r),
        reproduction=[
            f"Send {r.method} {path}",
            f"As identity '{r.identity}' (role={r.role}, auth={r.auth_state})",
            f"Expected: {r.expected.upper()}, got: {actual_txt}",
        ],
        evidence={"test_id": r.test_id, "status": r.actual_status, "leak": r.leak_detected,
                  "body_excerpt": r.body_excerpt[:500], "body_keys": r.body_keys},
        remediation=remediation,
        fingerprint=fingerprint(r.endpoint_id, r.method, category, r.identity, r.resource_variant),
    )


def _explain(category: str, r: TestResult) -> str:
    if category in ("BOLA", "IDOR"):
        return (f"User '{r.identity}' accessed resource variant '{r.resource_variant}' that the policy "
                f"reserves for its owner. Expected DENY, observed HTTP {r.actual_status} with data disclosure."
                if r.leak_detected else
                f"User '{r.identity}' received HTTP {r.actual_status} where policy expects DENY (variant {r.resource_variant}).")
    if category == "Authentication":
        return f"Endpoint accepted {r.auth_state} credentials (HTTP {r.actual_status}); must return 401."
    if category == "RoleEnforcement":
        return f"Role '{r.role}' was granted access denied by allowed_roles (HTTP {r.actual_status})."
    if category == "Consistency":
        return "Related endpoints/methods enforce different outcomes for the same protected resource."
    return f"Access-control violation: expected {r.expected.upper()}, got HTTP {r.actual_status}."


def infer_category(r: TestResult, ownership_required: bool, sensitivity: str) -> str | None:
    """Only called for FAIL verdicts. Returns None if not a finding (e.g. allow-expected failure is availability, still a finding)."""
    if r.verdict != "fail":
        return None
    if r.expected == "deny":
        if r.resource_variant == "other" and ownership_required:
            return "BOLA"
        if r.auth_state in ("missing", "invalid", "expired"):
            # unauth access to protected resource
            if sensitivity == "admin":
                return "BrokenAccessControl"
            return "Authentication" if r.auth_state in ("invalid", "expired") else "BrokenAccessControl"
        if sensitivity == "admin":
            return "BrokenAccessControl"
        if r.resource_variant == "other":
            return "IDOR"
        return "RoleEnforcement"
    # expected allow but denied -> still report as role/authN issue (availability-relevant, not vuln)
    if r.auth_state in ("missing", "invalid", "expired"):
        return "Authentication"
    return "RoleEnforcement"


def consistency_findings(results: List[TestResult], ep_meta: Dict[str, dict]) -> List[Finding]:
    """Compare outcomes across related endpoints/methods only when policy demands same outcome."""
    out: List[Finding] = []
    # group by (resource identity key): use body-agnostic grouping by other_resource target?
    # Simplest robust invariant: same identity+variant across PUT vs PATCH on same path family,
    # and same identity across secure vs vuln endpoints flagged by differing verdicts where both deny-expected.
    by_key: Dict[str, List[TestResult]] = {}
    for r in results:
        # family = path without trailing id
        fam = r.path_rendered.rsplit("/", 1)[0] if "/" in r.path_rendered else r.path_rendered
        key = f"{r.identity}|{r.resource_variant}|{fam}"
        by_key.setdefault(key, []).append(r)
    n = 0
    for key, group in by_key.items():
        denies = [g for g in group if g.expected == "deny"]
        if len(denies) < 2:
            continue
        verdicts = {g.verdict for g in denies}
        if verdicts == {"pass"} or verdicts == {"fail"}:
            continue  # consistent
        # mixed pass/fail on same resource+identity where both should deny => inconsistency
        passes = [g for g in denies if g.verdict == "pass"]
        fails = [g for g in denies if g.verdict == "fail"]
        if passes and fails:
            n += 1
            f0 = fails[0]
            sev, conf, rem = classify("Consistency", "private", f0.method, f0.auth_state, f0.leak_detected)
            out.append(Finding(
                finding_id=f"CONS-{n:03d}",
                endpoint_id=f0.endpoint_id,
                method=f0.method,
                path=f0.path_rendered,
                category="Consistency",  # type: ignore
                severity=sev,  # type: ignore
                confidence="suspicious",  # type: ignore
                expected=f"Consistent DENY for {f0.identity} on resource family '{key.split('|')[-1]}' (variant {f0.resource_variant})",
                actual=f"{fails[0].endpoint_id} allowed (HTTP {fails[0].actual_status}) while {passes[0].endpoint_id} denied (HTTP {passes[0].actual_status})",
                explanation=(f"Identity '{f0.identity}' is denied on one endpoint but allowed on a related endpoint "
                             f"for the same resource. One handler enforces the policy, the other does not."),
                reproduction=[
                    f"Compare {fails[0].method} {fails[0].path_rendered} (allowed, HTTP {fails[0].actual_status})",
                    f"with {passes[0].method} {passes[0].path_rendered} (denied, HTTP {passes[0].actual_status})",
                    f"as '{f0.identity}'",
                ],
                evidence={"group": key, "allowed": [x.test_id for x in fails], "denied": [x.test_id for x in passes]},
                remediation=rem,
                fingerprint=fingerprint("consistency", "MULTI", "Consistency", f0.identity, f0.resource_variant),
            ))
            if n >= 10:
                break
    return out
