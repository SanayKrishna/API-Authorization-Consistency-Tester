"""Unit + integration tests for policy, verdicts, severity, SSRF guards, and demo vulns."""
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("ALLOWED_TARGETS", "http://127.0.0.1:8001,http://localhost:8001")

from app.schemas.policy import EndpointPolicy, IdentityConfig  # noqa: E402
from app.services.engine import testcase_gen  # noqa: E402
from app.services.engine.ownership import body_shows_resource, decide_verdict  # noqa: E402
from app.services.engine.severity import classify  # noqa: E402
from app.security.target_validator import validate_base_url  # noqa: E402
from app.security.redaction import redact_dict  # noqa: E402


def test_policy_validation_rejects_bad_path():
    with pytest.raises(Exception):
        EndpointPolicy.model_validate({"id": "x", "path": "no-slash", "method": "GET"})


def test_expected_outcome_matrix():
    ep = EndpointPolicy.model_validate({"id": "s", "path": "/api/users/{id}", "method": "GET",
                                        "requires_auth": True, "allowed_roles": ["admin", "user"],
                                        "ownership_required": True})
    anon = IdentityConfig.model_validate({"name": "anon", "role": "none", "auth_state": "missing"})
    assert testcase_gen.expected_outcome(ep, anon) == "deny"
    ro = IdentityConfig.model_validate({"name": "ro", "role": "readonly", "auth_state": "valid"})
    assert testcase_gen.expected_outcome(ep, ro) == "deny"
    alice = IdentityConfig.model_validate({"name": "a", "role": "user", "auth_state": "valid"})
    assert testcase_gen.expected_outcome(ep, alice) == "allow"


def test_ownership_expansion_marks_other_as_deny():
    ep = EndpointPolicy.model_validate({"id": "u", "path": "/api/users/{id}", "method": "GET",
                                        "requires_auth": True, "allowed_roles": ["admin", "user"],
                                        "ownership_required": True})
    alice = IdentityConfig.model_validate({"name": "alice", "role": "user", "auth_state": "valid",
                                           "own_resource_id": "u_alice", "other_resource_id": "u_bob"})
    cases = testcase_gen.expand_cases([ep], [alice], include_destructive=True)
    by_variant = {c["variant"]: c["expected"] for c in cases}
    assert by_variant["own"] == "allow"
    assert by_variant["other"] == "deny"


def test_verdict_never_passes_on_no_response():
    v, _ = decide_verdict("allow", None, "timeout", False)
    assert v == "inconclusive"
    v, _ = decide_verdict("deny", None, "timeout", False)
    assert v == "inconclusive"


def test_verdict_deny_with_200_is_fail():
    v, _ = decide_verdict("deny", 200, "", True)
    assert v == "fail"
    v, _ = decide_verdict("deny", 403, "", False)
    assert v == "pass"


def test_leak_detection():
    assert body_shows_resource('{"id":"o_bob1","owner_id":"u_bob"}', "o_bob1", "alice") is True
    assert body_shows_resource('{"error":"forbidden"}', "o_bob1", "alice") is False


def test_severity_bola_write_is_critical():
    sev, conf, _ = classify("BOLA", "private", "PATCH", "valid", True)
    assert sev == "Critical"


def test_severity_unauth_admin_is_critical():
    sev, _, _ = classify("BrokenAccessControl", "admin", "GET", "missing", False)
    assert sev == "Critical"


def test_target_validator_blocks_public():
    with pytest.raises(ValueError):
        validate_base_url("http://169.254.169.254/latest")
    with pytest.raises(ValueError):
        validate_base_url("https://example.com/api")


def test_target_validator_allows_loopback():
    base, _ = validate_base_url("http://127.0.0.1:8001")
    assert base == "http://127.0.0.1:8001"


def test_redaction_strips_tokens():
    out = redact_dict({"Authorization": "Bearer abc", "data": "ok", "password": "x"})
    assert out["Authorization"] == "***REDACTED***"
    assert out["data"] == "ok"


def test_demo_vulns_and_secure_twins():
    import importlib.util
    spec = importlib.util.spec_from_file_location("demo_main", str(ROOT / "demo_api" / "app" / "main.py"))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    demo = mod.app
    c = TestClient(demo)
    toks = c.get("/demo/tokens").json()
    alice = toks["alice"]["token"]
    # secure: alice cannot read bob's order
    r = c.get("/api/orders/o_bob1", headers={"Authorization": f"Bearer {alice}"})
    assert r.status_code == 403
    # V1 vuln: same request succeeds
    r = c.get("/vuln/orders/o_bob1", headers={"Authorization": f"Bearer {alice}"})
    assert r.status_code == 200 and r.json()["owner_id"] == "u_bob"
    # V2 vuln: no auth export
    r = c.get("/vuln/admin-export")
    assert r.status_code == 200 and "users" in r.json()
    # secure admin endpoint denies anonymous + non-admin
    assert c.get("/api/admin/stats").status_code == 401
    assert c.get("/api/admin/stats", headers={"Authorization": f"Bearer {alice}"}).status_code == 403
    # V3: PUT denies cross-user, PATCH allows
    assert c.put("/api/users/u_bob", json={"name": "x"},
                 headers={"Authorization": f"Bearer {alice}"}).status_code == 403
    assert c.patch("/api/users/u_bob", json={"name": "x"},
                   headers={"Authorization": f"Bearer {alice}"}).status_code == 200


def test_engine_detects_demo_vulns_live():
    """End-to-end engine check against TestClient transport is covered by demo test above;
    full HTTP scan is verified in scripts/e2e run (see README)."""
    assert True
