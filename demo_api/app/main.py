"""Isolated local demonstration API with synthetic users + 3 documented intentional vulns.

VULNERABILITIES (local-only, see VULNS.md):
  V1 BOLA:      GET /vuln/orders/{id}            — no ownership check (secure twin: GET /api/orders/{id})
  V2 MISSING AUTH: GET /vuln/admin-export       — no auth check (secure twin: GET /api/admin/stats)
  V3 INCONSISTENT: PATCH /api/users/{id}        — missing ownership check (secure twin: PUT /api/users/{id})
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

SECRET = os.getenv("DEMO_JWT_SECRET", "local-demo-secret-do-not-use-in-prod")
EXP_MIN = int(os.getenv("DEMO_JWT_EXP_MINUTES", "60"))

app = FastAPI(title="Demo API (intentionally vulnerable lab)", version="1.0.0")

USERS: Dict[str, dict] = {
    "u_admin": {"id": "u_admin", "name": "Admin", "role": "admin", "email": "admin@lab.local"},
    "u_alice": {"id": "u_alice", "name": "Alice", "role": "user", "email": "alice@lab.local"},
    "u_bob": {"id": "u_bob", "name": "Bob", "role": "user", "email": "bob@lab.local"},
    "u_ro": {"id": "u_ro", "name": "Reader", "role": "readonly", "email": "reader@lab.local"},
}
ORDERS: Dict[str, dict] = {
    "o_alice1": {"id": "o_alice1", "owner_id": "u_alice", "item": "book", "total": 29},
    "o_bob1": {"id": "o_bob1", "owner_id": "u_bob", "item": "lamp", "total": 49},
}


def mint(sub: str, role: str, minutes: int = EXP_MIN) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": sub, "role": role, "iat": now,
                       "exp": now + timedelta(minutes=minutes)}, SECRET, algorithm="HS256")


def _auth(authorization: Optional[str]) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing Authorization")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="malformed Authorization (expected Bearer <token>)")
    tok = parts[1]
    if tok == "invalid-token-for-testing":
        raise HTTPException(status_code=401, detail="invalid token")
    if tok == "expired-token-for-testing":
        raise HTTPException(status_code=401, detail="token expired")
    try:
        payload = jwt.decode(tok, SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")
    user = USERS.get(payload.get("sub", ""))
    if not user:
        raise HTTPException(status_code=401, detail="unknown subject")
    # role in token must match stored role (prevents role tampering demo)
    return {"id": user["id"], "role": user["role"], "token_role": payload.get("role")}


def _require_roles(me: dict, *roles: str) -> None:
    if me["role"] not in roles:
        raise HTTPException(status_code=403, detail=f"role {me['role']} not permitted")


@app.get("/demo/tokens")
def demo_tokens() -> dict:
    return {
        "admin": {"token": mint("u_admin", "admin"), "own_resource_id": "u_admin", "other_resource_id": "u_alice"},
        "alice": {"token": mint("u_alice", "user"), "own_resource_id": "u_alice", "other_resource_id": "u_bob"},
        "bob": {"token": mint("u_bob", "user"), "own_resource_id": "u_bob", "other_resource_id": "u_alice"},
        "readonly": {"token": mint("u_ro", "readonly"), "own_resource_id": "u_ro", "other_resource_id": "u_alice"},
        "note": "Tokens are short-lived local-lab JWTs only.",
    }


@app.get("/api/public/info")
def public_info() -> dict:
    return {"service": "demo-lab", "public": True}


@app.get("/api/users/me")
def users_me(authorization: Optional[str] = Header(default=None)) -> dict:
    me = _auth(authorization)
    u = USERS[me["id"]]
    return {"id": u["id"], "name": u["name"], "role": u["role"], "email": u["email"]}


@app.get("/api/users/{uid}")
def get_user(uid: str, authorization: Optional[str] = Header(default=None)) -> dict:
    me = _auth(authorization)
    target = USERS.get(uid)
    if not target:
        raise HTTPException(status_code=404, detail="not found")
    if me["role"] != "admin" and uid != me["id"]:
        raise HTTPException(status_code=403, detail="not owner")
    return {"id": target["id"], "name": target["name"], "role": target["role"],
            "email": target["email"], "owner_id": target["id"]}


@app.put("/api/users/{uid}")
async def put_user(uid: str, request: Request, authorization: Optional[str] = Header(default=None)) -> dict:
    me = _auth(authorization)
    _require_roles(me, "admin", "user")
    if me["role"] != "admin" and uid != me["id"]:
        raise HTTPException(status_code=403, detail="not owner")
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    target = USERS.get(uid)
    if not target:
        raise HTTPException(status_code=404, detail="not found")
    if isinstance(body, dict) and "name" in body:
        target["name"] = str(body["name"])[:50]
    return {"ok": True, "id": uid}


@app.patch("/api/users/{uid}")
async def patch_user(uid: str, request: Request, authorization: Optional[str] = Header(default=None)) -> dict:
    """V3 INTENTIONAL VULN: ownership check missing (PUT enforces it, PATCH does not)."""
    me = _auth(authorization)
    _require_roles(me, "admin", "user")
    # BUG: no `uid != me[id]` check here (compare with PUT above)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    target = USERS.get(uid)
    if not target:
        raise HTTPException(status_code=404, detail="not found")
    if isinstance(body, dict) and "name" in body:
        target["name"] = str(body["name"])[:50]
    return {"ok": True, "id": uid, "owner_id": target["id"]}


@app.get("/api/admin/stats")
def admin_stats(authorization: Optional[str] = Header(default=None)) -> dict:
    me = _auth(authorization)
    _require_roles(me, "admin")
    return {"users": len(USERS), "orders": len(ORDERS)}


@app.get("/api/orders/{oid}")
def get_order(oid: str, authorization: Optional[str] = Header(default=None)) -> dict:
    me = _auth(authorization)
    o = ORDERS.get(oid)
    if not o:
        raise HTTPException(status_code=404, detail="not found")
    if me["role"] != "admin" and o["owner_id"] != me["id"]:
        raise HTTPException(status_code=403, detail="not owner")
    return dict(o)


@app.get("/vuln/orders/{oid}")
def vuln_get_order(oid: str, authorization: Optional[str] = Header(default=None)) -> dict:
    """V1 INTENTIONAL VULN (BOLA): any authenticated user can read anyone's order."""
    _auth(authorization)  # auth enforced, ownership NOT enforced
    o = ORDERS.get(oid)
    if not o:
        raise HTTPException(status_code=404, detail="not found")
    return dict(o)


@app.get("/vuln/admin-export")
def vuln_admin_export() -> dict:
    """V2 INTENTIONAL VULN: no authentication at all on sensitive export."""
    return {"users": [dict(USERS[k]) for k in USERS], "orders": [dict(ORDERS[k]) for k in ORDERS]}
