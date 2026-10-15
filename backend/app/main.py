"""FastAPI backend: policy validation, scan lifecycle, reports, regression diff."""
from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import ValidationError

load_dotenv()

from app.schemas.policy import (  # noqa: E402
    DiffEntry,
    EndpointPolicy,
    ScanRecord,
    ScanRequest,
    ScanSummary,
)
from app.security.target_validator import validate_base_url  # noqa: E402
from app.services.engine import reporter, scanner  # noqa: E402
from app.store import file_store  # noqa: E402

app = FastAPI(title="API Authorization Consistency Tester", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "authz-tester"}


@app.post("/api/policy/validate")
def validate_policy(payload: Dict[str, Any]) -> Dict[str, Any]:
    endpoints = payload.get("endpoints", payload if isinstance(payload, list) else [])
    try:
        parsed = [EndpointPolicy.model_validate(e) for e in endpoints]
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())
    return {"valid": True, "count": len(parsed), "ids": [p.id for p in parsed]}


def _strip_tokens(req: ScanRequest) -> Dict[str, Any]:
    d = req.model_dump()
    for ident in d.get("identities", []):
        if ident.get("token"):
            ident["token"] = "***REDACTED***"
    return d


async def _run_scan_task(scan_id: str, req: ScanRequest, base: str) -> None:
    scan = file_store.get(scan_id)
    if not scan:
        return
    try:
        def progress(done: int, total: int) -> None:
            s = file_store.get(scan_id)
            if s:
                s.progress = {"done": done, "total": total}
                file_store.save(s)

        # env defaults applied when client leaves zeros
        if not req.options.timeout_secs:
            req.options.timeout_secs = float(os.getenv("SCAN_TIMEOUT_SECS", "10"))
        results, findings, summary = await scanner.run_scan(
            base, req.endpoints, req.identities, req.options, progress_cb=progress
        )
        s = file_store.get(scan_id)
        if s:
            s.results = results
            s.findings = findings
            s.summary = ScanSummary.model_validate(summary)
            s.status = "completed"
            s.progress = {"done": len(results), "total": len(results)}
            file_store.save(s)
    except Exception as e:
        s = file_store.get(scan_id)
        if s:
            s.status = "failed"
            s.progress = {"error": str(e)[:300]}
            file_store.save(s)


@app.post("/api/scans", status_code=202)
async def create_scan(req: ScanRequest, background: BackgroundTasks) -> Dict[str, Any]:
    if not req.confirm_target:
        raise HTTPException(status_code=400, detail="Target confirmation required (confirm_target=true).")
    try:
        base, _host = validate_base_url(req.target_base_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # destructive guard
    wants_write = any(e.method in ("POST", "PUT", "PATCH", "DELETE") for e in req.endpoints)
    if wants_write and not req.options.include_destructive:
        raise HTTPException(
            status_code=400,
            detail="Scan includes state-changing methods but include_destructive=false. "
                   "Re-submit with options.include_destructive=true to opt in.",
        )
    scan_id = "scan-" + uuid.uuid4().hex[:8]
    scan = ScanRecord(
        scan_id=scan_id, target_base_url=base, status="running",
        progress={"done": 0, "total": 0}, config_echo=_strip_tokens(req),
    )
    file_store.save(scan)
    background.add_task(_run_scan_task, scan_id, req, base)
    # also ensure task runs even if BackgroundTasks timing differs in tests
    asyncio.get_event_loop().call_soon_threadsafe(lambda: None) if False else None
    return {"scan_id": scan_id, "status": "running", "target": base}


@app.get("/api/scans")
def list_scans() -> Dict[str, Any]:
    scans = file_store.list_all()
    return {"scans": [
        {"scan_id": s.scan_id, "target": s.target_base_url, "status": s.status,
         "summary": s.summary.model_dump(), "created_at": s.created_at,
         "findings": len(s.findings)} for s in scans
    ]}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> Dict[str, Any]:
    s = file_store.get(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="scan not found")
    return s.model_dump()


@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str, severity: Optional[str] = None, category: Optional[str] = None,
                 q: Optional[str] = None) -> Dict[str, Any]:
    s = file_store.get(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="scan not found")
    out = s.findings
    if severity:
        out = [f for f in out if f.severity.value.lower() == severity.lower()]
    if category:
        out = [f for f in out if f.category.value.lower() == category.lower()]
    if q:
        ql = q.lower()
        out = [f for f in out if ql in (f.endpoint_id + f.path + f.explanation + f.finding_id).lower()]
    return {"findings": [f.model_dump() for f in out], "total": len(out)}


@app.get("/api/scans/{scan_id}/report.json")
def report_json(scan_id: str) -> Dict[str, Any]:
    s = file_store.get(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="scan not found")
    return reporter.scan_to_json_dict(s)


@app.get("/api/scans/{scan_id}/report.csv")
def report_csv(scan_id: str, kind: str = Query(default="findings")) -> PlainTextResponse:
    s = file_store.get(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="scan not found")
    if kind == "results":
        return PlainTextResponse(reporter.results_to_csv(s.results), media_type="text/csv",
                                 headers={"Content-Disposition": f"attachment; filename={scan_id}-results.csv"})
    return PlainTextResponse(reporter.findings_to_csv(s.findings), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={scan_id}-findings.csv"})


@app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: str) -> str:
    s = file_store.get(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="scan not found")
    return reporter.scan_to_html(s)


@app.get("/api/scans/{scan_id}/diff")
def diff_scan(scan_id: str, against: str = Query(description="previous scan id")) -> Dict[str, Any]:
    cur = file_store.get(scan_id)
    prev = file_store.get(against)
    if not cur or not prev:
        raise HTTPException(status_code=404, detail="scan not found (need both scan_id and against)")
    prev_fp = {f.fingerprint: f for f in prev.findings}
    cur_fp = {f.fingerprint: f for f in cur.findings}
    entries: List[Dict[str, Any]] = []
    for fp, f in cur_fp.items():
        entries.append(DiffEntry(fingerprint=fp, status="new" if fp not in prev_fp else "unchanged", finding=f).model_dump())
    for fp, f in prev_fp.items():
        if fp not in cur_fp:
            entries.append(DiffEntry(fingerprint=fp, status="resolved", finding=f).model_dump())
    new_n = sum(1 for e in entries if e["status"] == "new")
    res_n = sum(1 for e in entries if e["status"] == "resolved")
    return {"scan_id": scan_id, "against": against, "new": new_n, "resolved": res_n,
            "unchanged": len(entries) - new_n - res_n, "entries": entries}


@app.get("/api/demo/info")
def demo_info() -> Dict[str, Any]:
    return {
        "demo_url": os.getenv("DEMO_API_URL", "http://127.0.0.1:8001"),
        "note": "Use demo_api tokens via GET {demo}/demo/tokens. Never use real credentials.",
    }
