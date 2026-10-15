"""Scan orchestrator: expand -> execute (bounded) -> verdict -> findings -> summary."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Any, Callable, Dict, List

import httpx

from app.schemas.policy import Finding, ScanOptions, TestResult
from app.services.engine import testcase_gen
from app.services.engine.analyzers import consistency_findings, finding_from_failure, infer_category
from app.services.engine.executor import build_headers, execute_one
from app.services.engine.ownership import body_shows_resource, decide_verdict


async def run_scan(
    base: str,
    endpoints: list,
    identities: list,
    options: ScanOptions,
    progress_cb: Callable[[int, int], None] | None = None,
) -> tuple[List[TestResult], List[Finding], Dict[str, Any]]:
    started = time.perf_counter()
    cases = testcase_gen.expand_cases(endpoints, identities, options.include_destructive)
    ep_by_id = {e.id: e for e in endpoints}
    sem = asyncio.Semaphore(max(1, options.max_concurrency))
    results: List[TestResult] = []
    total = len(cases)
    done = 0

    async with httpx.AsyncClient(headers={"User-Agent": "authz-tester/1.0"}) as client:
        async def one(c: Dict[str, Any]) -> TestResult:
            nonlocal done
            async with sem:
                if options.rate_delay_secs:
                    await asyncio.sleep(options.rate_delay_secs)
                ep = c["endpoint"]
                ident = c["identity"]
                headers = build_headers(ident.auth_state.value, ident.token, ep.headers)
                out = await execute_one(
                    client, base, ep.method, c["path_rendered"], headers,
                    ep.params, ep.safe_payload, options.timeout_secs,
                )
                # leak check for deny-expected other-variant accesses (per-endpoint override aware)
                over = (ident.resources or {}).get(ep.id, {}) if getattr(ident, "resources", None) else {}
                target_rid = over.get("other" if c["variant"] == "other" else "own",
                                      ident.other_resource_id if c["variant"] == "other" else ident.own_resource_id)
                leak = body_shows_resource(out.get("body", ""), target_rid, ident.name) if c["expected"] == "deny" else False
                verdict, reason = decide_verdict(c["expected"], out.get("status"), out.get("error", ""), leak)
                tr = TestResult(
                    test_id=c["test_id"], endpoint_id=ep.id, method=ep.method,
                    path_rendered=c["path_rendered"], identity=ident.name, role=ident.role,
                    auth_state=ident.auth_state.value, resource_variant=c["variant"],
                    expected=c["expected"], actual_status=out.get("status"),
                    verdict=verdict, leak_detected=leak,  # type: ignore
                    body_excerpt=(out.get("body", "") or "")[:800],
                    body_keys=out.get("body_keys", []),
                    duration_ms=out.get("duration_ms", 0), error=reason if verdict != "pass" else "",
                    evidence={"expected": c["expected"], "reason": reason},
                )
                done += 1
                if progress_cb:
                    try:
                        progress_cb(done, total)
                    except Exception:
                        pass
                return tr

        # bounded gather preserving order
        results = await asyncio.gather(*[one(c) for c in cases])

    # findings from failures
    findings: List[Finding] = []
    for r in results:
        if r.verdict != "fail":
            continue
        meta = ep_by_id.get(r.endpoint_id)
        cat = infer_category(r, bool(meta and meta.ownership_required), (meta.sensitivity if meta else "private"))
        if cat is None:
            continue
        # expected-allow failures are lower signal: keep but mark suspicious/info-ish via severity rules
        findings.append(finding_from_failure(r, cat, (meta.sensitivity if meta else "private"), r.path_rendered))

    # consistency layer
    try:
        findings.extend(consistency_findings(list(results), {e.id: e.model_dump() for e in endpoints}))
    except Exception:
        pass

    duration = time.perf_counter() - started
    summary = summarize(list(results), list(findings), duration)
    return list(results), findings, summary


def summarize(results: List[TestResult], findings: List[Finding], duration: float) -> Dict[str, Any]:
    by_sev: Dict[str, int] = {}
    by_cat: Dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1
    by_ep: Dict[str, Dict[str, int]] = {}
    for r in results:
        d = by_ep.setdefault(r.endpoint_id, {"pass": 0, "fail": 0, "inconclusive": 0})
        d[r.verdict.value] = d.get(r.verdict.value, 0) + 1
    now = datetime.utcnow().isoformat() + "Z"
    return {
        "total": len(results),
        "passed": sum(1 for r in results if r.verdict.value == "pass"),
        "failed": sum(1 for r in results if r.verdict.value == "fail"),
        "inconclusive": sum(1 for r in results if r.verdict.value == "inconclusive"),
        "by_severity": by_sev, "by_category": by_cat, "by_endpoint": by_ep,
        "duration_secs": round(duration, 2), "started_at": now, "finished_at": now,
    }
