"""JSON/CSV/HTML report builders. Tokens never included."""
from __future__ import annotations

import csv
import html
import io
from typing import List

from app.schemas.policy import Finding, ScanRecord, TestResult


def scan_to_json_dict(scan: ScanRecord) -> dict:
    return scan.model_dump()


def findings_to_csv(findings: List[Finding]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["finding_id", "endpoint_id", "method", "path", "category", "severity",
                "confidence", "expected", "actual", "explanation", "remediation", "fingerprint"])
    for f in findings:
        w.writerow([f.finding_id, f.endpoint_id, f.method, f.path, f.category.value,
                    f.severity.value, f.confidence.value, f.expected, f.actual,
                    f.explanation, f.remediation, f.fingerprint])
    return buf.getvalue()


def results_to_csv(results: List[TestResult]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["test_id", "endpoint_id", "method", "path", "identity", "role", "auth_state",
                "variant", "expected", "actual_status", "verdict", "leak", "duration_ms", "error"])
    for r in results:
        w.writerow([r.test_id, r.endpoint_id, r.method, r.path_rendered, r.identity, r.role,
                    r.auth_state, r.resource_variant, r.expected, r.actual_status or "",
                    r.verdict.value, r.leak_detected, r.duration_ms, r.error[:200]])
    return buf.getvalue()


def scan_to_html(scan: ScanRecord) -> str:
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(f.finding_id)}</td><td>{e(f.endpoint_id)} {e(f.method)}</td>"
        f"<td>{e(f.category.value)}</td><td><b>{e(f.severity.value)}</b></td>"
        f"<td>{e(f.expected)}</td><td>{e(f.actual)}</td></tr>"
        for f in scan.findings
    )
    trows = "".join(
        f"<tr><td>{e(r.test_id[:80])}</td><td>{e(r.expected)}</td>"
        f"<td>{e(str(r.actual_status))}</td><td>{e(r.verdict.value)}</td></tr>"
        for r in scan.results[:200]
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>AuthZ Scan {e(scan.scan_id)}</title>
<style>body{{font-family:system-ui,Arial,sans-serif;margin:24px;color:#1a1a1a}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border:1px solid #ddd;padding:6px;text-align:left}}
.badge{{display:inline-block;padding:2px 8px;border:1px solid #ccc;border-radius:4px;margin-right:8px}}</style>
</head><body>
<h2>Authorization Scan Report — {e(scan.scan_id)}</h2>
<p>Target: {e(scan.target_base_url)} · Status: {e(scan.status)} · Duration: {e(str(scan.summary.duration_secs))}s</p>
<p><span class="badge">Total {scan.summary.total}</span><span class="badge">Passed {scan.summary.passed}</span>
<span class="badge">Failed {scan.summary.failed}</span><span class="badge">Inconclusive {scan.summary.inconclusive}</span></p>
<h3>Findings ({len(scan.findings)})</h3>
<table><tr><th>ID</th><th>Endpoint</th><th>Category</th><th>Severity</th><th>Expected</th><th>Actual</th></tr>{rows}</table>
<h3>Test results (first 200)</h3>
<table><tr><th>Test</th><th>Expected</th><th>Status</th><th>Verdict</th></tr>{trows}</table>
<p><small>Tokens redacted. Generated locally by API Authorization Consistency Tester.</small></p>
</body></html>"""
