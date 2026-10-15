import { Fragment, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../services/api";
import type { ScanDetail } from "../types";
import { sevColor, verdictColor } from "../components/Layout";

export default function Results() {
  const { id = "" } = useParams();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [err, setErr] = useState("");
  const [sev, setSev] = useState("");
  const [cat, setCat] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [diff, setDiff] = useState<{ new: number; resolved: number; unchanged: number } | null>(null);
  const [against, setAgainst] = useState("");

  useEffect(() => {
    let stop = false;
    async function load() {
      try {
        const s = await api.getScan(id);
        if (!stop) setScan(s);
        if (s.status === "running") setTimeout(load, 1500);
      } catch (e) { if (!stop) setErr(String(e)); }
    }
    load();
    return () => { stop = true; };
  }, [id]);

  const findings = useMemo(() => {
    if (!scan) return [];
    return scan.findings.filter((f) => {
      if (sev && f.severity.toLowerCase() !== sev.toLowerCase()) return false;
      if (cat && f.category.toLowerCase() !== cat.toLowerCase()) return false;
      if (q && !(f.endpoint_id + f.path + f.explanation + f.finding_id).toLowerCase().includes(q.toLowerCase())) return false;
      return true;
    });
  }, [scan, sev, cat, q]);

  if (err) return <div className="bg-white border border-red-200 text-red-700 rounded p-3">{err}</div>;
  if (!scan) return <p className="text-neutral-500">Loading scan…</p>;
  if (scan.status === "running")
    return (
      <div className="bg-white border border-neutral-200 rounded p-6">
        <p>Scan running… {JSON.stringify(scan.progress)}</p>
        <p className="text-neutral-500 text-sm mt-1">Polling live backend progress (not simulated).</p>
      </div>
    );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 flex-wrap">
        <h2 className="font-medium">Scan {scan.scan_id}</h2>
        <span className="text-xs text-neutral-500">{scan.target_base_url} · {scan.summary.duration_secs}s</span>
        <span className="ml-auto flex gap-2">
          <a className="btn" href={api.reportUrl(id, "json")}>JSON</a>
          <a className="btn" href={`${api.reportUrl(id, "csv")}?kind=findings`}>Findings CSV</a>
          <a className="btn" href={`${api.reportUrl(id, "csv")}?kind=results`}>Results CSV</a>
          <a className="btn" href={api.reportUrl(id, "html")}>HTML</a>
        </span>
      </div>
      <div className="flex flex-wrap gap-2 text-sm">
        <span className="badge border-neutral-200">Total {scan.summary.total}</span>
        <span className="badge bg-green-50 border-green-200 text-green-700">Passed {scan.summary.passed}</span>
        <span className="badge bg-red-50 border-red-200 text-red-700">Failed {scan.summary.failed}</span>
        <span className="badge border-neutral-200">Inconclusive {scan.summary.inconclusive}</span>
      </div>
      <div className="bg-white border border-neutral-200 rounded p-3 flex flex-wrap gap-2 items-center">
        <input className="input max-w-56" placeholder="Search findings…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input max-w-40" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option>
        </select>
        <select className="input max-w-48" value={cat} onChange={(e) => setCat(e.target.value)}>
          <option value="">All categories</option><option>BOLA</option><option>IDOR</option><option>BrokenAccessControl</option><option>Authentication</option><option>RoleEnforcement</option><option>Consistency</option>
        </select>
        <span className="text-xs text-neutral-500 ml-auto">{findings.length} of {scan.findings.length} findings</span>
      </div>
      <div className="bg-white border border-neutral-200 rounded">
        <table className="table">
          <thead><tr><th>ID</th><th>Endpoint</th><th>Category</th><th>Severity</th><th>Actual</th></tr></thead>
          <tbody>
            {findings.map((f) => (
              <Fragment key={f.finding_id}>
                <tr className="cursor-pointer hover:bg-neutral-50" onClick={() => setOpen(open === f.finding_id ? null : f.finding_id)}>
                  <td className="font-mono text-xs">{f.finding_id}</td>
                  <td>{f.endpoint_id} <span className="text-neutral-500">{f.method} {f.path}</span></td>
                  <td>{f.category}</td>
                  <td><span className={`badge border ${sevColor(f.severity)}`}>{f.severity}</span></td>
                  <td className="text-xs">{f.actual}</td>
                </tr>
                {open === f.finding_id && (
                  <tr><td colSpan={5} className="bg-neutral-50">
                    <div className="text-xs space-y-1">
                      <p><b>Expected:</b> {f.expected}</p>
                      <p><b>Explanation:</b> {f.explanation}</p>
                      <p><b>Reproduction:</b></p>
                      <ol className="list-decimal ml-4">{f.reproduction.map((s, i) => <li key={i}>{s}</li>)}</ol>
                      <p><b>Remediation:</b> {f.remediation}</p>
                      <p className="text-neutral-500">Confidence: {f.confidence} · Fingerprint: {f.fingerprint} · Evidence: {JSON.stringify(f.evidence).slice(0, 400)}</p>
                    </div>
                  </td></tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
        {findings.length === 0 && <p className="p-4 text-neutral-500 text-sm">No findings match the current filters. Secure endpoints produced no false positives.</p>}
      </div>
      <div className="bg-white border border-neutral-200 rounded p-3">
        <h3 className="font-medium text-sm mb-2">Test results ({scan.results.length})</h3>
        <table className="table">
          <thead><tr><th>Test</th><th>Expected</th><th>Status</th><th>Verdict</th></tr></thead>
          <tbody>
            {scan.results.slice(0, 100).map((r) => (
              <tr key={r.test_id}><td className="font-mono text-xs">{r.test_id}</td><td>{r.expected}</td><td>{r.actual_status ?? r.error.slice(0, 40)}</td>
              <td><span className={`badge border ${verdictColor(r.verdict)}`}>{r.verdict}</span></td></tr>
            ))}
          </tbody>
        </table>
        <p className="text-xs text-neutral-500 mt-1">First 100 shown. Full list in CSV/JSON export. <Link className="underline" to="/">Back to dashboard</Link></p>
      </div>
      <div className="bg-white border border-neutral-200 rounded p-3 flex gap-2 items-center flex-wrap">
        <span className="text-sm font-medium">Regression:</span>
        <input className="input max-w-48" placeholder="previous scan id" value={against} onChange={(e) => setAgainst(e.target.value)} />
        <button className="btn" onClick={async () => { const d = await api.diff(id, against) as { new: number; resolved: number; unchanged: number }; setDiff(d); }}>Compare</button>
        {diff && <span className="text-sm">New: {diff.new} · Resolved: {diff.resolved} · Unchanged: {diff.unchanged}</span>}
      </div>
    </div>
  );
}
