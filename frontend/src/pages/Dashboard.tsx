import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import type { ScanListItem } from "../types";
import { sevColor } from "../components/Layout";

export default function Dashboard() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listScans().then((d) => setScans(d.scans)).catch((e) => setErr(String(e))).finally(() => setLoading(false));
  }, []);

  const latest = scans[0];
  if (loading) return <p className="text-neutral-500">Loading scans…</p>;
  if (err) return <div className="bg-white border border-red-200 text-red-700 rounded p-3">Backend unreachable: {err}. Start backend on :8000 (see README).</div>;
  if (!latest)
    return (
      <div className="bg-white border border-neutral-200 rounded p-8 text-center">
        <h2 className="font-medium mb-1">No scans yet</h2>
        <p className="text-neutral-500 mb-3">Configure a target and policy to run your first authorization scan.</p>
        <Link to="/scans/new" className="btn btn-primary">New scan</Link>
      </div>
    );

  return (
    <div className="space-y-4">
      <div className="bg-white border border-neutral-200 rounded p-4">
        <div className="flex items-center gap-2 mb-2">
          <h2 className="font-medium">Latest scan</h2>
          <span className="text-xs text-neutral-500">{latest.scan_id} · {latest.target} · {latest.status}</span>
          <Link to={`/scans/${latest.scan_id}`} className="btn ml-auto">Open results</Link>
        </div>
        <div className="flex flex-wrap gap-2 text-sm">
          <span className="badge border-neutral-200">Total {latest.summary.total}</span>
          <span className="badge bg-green-50 border-green-200 text-green-700">Passed {latest.summary.passed}</span>
          <span className="badge bg-red-50 border-red-200 text-red-700">Failed {latest.summary.failed}</span>
          <span className="badge border-neutral-200">Inconclusive {latest.summary.inconclusive}</span>
          {Object.entries(latest.summary.by_severity || {}).map(([k, v]) => (
            <span key={k} className={`badge border ${sevColor(k)}`}>{k}: {v}</span>
          ))}
        </div>
      </div>
      <div className="bg-white border border-neutral-200 rounded">
        <table className="table">
          <thead><tr><th>Scan</th><th>Target</th><th>Status</th><th>Results</th><th>Created</th></tr></thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.scan_id}>
                <td><Link className="text-blue-700 underline" to={`/scans/${s.scan_id}`}>{s.scan_id}</Link></td>
                <td className="text-neutral-600">{s.target}</td>
                <td>{s.status}</td>
                <td>{s.summary.passed}/{s.summary.total} pass · {s.findings} findings</td>
                <td className="text-neutral-500">{s.created_at}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
