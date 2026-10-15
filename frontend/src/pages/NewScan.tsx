import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../services/api";

const SAMPLE = `{
  "target_base_url": "http://127.0.0.1:8001",
  "endpoints": [
    {"id": "get-user", "path": "/api/users/{id}", "method": "GET", "requires_auth": true, "allowed_roles": ["admin", "user", "readonly"], "ownership_required": true, "sensitivity": "private"}
  ],
  "identities": [
    {"name": "alice", "role": "user", "auth_state": "valid", "token": "PASTE_JWT", "own_resource_id": "u_alice", "other_resource_id": "u_bob"}
  ]
}`;

export default function NewScan() {
  const nav = useNavigate();
  const [target, setTarget] = useState("http://127.0.0.1:8001");
  const [policyText, setPolicyText] = useState(SAMPLE);
  const [includeDestructive, setIncludeDestructive] = useState(true);
  const [confirm, setConfirm] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function fillDemoTokens() {
    setErr("");
    try {
      const toks = await api.demoTokens(target);
      const pol = JSON.parse(policyText);
      const map: Record<string, string> = { admin: toks.admin?.token, alice: toks.alice?.token, readonly: toks.readonly?.token };
      pol.identities = (pol.identities || []).map((id: { name: string }) => {
        const first = id.name.split("-")[0];
        if (map[first]) return { ...id, token: map[first] };
        if (id.name.includes("alice") && toks.alice) return { ...id, token: toks.alice.token };
        return id;
      });
      setPolicyText(JSON.stringify(pol, null, 2));
    } catch (e) {
      setErr(`Could not fetch demo tokens from ${target}/demo/tokens: ${e}`);
    }
  }

  async function submit() {
    setErr("");
    if (!confirm) { setErr("Please confirm you are authorized to test this target."); return; }
    let pol: { endpoints: unknown[]; identities: unknown[] };
    try {
      pol = JSON.parse(policyText);
    } catch {
      setErr("Policy is not valid JSON."); return;
    }
    setBusy(true);
    try {
      const payload = { target_base_url: target, endpoints: pol.endpoints, identities: pol.identities,
        options: { include_destructive: includeDestructive, timeout_secs: 10, max_concurrency: 5, rate_delay_secs: 0.05 },
        confirm_target: true };
      const r = await api.createScan(payload);
      nav(`/scans/${r.scan_id}`);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3 max-w-3xl">
      <h2 className="font-medium text-base">New scan</h2>
      {err && <div className="bg-red-50 border border-red-200 text-red-700 rounded p-2">{err}</div>}
      <label className="block">
        <span className="text-xs text-neutral-500">Target base URL (localhost / lab only)</span>
        <input className="input mt-1" value={target} onChange={(e) => setTarget(e.target.value)} />
      </label>
      <label className="block">
        <span className="text-xs text-neutral-500">Policy JSON (endpoints + identities). See examples/sample_policy.json</span>
        <textarea className="input mt-1 font-mono text-xs" rows={14} value={policyText} onChange={(e) => setPolicyText(e.target.value)} />
      </label>
      <div className="flex items-center gap-4 text-sm">
        <label className="flex items-center gap-1"><input type="checkbox" checked={includeDestructive} onChange={(e) => setIncludeDestructive(e.target.checked)} /> Allow PUT/PATCH/POST/DELETE tests</label>
        <button className="btn" onClick={fillDemoTokens} type="button">Fetch demo tokens</button>
      </div>
      <label className="flex items-start gap-2 text-sm bg-white border border-neutral-200 rounded p-2">
        <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} className="mt-1" />
        <span>I confirm I am authorized to test <b>{target}</b>. Scanning is restricted to localhost and configured lab targets.</span>
      </label>
      <button className="btn btn-primary" disabled={busy || !confirm} onClick={submit}>{busy ? "Starting…" : "Launch scan"}</button>
    </div>
  );
}
