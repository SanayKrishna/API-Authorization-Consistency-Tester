const BASE = "";

async function j<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`HTTP ${res.status}: ${txt.slice(0, 300)}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => fetch(`${BASE}/api/health`).then((r) => j(r)),
  listScans: () => fetch(`${BASE}/api/scans`).then((r) => j<{ scans: import("../types").ScanListItem[] }>(r)),
  getScan: (id: string) => fetch(`${BASE}/api/scans/${id}`).then((r) => j<import("../types").ScanDetail>(r)),
  createScan: (payload: unknown) =>
    fetch(`${BASE}/api/scans`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }).then((r) =>
      j<{ scan_id: string; status: string }>(r),
    ),
  validatePolicy: (payload: unknown) =>
    fetch(`${BASE}/api/policy/validate`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }).then((r) =>
      j(r),
    ),
  diff: (id: string, against: string) =>
    fetch(`${BASE}/api/scans/${id}/diff?against=${encodeURIComponent(against)}`).then((r) => j(r)),
  reportUrl: (id: string, kind: string) => `${BASE}/api/scans/${id}/report.${kind}`,
  demoTokens: async (demoBase: string) => {
    const r = await fetch(`${demoBase.replace(/\/$/, "")}/demo/tokens`);
    return j<Record<string, { token: string; own_resource_id: string; other_resource_id: string }>>(r);
  },
};
