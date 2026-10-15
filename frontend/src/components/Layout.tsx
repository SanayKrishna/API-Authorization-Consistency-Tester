import { NavLink, Outlet } from "react-router-dom";

export function sevColor(s: string): string {
  const v = s.toLowerCase();
  if (v === "critical") return "bg-red-50 text-red-700 border-red-200";
  if (v === "high") return "bg-orange-50 text-orange-700 border-orange-200";
  if (v === "medium") return "bg-amber-50 text-amber-800 border-amber-200";
  if (v === "low") return "bg-neutral-50 text-neutral-600 border-neutral-200";
  return "bg-blue-50 text-blue-700 border-blue-200";
}

export function verdictColor(v: string): string {
  if (v === "pass") return "bg-green-50 text-green-700 border-green-200";
  if (v === "fail") return "bg-red-50 text-red-700 border-red-200";
  return "bg-neutral-100 text-neutral-600 border-neutral-200";
}

export default function Layout() {
  return (
    <div className="min-h-screen flex">
      <aside className="w-48 shrink-0 bg-white border-r border-neutral-200 p-3 flex flex-col gap-1">
        <div className="px-1 py-2">
          <div className="font-semibold text-sm">AuthZ Tester</div>
          <div className="text-xs text-neutral-500">local lab</div>
        </div>
        <NavLink to="/" className={({ isActive }) => `px-2 py-1.5 rounded text-sm ${isActive ? "bg-neutral-100 font-medium" : "hover:bg-neutral-50"}`}>Dashboard</NavLink>
        <NavLink to="/scans/new" className={({ isActive }) => `px-2 py-1.5 rounded text-sm ${isActive ? "bg-neutral-100 font-medium" : "hover:bg-neutral-50"}`}>New scan</NavLink>
        <NavLink to="/settings" className={({ isActive }) => `px-2 py-1.5 rounded text-sm ${isActive ? "bg-neutral-100 font-medium" : "hover:bg-neutral-50"}`}>Settings</NavLink>
        <div className="mt-auto text-xs text-neutral-400 px-1">Real backend data only.<br />No fake findings.</div>
      </aside>
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="bg-white border-b border-neutral-200 px-4 py-2 flex items-center gap-3">
          <span className="text-sm font-medium">API Authorization Consistency Tester</span>
          <span className="text-xs text-neutral-500 ml-auto" id="workspace">workspace: local</span>
        </header>
        <main className="p-4 max-w-6xl w-full mx-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
