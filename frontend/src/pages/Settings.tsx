export default function Settings() {
  return (
    <div className="space-y-3 max-w-2xl">
      <h2 className="font-medium text-base">Settings</h2>
      <div className="bg-white border border-neutral-200 rounded p-4 text-sm space-y-2">
        <p><b>Backend:</b> <code>http://127.0.0.1:8000</code> (proxied via <code>/api</code> in dev)</p>
        <p><b>Demo API:</b> <code>http://127.0.0.1:8001</code> — synthetic users only.</p>
        <p className="text-neutral-600">Scanning is restricted to localhost and <code>ALLOWED_TARGETS</code>. Private-network targets require <code>ALLOW_PRIVATE_TARGETS=true</code> in an isolated lab. Destructive methods (PUT/PATCH/POST/DELETE) require explicit opt-in per scan. Tokens are redacted in reports.</p>
        <p className="text-neutral-600">Severity is rule-based (see backend <code>severity.py</code>). Different outcomes are not flagged unless they contradict the configured policy.</p>
      </div>
    </div>
  );
}
