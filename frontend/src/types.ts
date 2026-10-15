export type Verdict = "pass" | "fail" | "inconclusive";
export interface TestResult {
  test_id: string; endpoint_id: string; method: string; path_rendered: string;
  identity: string; role: string; auth_state: string; resource_variant: string;
  expected: string; actual_status: number | null; verdict: Verdict;
  leak_detected: boolean; body_excerpt: string; duration_ms: number; error: string;
}
export interface Finding {
  finding_id: string; endpoint_id: string; method: string; path: string;
  category: string; severity: string; confidence: string;
  expected: string; actual: string; explanation: string;
  reproduction: string[]; evidence: Record<string, unknown>;
  remediation: string; fingerprint: string;
}
export interface ScanSummary {
  total: number; passed: number; failed: number; inconclusive: number;
  by_severity: Record<string, number>; by_category: Record<string, number>;
  duration_secs: number;
}
export interface ScanDetail {
  scan_id: string; target_base_url: string; status: string;
  progress: Record<string, unknown>; summary: ScanSummary;
  results: TestResult[]; findings: Finding[]; created_at: string;
}
export interface ScanListItem {
  scan_id: string; target: string; status: string; summary: ScanSummary;
  created_at: string; findings: number;
}
