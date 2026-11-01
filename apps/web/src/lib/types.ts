export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";
export type Finding = {
  finding_id: string; severity: Severity; source: string; title: string; description: string;
  resource: string; account_id: string; region: string; check_id: string;
  timestamp: string; status: string; synthetic: boolean; compliance?: string[];
};
export type Summary = {
  accounts:string[]; latest_evidence_at:string|null;
  total: number; severity: Record<Severity, number>; sources: Record<string, number>;
  tracked: number; workflow: Record<string, number>; synthetic_count: number; data_scope: string;
};
export type FindingPage = { items: Finding[]; total: number; page: number; page_size: number };
export type Assessment = {
  category: string; weakness_id: string | null; weakness_name: string | null;
  technique_id: string | null; technique_name: string | null; technique_tactic: string | null;
  conditions: string; remediation: string[]; verification: string; mapping_basis: string;
  cwe_url: string | null; attack_url: string | null;
};
export type Remediation = {
  finding_id: string; state: string; assignee: string; updated_at: string;
  pending_at: string | null; verified_at: string | null; verified_scan_id: string | null;
  verification_evidence: string;
};
export type Analysis = { explanation: string; mitigation_steps: string[]; model_used: string; analyzed_at: string };
export type FindingDetail = { snapshot_scan_id?: string | null; finding: Finding; assessment: Assessment; remediation: Remediation; ai_analysis: Analysis | null; evidence_notice: string };
export type Activity = { id: number; actor: string; action: string; previous_state: string; new_state: string; note: string; occurred_at: string };
export type AIProviderChoice = {
  id: string; name: string; models: string[]; default_model: string;
  destination: "external" | "operator-configured";
};
export type AIStatus = {
  configured: boolean; provider: string | null; model: string | null;
  providers: AIProviderChoice[]; message: string;
};
export type AIReviewAlert = {
  code: string; level: "high" | "warning"; title: string;
  explanation: string; engineer_check: string;
};
export type AIReview = {
  version: string; assessment: string; alerts: AIReviewAlert[];
  scan_evidence: { label: string; value: string }[];
  unverified_conditions: string[]; activity_evidence: string; disclaimer: string;
};
export type AIFeedback = { rating: "helpful" | "needs_correction"; note: string; updated_at: string };
export type AIAdvisorResult = {
  review?: AIReview;
  explanation: string; attack_scenario: string; risk_priority: Severity;
  risk_justification: string; mitigation_steps: string[]; verification_steps: string[]; cautions: string[];
};
export type AIHistoryEntry = {
  id: number; provider: string; model: string; analyzed_at: string;
  analysis: AIAdvisorResult; prompt_version: string; feedback?: AIFeedback | null;
};
export type AIAnalyzeResponse = Omit<AIHistoryEntry, "prompt_version"> & { cached: boolean };
