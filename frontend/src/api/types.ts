// The API's shapes, as backend/kasauti/api/*.py and kasauti/audit.py send them.

export type JobState = "queued" | "running" | "succeeded" | "failed" | "cancelled";
export type UploadState = "open" | "started" | "discarded" | "expired";
export type Status = "PASS" | "FAIL" | "REVIEW" | "N/A";
export type Severity = "critical" | "high" | "medium" | "low";
export type ControlStatus =
  "satisfied" | "partially satisfied" | "not satisfied" | "undetermined" | "not applicable";
export type FactState = "explicit" | "vendor_default" | "absent" | "unknown";

export interface Health {
  status: string;
  kasauti_version: string;
  kb_version: string;
  ruleset_version: string;
  vendor_packs: string[];
  frameworks: string[];
  database: string;
  schema_revision: string;
}

// -- uploads ------------------------------------------------------------------------------------

export interface UploadBrief {
  id: string;
  label: string | null;
  state: UploadState;
  frameworks: string[];
  vendor: string | null;
  created_at: string;
  started_at: string | null;
  accepted: number;
  refused: number;
  audits: Partial<Record<JobState, number>>;
}

export interface FileOut {
  id: string;
  name: string;
  size: number;
  sha256: string | null;
  accepted: boolean;
  reason: string | null;
  job_id: string | null;
  job_state: JobState | null;
  job_error: string | null;
  recognition: "pending" | "done" | "failed" | null;
  kind: "config" | "companion" | "unknown" | null;
  vendor: string | null;
  command: string | null;
  hostname: string | null;
  device: string | null;
  paired_by: "own" | "hostname" | "name" | "hand" | "alone" | null;
  note: string | null;
  entered: Record<string, string>;
}

export interface DeviceOut {
  config: string;
  name: string;
  vendor: string | null;
  hostname: string | null;
  companions: string[];
  entered: Record<string, string>;
}

export interface Upload {
  id: string;
  label: string | null;
  state: UploadState;
  frameworks: string[];
  vendor: string | null;
  created_at: string;
  touched_at: string;
  started_at: string | null;
  accepted: number;
  refused: number;
  recognising: number;
  files: FileOut[];
  devices: DeviceOut[];
}

export const ENTERABLE = ["hostname", "os_version", "model", "serial", "hardware"] as const;
export type Enterable = (typeof ENTERABLE)[number];

// -- audits -------------------------------------------------------------------------------------

export interface ScoreOut {
  framework: string;
  title: string;
  compliance_pct: number | null;
  coverage_pct: number | null;
  passed: number;
  failed: number;
  review: number;
  not_applicable: number;
  /** Why the framework judges nothing here (no STIG for this platform). */
  note?: string;
  /** The vendor benchmarks applied, for per-vendor frameworks (DISA STIG). */
  benchmarks?: string[];
}

export interface RuleBrief {
  rule_id: string;
  title: string;
  domain: string;
  severity: Severity | null;
  status: Status;
}

export interface Summary {
  audit_id: string;
  hostname: string | null;
  vendor: string | null;
  pack: string;
  os_version: string | null;
  model: string | null;
  identity_found: number;
  identity_total: number;
  scores: ScoreOut[];
  statuses: Partial<Record<Status, number>>;
  failed_by_severity: Partial<Record<Severity, number>>;
  rules: RuleBrief[];
  understood_pct: number | null;
  statements: number;
  warnings: number;
}

export interface AuditOut {
  job_id: string;
  upload_id: string;
  label: string | null;
  name: string;
  state: JobState;
  error: string | null;
  created_at: string;
  finished_at: string | null;
  summary: Summary | null;
}

// -- the full audit result (GET /api/jobs/{id}/result) ------------------------------------------

export interface Evidence {
  file: string;
  line_start: number;
  line_end: number;
  raw: string;
  mapping_id: string | null;
  mapping_version: number | null;
  approved_by: string[];
}

export interface Fact {
  value: unknown;
  state: FactState;
  evidence: Evidence[];
  default_source: string | null;
}

export interface Entity {
  key: string;
  type: string;
  evidence: Evidence[];
  [attribute: string]: unknown;
}

export interface Finding {
  rule_id: string;
  entity_id: string;
  status: Status;
  severity: Severity | null;
  severity_reason: string | null;
  reason: string;
  actual: string[];
  defaults_used: string[];
  evidence: Evidence[];
}

export interface RuleResult {
  rule_id: string;
  title: string;
  domain: string;
  status: Status;
  severity: Severity;
  nist_800_53r5: string[];
  hardening_best_practice: boolean;
  /** Framework -> controls on this device, for selected frameworks other than NIST. */
  controls?: Record<string, string[]>;
}

export interface ControlResult {
  framework: string;
  control: string;
  title: string;
  status: ControlStatus;
  rules: string[];
  /** DISA category of a STIG requirement: high = CAT I, medium = CAT II, low = CAT III. */
  severity: "high" | "medium" | "low" | null;
  benchmark: string | null;
  /** Undetermined because the passing rules check only part of the control. */
  partial: boolean;
}

export interface AuditResult {
  format_version: number;
  audit_id: string;
  input: {
    file: string;
    sha256: string;
    encoding: string;
    shape_family: string;
    rebuilt_from: string | null;
    parse_warnings: string[];
  };
  detection: {
    pack_id: string;
    pack_version: number;
    chosen_by: string;
    score: number | null;
    min_score: number | null;
    signatures: string[];
  };
  identity: Record<string, { value: string | null; source: string }>;
  kb: {
    kasauti_version: string;
    kb_version: string;
    ruleset_version: string;
    vendor_pack: string;
    frameworks: Record<string, string>;
  };
  frameworks: string[];
  scores: ScoreOut[];
  rules: RuleResult[];
  controls: ControlResult[];
  findings: Finding[];
  assurance: {
    statements: number;
    understood: number;
    unmapped: number;
    near_miss: number;
    understood_pct: number | null;
    unmapped_patterns: {
      pattern_key: string;
      count: number;
      first_line: number;
      example: string;
    }[];
    review_findings: number;
    mappings_used: { mapping: string; approved_by: string[]; facts: number }[];
    defaults_used: string[];
    mappings_skipped_for_version: string[];
  };
  sbm: {
    sbm_version: string;
    device: Entity;
    entities: Entity[];
    derived: Record<string, Fact>;
    known_empty: Record<string, string>;
    unread: Record<string, unknown>;
  };
  warnings: string[];
  companions: {
    file: string;
    sha256: string;
    command: string | null;
    used: boolean;
    note: string | null;
  }[];
  inventory: {
    name: string;
    description: string | null;
    part: string | null;
    version: string | null;
    serial: string;
    source: string;
  }[];
  /** Absent where nothing failed (and on results from before fixes existed). */
  remediation?: Remediation | null;
}

// -- remediation (kasauti/remediation/model.py) --------------------------------------------------

export type Proof = "verified" | "not_verified" | "not_checked";

export interface FixStep {
  commands: string[];
  note: string | null;
}

export interface Fix {
  rule_id: string;
  entity_ids: string[];
  recipe: string;
  source: string;
  precheck: FixStep;
  change: FixStep;
  verify: FixStep;
  save: FixStep | null;
  rollback: FixStep;
  placeholders: { name: string; means: string }[];
  note: string | null;
  proof: Proof;
  proof_detail: string;
}

export interface Remediation {
  fixes: Fix[];
  unfixed: string[];
  combined: {
    proof: Proof;
    detail: string;
    failed_before: number;
    failed_after: number;
    compliance_after_pct: number | null;
    still_failing: string[];
    left_for_review: string[];
  } | null;
  basis: string;
}

// -- knowledge base -----------------------------------------------------------------------------

export interface VendorOut {
  id: string;
  name: string;
  vendor: string;
  os_family: string;
  shape_family: string;
  pack_version: number;
  default_role: string | null;
  description: string;
  mappings: number;
  approved: number;
  defaults: number;
  signatures: number;
  /** Still being taught in the Training Studio. */
  learning: boolean;
}

export interface RuleOut {
  id: string;
  title: string;
  intent: string;
  domain: string;
  severity: Severity;
  applies_to: string[];
  for_each: string;
  assertion: string;
  controls: Record<string, string[]>;
  /** Per-vendor frameworks (DISA STIG): framework -> vendor pack -> controls. */
  vendor_controls: Record<string, Record<string, string[]>>;
  hardening_best_practice: boolean;
  fixtures_pass: string[];
  fixtures_fail: string[];
}

export interface Kb {
  kb_version: string;
  ruleset_version: string;
  vendors: VendorOut[];
  frameworks: {
    id: string;
    title: string;
    version: string;
    source_url: string;
    licence: string;
    retrieved: string;
    controls: number;
    benchmarks: {
      id: string;
      title: string;
      version: string;
      released: string;
      vendors: string[];
      sunset: boolean;
      source_url: string;
      source_sha256: string;
    }[];
    bridge: string | null;
    mapped_rules: number;
  }[];
  rules: RuleOut[];
  control_titles: Record<string, string>;
}

export interface MappingOut {
  id: string;
  version: number;
  match: string;
  context: string[];
  entity: string | null;
  os_versions: string;
  proposed_by: string;
  approved_by: string[];
  signals: string[];
  effects: Record<string, unknown>[];
}

export interface VendorDetail {
  vendor: VendorOut;
  mappings: MappingOut[];
  defaults: {
    id: string;
    attr: string | null;
    value: unknown;
    os_versions: string;
    source: string;
    reference: string;
  }[];
}

// -- training studio -----------------------------------------------------------------------------

export interface StudioTally {
  understood: number;
  statements: number;
  passed: number;
  failed: number;
  review: number;
  not_applicable: number;
}

export interface StudioPack {
  id: string;
  name: string;
  learning: boolean;
  mappings: number;
  taught: number;
  files: number;
  tally: StudioTally | null;
}

export interface StudioFile {
  id: string;
  name: string;
  pack: string;
  added: string;
  tally: StudioTally;
}

export interface StudioState {
  packs: StudioPack[];
  files: StudioFile[];
  kb_version: string;
}

export type SlotType = "INT" | "IP" | "IFNAME" | "STR" | "LIST";

export interface StudioSuggestion {
  meaning: string;
  label: string;
  score: number;
  why: string;
  choices: Record<string, string | string[]>;
  /** Token index -> role. */
  roles: Record<string, string>;
}

export interface StudioPattern {
  key: string;
  pattern: string;
  block: string | null;
  block_taught: boolean;
  count: number;
  files: number;
  examples: { file: string; line: number; text: string; block: string | null }[];
  tokens: { text: string; slot: SlotType | null }[];
  relevance: number;
  suggestions: StudioSuggestion[];
}

export interface StudioMeaning {
  id: string;
  label: string;
  explain: string;
  under: string | null;
  roles: { name: string; label: string; types: SlotType[]; optional: boolean }[];
  choices: { name: string; options: string[]; many: boolean }[];
}

export interface StudioFlip {
  rule: string;
  title: string;
  file: string;
  before: Status;
  after: Status;
}

export interface StudioProposal {
  id: string;
  pack: string;
  pattern: string;
  meaning: string;
  mapping_id: string;
  mapping: string;
  impact: {
    lines: number;
    files: number;
    facts: number;
    understood_before: number;
    understood_after: number;
    statements: number;
    to_pass: number;
    flips: StudioFlip[];
  };
  proposed_by: string;
  needs_second: boolean;
}

export interface StudioTaught {
  id: string;
  match: string;
  context: string[];
  proposed_by: string;
  approved_by: string[];
  mapping: string;
}

export interface StudioDecision {
  at: string;
  action: "propose" | "approve" | "reject" | "ignore" | "undo";
  pack: string;
  mapping?: string;
  /** The taught line, as the trainer wrote it. */
  line?: string;
  pattern?: string;
  by: string;
  proposed_by?: string;
  to_pass?: number;
}

// --- accounts (backend/kasauti/api/auth.py) -------------------------------------------------------

export type Role = "viewer" | "auditor" | "trainer" | "approver" | "admin";

/** Least privilege first: each role may do what the ones before it may. */
export const ROLES: Role[] = ["viewer", "auditor", "trainer", "approver", "admin"];

export interface Me {
  username: string;
  name: string;
  role: Role;
}

export interface AuthOptions {
  signup: boolean;
  min_password: number;
  demo: (Me & { password: string })[];
}
