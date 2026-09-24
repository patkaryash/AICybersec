/**
 * Sentinel AI — Backend v1 Frozen API Contract Types
 * Directly maps to backend schemas and DTOs.
 */

// ==========================================
// Response Envelope & Common
// ==========================================

export interface ErrorBody {
  code: string;
  message: string;
}

export interface Meta {
  request_id: string;
  page?: number;
  page_size?: number;
  total?: number;
}

export interface Envelope<T> {
  success: boolean;
  data: T | null;
  error: ErrorBody | null;
  meta: Meta;
}

export interface PageData<T> {
  items: T[];
}

export type ErrorCodeType =
  | 'PROJECT_NOT_FOUND'
  | 'SCAN_NOT_FOUND'
  | 'FINDING_NOT_FOUND'
  | 'INVALID_TARGET'
  | 'TARGET_OUT_OF_SCOPE'
  | 'TARGET_NOT_AUTHORIZED'
  | 'INVALID_SCAN_PROFILE'
  | 'INVALID_TOOL_PARAMETERS'
  | 'INVALID_AGENT_ACTION'
  | 'TOOL_NOT_ALLOWED'
  | 'INVALID_TOOL'
  | 'TOOL_TIMEOUT'
  | 'TOOL_EXECUTION_FAILED'
  | 'SCAN_ALREADY_RUNNING'
  | 'SCAN_NOT_CANCELLABLE'
  | 'EMAIL_ALREADY_REGISTERED'
  | 'INVALID_CREDENTIALS'
  | 'DATABASE_ERROR'
  | 'VALIDATION_ERROR'
  | 'INTERNAL_ERROR'
  | 'NETWORK_ERROR'
  | 'UNAUTHORIZED';

// ==========================================
// Authentication
// ==========================================

export interface RegisterRequest {
  email: string;
  password: string;
  display_name?: string | null;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface UserOut {
  id: string;
  email: string;
  display_name: string | null;
  role: 'admin' | 'user' | string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

// ==========================================
// Projects
// ==========================================

export type ScopeType = 'host' | 'cidr' | 'url';
export type ProjectStatus = 'active' | 'archived';

export interface ScopeEntry {
  type: ScopeType;
  value: string;
  note?: string | null;
}

export interface ProjectCreate {
  name: string;
  description?: string | null;
  scope: ScopeEntry[];
}

export interface ProjectUpdate {
  name?: string | null;
  description?: string | null;
  scope?: ScopeEntry[] | null;
  status?: ProjectStatus | null;
}

export interface ProjectOut {
  id: string;
  owner_id: string;
  name: string;
  description: string | null;
  status: ProjectStatus;
  scope: ScopeEntry[];
  created_at: string;
  updated_at: string;
}

// ==========================================
// Scans
// ==========================================

export type ScanStatus =
  | 'queued'
  | 'initializing'
  | 'running'
  | 'cancelling'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type ScanMode = 'pipeline' | 'agent';

export type ScanProfile = 'recon' | 'web' | 'full';

export interface FindingsCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface ScanCreate {
  project_id: string;
  profile?: ScanProfile;
  mode?: ScanMode;
  goal?: string | null;
  tool_timeout_s?: number;
  max_steps?: number | null;
}

export interface ScanOut {
  id: string;
  project_id: string;
  status: ScanStatus;
  mode: ScanMode;
  profile: ScanProfile;
  goal: string | null;
  target_snapshot: ScopeEntry[];
  tool_timeout_s: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
  updated_at: string;
  total_steps: number;
  current_step: number;
  findings_count: FindingsCount;
}

export interface DashboardOut {
  total_projects: number;
  total_scans: number;
  running_scans: number;
  scans_by_status: Record<ScanStatus, number> | Record<string, number>;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  total_assets: number;
  recent_scans: ScanOut[];
}

// ==========================================
// Findings
// ==========================================

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type FindingStatus = 'open' | 'accepted_risk' | 'resolved' | 'false_positive';
export type Confidence = 'low' | 'medium' | 'high';

export interface FindingOut {
  id: string;
  scan_id: string;
  project_id: string;
  asset_id: string | null;
  fingerprint: string;
  title: string;
  description: string | null;
  source_tool: string;
  scanner_severity: Severity;
  scanner_evidence: Record<string, unknown>;
  scanner_references: unknown[];
  ai_severity: Severity | null;
  ai_analysis: string | null;
  ai_confidence: Confidence | null;
  ai_recommendation: string | null;
  ai_analyzed_at: string | null;
  status: FindingStatus;
  created_at: string;
  updated_at: string;
}

// ==========================================
// Assets
// ==========================================

export type AssetType = 'host' | 'service' | 'url';

export interface AssetOut {
  id: string;
  scan_id: string;
  project_id: string;
  asset_type: AssetType;
  value: string;
  host: string | null;
  port: number | null;
  scheme: string | null;
  attributes: Record<string, unknown>;
  source_tool: string;
  created_at: string;
  last_seen: string;
}

// ==========================================
// Events & Tool Runs
// ==========================================

export interface AgentEventOut {
  seq: number;
  scan_id: string;
  event_type: string;
  step: number | null;
  data: Record<string, unknown>;
  created_at: string;
}

export interface ToolRunOut {
  id: string;
  scan_id: string;
  tool: string;
  status: string;
  initiated_by: string;
  parameters: Record<string, unknown>;
  exit_code: number | null;
  summary: string | null;
  started_at: string | null;
  ended_at: string | null;
  duration_ms: number | null;
}
