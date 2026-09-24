/**
 * Sentinel AI — Domain Model Adapters
 * Safely maps backend v1 DTOs to frontend presentation models.
 */

import { ScanOut, FindingOut, ScopeEntry } from '../types/contract';
import { Scan, ScanProfile } from '../types/scan';
import { Finding, Severity } from '../types/finding';

export function mapScanOutToScan(out: ScanOut): Scan {
  const firstTarget =
    out.target_snapshot && out.target_snapshot.length > 0
      ? out.target_snapshot[0].value
      : 'Authorized Target';

  // Map backend profile to UI profile
  const profile: ScanProfile =
    out.profile === 'recon' ? 'recon' : out.profile === 'web' ? 'web' : 'full';

  return {
    id: out.id,
    projectId: out.project_id,
    target: firstTarget,
    profile,
    status: out.status,
    startedAt: out.started_at || out.created_at,
    completedAt: out.completed_at || out.cancelled_at || undefined,
    findingsCount: out.findings_count || {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 0,
    },
    currentStep: out.current_step,
    totalSteps: out.total_steps,
    goal: out.goal || `Autonomous security assessment with ${out.profile} profile.`,
    notes: out.error ? `Error: ${out.error}` : undefined,
    isSimulated: false,
  };
}

export function mapFindingOutToFinding(out: FindingOut): Finding {
  const targetStr =
    typeof out.scanner_evidence?.target === 'string'
      ? out.scanner_evidence.target
      : typeof out.scanner_evidence?.host === 'string'
      ? out.scanner_evidence.host
      : typeof out.scanner_evidence?.url === 'string'
      ? out.scanner_evidence.url
      : 'Lab Asset';

  const rawJsonSnippet =
    out.scanner_evidence && Object.keys(out.scanner_evidence).length > 0
      ? JSON.stringify(out.scanner_evidence, null, 2)
      : undefined;

  return {
    id: out.id,
    scanId: out.scan_id,
    title: out.title,
    severity: out.scanner_severity as Severity,
    target: targetStr,
    asset: out.asset_id || out.fingerprint,
    description: out.description || 'No detailed description provided by tool evidence.',
    tool: out.source_tool,
    confidence: out.ai_confidence || 'medium',
    status: out.status,
    detectedAt: out.created_at,
    evidence: {
      request: typeof out.scanner_evidence?.request === 'string' ? out.scanner_evidence.request : undefined,
      response: typeof out.scanner_evidence?.response === 'string' ? out.scanner_evidence.response : undefined,
      matchedPattern: typeof out.scanner_evidence?.matched_pattern === 'string' ? out.scanner_evidence.matched_pattern : undefined,
      extractedData: out.scanner_evidence,
      rawSnippet: rawJsonSnippet,
    },
    aiAnalysis: {
      summary: out.ai_analysis || 'AI analysis pending Phase 8 model pipeline integration.',
      impact: out.ai_recommendation || 'Verified by scanner technical evidence.',
      attackVector: `Identified by ${out.source_tool}`,
      exploitLikelihood:
        out.ai_confidence === 'high'
          ? 'High'
          : out.ai_confidence === 'low'
          ? 'Low'
          : 'Medium',
    },
    remediation: {
      summary:
        out.ai_recommendation ||
        'Inspect the raw technical evidence logs and implement recommended hardening.',
      steps: out.ai_recommendation
        ? [out.ai_recommendation]
        : ['Review detection evidence and apply relevant mitigation patches.'],
    },
    references: Array.isArray(out.scanner_references)
      ? out.scanner_references.map((r) => String(r))
      : [],
    isSynthetic: false,
  };
}

/**
 * Determine scope type from target string.
 */
export function inferScopeFromTarget(target: string): ScopeEntry {
  const trimmed = target.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return { type: 'url', value: trimmed };
  }
  if (/\/\d{1,2}$/.test(trimmed)) {
    return { type: 'cidr', value: trimmed };
  }
  return { type: 'host', value: trimmed.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase() };
}
