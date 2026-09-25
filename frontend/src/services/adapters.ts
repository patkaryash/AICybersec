/**
 * CyberSec AI — Domain Model Adapters
 * Safely maps backend v1 DTOs to frontend presentation models.
 */

import { ScanOut, FindingOut, ScopeEntry, AgentEventOut } from '../types/contract';
import { Scan, ScanProfile } from '../types/scan';
import { Finding, Severity } from '../types/finding';
import { AgentTimelineEvent } from '../types/agent';

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

/**
 * Render real backend agent events with the same readable timeline cards
 * as the demo simulation: human titles, plain-English descriptions, tool
 * chips, and measured tool durations.
 *
 * Handles BOTH the Phase-3 dot-notation vocabulary (run.started, …) and
 * the frozen snake_case vocabulary (scan_started, tool_completed, …).
 * Pure loop bookkeeping (step.started) and lifecycle echoes already shown
 * in the page header (scan_status_changed) are skipped.
 *
 * NOTE: no rationale box renders for real events — planner reasoning
 * never reaches the database (security boundary), so there is nothing
 * honest to display there.
 */
const TOOL_LABELS: Record<string, string> = {
  nmap: 'Nmap',
  httpx: 'HTTPX',
  nuclei: 'Nuclei',
};

function toolLabel(tool: unknown): string {
  if (typeof tool === 'string' && tool.length > 0) {
    return TOOL_LABELS[tool] ?? tool;
  }
  return 'Scanner';
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function asStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((v): v is string => typeof v === 'string' && v.length > 0);
  }
  const single = asString(value);
  return single ? [single] : [];
}

function durationBetweenMs(a: string, b: string): number | undefined {
  const ms = new Date(b).getTime() - new Date(a).getTime();
  return Number.isFinite(ms) && ms >= 0 ? Math.round(ms) : undefined;
}

export function mapRealEventsToTimeline(events: AgentEventOut[]): AgentTimelineEvent[] {
  const startedByKey = new Map<string, number>();
  const out: AgentTimelineEvent[] = [];

  for (const e of events) {
    const data = (e.data ?? {}) as Record<string, unknown>;
    const t = e.event_type;
    const id = String(e.seq);
    const step = e.step ?? 0;

    const card = (
      title: string,
      description: string,
      extra?: Partial<Pick<AgentTimelineEvent, 'tool' | 'status' | 'durationMs'>>,
    ): AgentTimelineEvent => ({
      id,
      step,
      timestamp: e.created_at,
      type: t as AgentTimelineEvent['type'],
      title,
      description,
      status: 'completed',
      payload: data,
      ...extra,
    });

    switch (t) {
      case 'step.started':
      case 'scan_status_changed':
        break;
      case 'run.started':
      case 'scan_started': {
        const goal = asString(data.goal);
        const mode = asString(data.mode);
        out.push(
          card(
            'Assessment Run Started',
            goal ?? (mode ? `Security assessment started in ${mode} mode.` : 'Security assessment started.'),
          ),
        );
        break;
      }
      case 'decision.proposed':
      case 'agent_decision': {
        const decision = (data.decision ?? {}) as Record<string, unknown>;
        if (decision.kind === 'tool_call') {
          const tool = asString(decision.tool);
          const params = (decision.params ?? {}) as Record<string, unknown>;
          const targets = asStringArray(params.targets ?? params.target);
          out.push(
            card(
              `${toolLabel(tool)} Scan Planned`,
              targets.length > 0
                ? `Authorized targets: ${targets.join(', ')}`
                : 'Planner proposed a scanner invocation.',
              { tool: tool ?? undefined },
            ),
          );
        } else {
          out.push(
            card('Assessment Complete', asString(decision.summary) ?? 'The planner finished the assessment pipeline.'),
          );
        }
        break;
      }
      case 'decision.rejected':
      case 'agent_observation': {
        const reason = asString(data.reason);
        const decision = (data.decision ?? {}) as Record<string, unknown>;
        const tool = asString(decision.tool);
        if (reason) {
          out.push(
            card('Tool Call Blocked by Policy', reason, {
              tool: tool ?? undefined,
              status: 'warning',
            }),
          );
        } else {
          out.push(
            card('Agent Observation', 'The agent recorded a policy observation.', {
              tool: tool ?? undefined,
              status: 'warning',
            }),
          );
        }
        break;
      }
      case 'tool.started':
      case 'tool_started': {
        const tool = asString(data.tool);
        out.push(
          card(`${toolLabel(tool)} Execution Started`, `${toolLabel(tool)} invoked with pipeline-approved parameters.`, {
            tool: tool ?? undefined,
            status: 'in_progress',
          }),
        );
        startedByKey.set(`${step}::${tool}`, out.length - 1);
        break;
      }
      case 'tool.finished':
      case 'tool_completed':
      case 'tool_failed': {
        const tool = asString(data.tool);
        const status = asString(data.status);
        const ok = status === 'ok' || t === 'tool_completed';
        const summary = asString(data.summary);
        const evt = card(
          ok ? `${toolLabel(tool)} Execution Completed` : `${toolLabel(tool)} Execution Failed`,
          summary ?? `Tool finished with status ${status ?? 'unknown'}.`,
          { tool: tool ?? undefined, status: ok ? 'completed' : 'error' },
        );
        const idx = startedByKey.get(`${step}::${tool}`);
        if (idx !== undefined) {
          const ms = durationBetweenMs(out[idx].timestamp, e.created_at);
          if (ms !== undefined) {
            out[idx].durationMs = ms;
            evt.durationMs = ms;
          }
          out[idx].status = 'completed';
          startedByKey.delete(`${step}::${tool}`);
        }
        out.push(evt);
        break;
      }
      case 'finding.recorded':
      case 'finding_created': {
        const f = (data.finding ?? {}) as Record<string, unknown>;
        const target = asString(f.target) ?? asString(f.asset);
        const fstatus = asString(f.status);
        out.push(
          card(asString(f.title) ?? 'Security Finding Recorded', target ? `Recorded on ${target}${fstatus ? ` — status ${fstatus}` : ''}.` : 'Recorded by the scanner.', {
            tool: asString(f.tool) ?? undefined,
          }),
        );
        break;
      }
      case 'run.finished':
      case 'scan_completed': {
        out.push(card('Assessment Run Finished', asString(data.summary) ?? 'The assessment pipeline completed.'));
        break;
      }
      case 'run.failed':
      case 'scan_failed': {
        out.push(
          card('Assessment Run Failed', asString(data.error) ?? asString(data.summary) ?? 'The assessment pipeline failed.', {
            status: 'error',
          }),
        );
        break;
      }
      case 'scan_cancelled': {
        out.push(card('Assessment Run Cancelled', asString(data.error) ?? 'The assessment was cancelled.'));
        break;
      }
      default: {
        const label = t.replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
        out.push(card(label, 'Telemetry event recorded.'));
        break;
      }
    }
  }

  return out;
}
