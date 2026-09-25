import { Finding } from './finding';

export type AgentEventType =
  // Phase-3 dot-notation vocabulary (pre-#14 backends)
  | 'run.started'
  | 'step.started'
  | 'decision.proposed'
  | 'decision.rejected'
  | 'tool.started'
  | 'tool.finished'
  | 'finding.recorded'
  | 'run.finished'
  | 'run.failed'
  // Frozen snake_case vocabulary (PR #14+)
  | 'scan_started'
  | 'scan_status_changed'
  | 'scan_completed'
  | 'scan_failed'
  | 'scan_cancelled'
  | 'tool_started'
  | 'tool_completed'
  | 'tool_failed'
  | 'agent_decision'
  | 'agent_observation'
  | 'finding_created';

export interface AgentTimelineEvent {
  id: string;
  step: number;
  type: AgentEventType;
  timestamp: string;
  title: string;
  description: string;
  tool?: string;
  status: 'pending' | 'in_progress' | 'completed' | 'warning' | 'error';
  reasoning?: string;
  durationMs?: number;
  payload?: Record<string, unknown>;
  associatedFinding?: Finding;
}

export interface AgentState {
  runId: string;
  target: string;
  goal: string;
  status: 'running' | 'finished' | 'failed' | 'cancelled';
  step: number;
  maxSteps: number;
  elapsedSeconds: number;
  events: AgentTimelineEvent[];
}
