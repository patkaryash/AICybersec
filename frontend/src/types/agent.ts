import { Finding } from './finding';

export type AgentEventType =
  | 'run.started'
  | 'step.started'
  | 'decision.proposed'
  | 'decision.rejected'
  | 'tool.started'
  | 'tool.finished'
  | 'finding.recorded'
  | 'run.finished'
  | 'run.failed';

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
