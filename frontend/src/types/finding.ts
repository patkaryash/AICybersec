export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Confidence = 'low' | 'medium' | 'high';

export type FindingStatus = 'open' | 'accepted_risk' | 'resolved' | 'false_positive';

export interface Finding {
  id: string;
  scanId: string;
  title: string;
  severity: Severity;
  target: string;
  asset: string;
  description: string;
  tool: string;
  confidence: Confidence;
  status: FindingStatus;
  detectedAt: string;
  evidence: {
    request?: string;
    response?: string;
    matchedPattern?: string;
    extractedData?: Record<string, unknown>;
    rawSnippet?: string;
  };
  aiAnalysis: {
    summary: string;
    impact: string;
    attackVector: string;
    exploitLikelihood: 'High' | 'Medium' | 'Low';
  };
  remediation: {
    summary: string;
    steps: string[];
    codeSnippet?: {
      language: string;
      before?: string;
      after: string;
      description: string;
    };
  };
  references: string[];
  isSynthetic: boolean;
}

export interface SeverityCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}
