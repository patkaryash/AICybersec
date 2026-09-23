export type ScanProfile = 'recon' | 'web_assessment' | 'full_assessment';

export type ScanStatus = 'running' | 'finished' | 'failed' | 'cancelled';

export interface ScanProfileInfo {
  id: ScanProfile;
  name: string;
  shortDesc: string;
  description: string;
  tools: string[];
  estimatedDuration: string;
  intensity: 'Passive' | 'Moderate' | 'Aggressive';
}

export interface Scan {
  id: string;
  target: string;
  profile: ScanProfile;
  status: ScanStatus;
  startedAt: string;
  completedAt?: string;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  currentStep: number;
  totalSteps: number;
  goal: string;
  notes?: string;
  isSimulated: boolean;
}

export const SCAN_PROFILES: Record<ScanProfile, ScanProfileInfo> = {
  recon: {
    id: 'recon',
    name: 'Reconnaissance',
    shortDesc: 'Passive & active reconnaissance, port discovery, and technology fingerprinting.',
    description: 'Discovers exposed host ports, active services, DNS records, and banner details without invasive payloads.',
    tools: ['mock_port_scan', 'dns_lookup', 'tech_detect'],
    estimatedDuration: '45-90s',
    intensity: 'Passive',
  },
  web_assessment: {
    id: 'web_assessment',
    name: 'Web Assessment',
    shortDesc: 'Web application vulnerability scanning and OWASP Top 10 surface checks.',
    description: 'Inspects HTTP endpoints, security headers, injection risks, authentication entrypoints, and misconfigurations.',
    tools: ['mock_port_scan', 'httpx_probe', 'nuclei_web_scan', 'ai_reasoner'],
    estimatedDuration: '2-4m',
    intensity: 'Moderate',
  },
  full_assessment: {
    id: 'full_assessment',
    name: 'Full Assessment',
    shortDesc: 'Comprehensive multi-phase network reconnaissance, service analysis, and vulnerability detection.',
    description: 'Full automated security audit combining network scanning, web fuzzing, configuration audit, and AI-guided chaining.',
    tools: ['nmap_discovery', 'httpx_probe', 'nuclei_full', 'cve_correlator', 'ai_reasoner'],
    estimatedDuration: '4-7m',
    intensity: 'Aggressive',
  },
};
