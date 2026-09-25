import React, { useState } from 'react';
import { Finding, FindingStatus } from '../../types/finding';
import { SeverityBadge } from './SeverityBadge';
import { X, ExternalLink, Copy, Check, Terminal, ShieldAlert, Cpu, Wrench, FileCode, CheckCircle } from 'lucide-react';

interface FindingDetailModalProps {
  finding: Finding | null;
  isOpen: boolean;
  onClose: () => void;
  onStatusChange?: (id: string, newStatus: FindingStatus) => void;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  isOpen,
  onClose,
  onStatusChange,
}) => {
  const [copiedSection, setCopiedSection] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'ai' | 'remediation'>('overview');

  if (!isOpen || !finding) return null;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(id);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const statusOptions: { value: FindingStatus; label: string }[] = [
    { value: 'open', label: 'Open' },
    { value: 'accepted_risk', label: 'Accepted Risk' },
    { value: 'resolved', label: 'Resolved' },
    { value: 'false_positive', label: 'False Positive' },
  ];

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-sm flex justify-end transition-opacity">
      {/* Drawer Container */}
      <div
        className="w-full max-w-2xl bg-sentinel-surface border-l border-sentinel-border min-h-screen flex flex-col shadow-2xl animate-in slide-in-from-right duration-300"
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-modal-title"
      >
        {/* Header */}
        <div className="p-6 border-b border-sentinel-border bg-sentinel-bg/60 sticky top-0 z-10 backdrop-blur">
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-2">
              <div className="flex items-center gap-2.5 flex-wrap">
                <SeverityBadge severity={finding.severity} size="md" />
                <span className="text-xs font-mono text-sentinel-dim bg-sentinel-elevated px-2 py-0.5 rounded border border-sentinel-border">
                  {finding.id}
                </span>
                <span className="text-xs px-2 py-0.5 rounded font-mono border border-cyan-800/40 bg-cyan-950/40 text-cyan-300">
                  Synthetic Telemetry
                </span>
              </div>
              <h2 id="finding-modal-title" className="text-lg font-bold text-sentinel-text leading-snug">
                {finding.title}
              </h2>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-lg text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-elevated transition-colors"
              aria-label="Close details"
            >
              <X size={20} />
            </button>
          </div>

          {/* Quick Target / Asset bar */}
          <div className="mt-4 pt-3 border-t border-sentinel-border/50 flex flex-wrap items-center justify-between text-xs gap-3">
            <div className="flex items-center gap-2">
              <span className="text-sentinel-dim">Asset:</span>
              <code className="text-sentinel-cyan bg-sentinel-elevated px-2 py-0.5 rounded border border-sentinel-border font-mono">
                {finding.asset}
              </code>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sentinel-dim">Tool:</span>
              <span className="font-mono text-sentinel-text bg-sentinel-elevated px-2 py-0.5 rounded border border-sentinel-border">
                {finding.tool}
              </span>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex items-center gap-2 mt-4 pt-2 border-t border-sentinel-border/60">
            {[
              { id: 'overview', label: 'Overview', icon: ShieldAlert },
              { id: 'evidence', label: 'Evidence', icon: Terminal },
              { id: 'ai', label: 'AI Analysis', icon: Cpu },
              { id: 'remediation', label: 'Remediation', icon: Wrench },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-sentinel-cyan/15 text-sentinel-cyan border border-sentinel-cyan/30'
                      : 'text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-elevated'
                  }`}
                >
                  <Icon size={14} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Content Body */}
        <div className="p-6 flex-1 space-y-6 overflow-y-auto">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Description */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
                  Vulnerability Description
                </h4>
                <p className="text-sm text-sentinel-text/90 leading-relaxed bg-sentinel-bg/50 p-4 rounded-lg border border-sentinel-border">
                  {finding.description}
                </p>
              </div>

              {/* Status Update Control */}
              <div className="p-4 rounded-lg border border-sentinel-border bg-sentinel-elevated/40 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-sentinel-text">Triage & Remediation Status</span>
                  <span className="text-xs font-mono capitalize px-2 py-0.5 rounded bg-sentinel-surface border border-sentinel-border text-sentinel-cyan">
                    Current: {finding.status.replace('_', ' ')}
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {statusOptions.map((opt) => (
                    <button
                      key={opt.value}
                      onClick={() => onStatusChange && onStatusChange(finding.id, opt.value)}
                      className={`text-xs px-3 py-1.5 rounded-md border font-medium transition-all ${
                        finding.status === opt.value
                          ? 'bg-sentinel-cyan text-sentinel-bg border-sentinel-cyan font-semibold'
                          : 'border-sentinel-border bg-sentinel-surface text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-elevated'
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Meta details grid */}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-lg border border-sentinel-border bg-sentinel-bg/40 space-y-1">
                  <span className="text-sentinel-dim">Confidence Score</span>
                  <p className="font-mono text-sentinel-text font-semibold capitalize">{finding.confidence}</p>
                </div>
                <div className="p-3 rounded-lg border border-sentinel-border bg-sentinel-bg/40 space-y-1">
                  <span className="text-sentinel-dim">Detection Timestamp</span>
                  <p className="font-mono text-sentinel-text">{new Date(finding.detectedAt).toLocaleString()}</p>
                </div>
              </div>

              {/* References */}
              {finding.references && finding.references.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
                    Standards & Security References
                  </h4>
                  <ul className="space-y-1.5">
                    {finding.references.map((ref, idx) => (
                      <li key={idx} className="flex items-center gap-2 text-xs">
                        <ExternalLink size={12} className="text-sentinel-cyan shrink-0" />
                        <a
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sentinel-cyan hover:underline truncate font-mono"
                        >
                          {ref}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="space-y-5">
              {finding.evidence.request && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
                      Synthetic HTTP Request Payload
                    </span>
                    <button
                      onClick={() => handleCopy(finding.evidence.request || '', 'req')}
                      className="text-xs text-sentinel-muted hover:text-sentinel-cyan flex items-center gap-1"
                    >
                      {copiedSection === 'req' ? <Check size={12} /> : <Copy size={12} />}
                      <span>{copiedSection === 'req' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-3.5 bg-black/60 border border-sentinel-border rounded-lg text-xs font-mono text-rose-300 overflow-x-auto whitespace-pre leading-relaxed">
                    {finding.evidence.request}
                  </pre>
                </div>
              )}

              {finding.evidence.response && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
                      Synthetic Server Response
                    </span>
                    <button
                      onClick={() => handleCopy(finding.evidence.response || '', 'res')}
                      className="text-xs text-sentinel-muted hover:text-sentinel-cyan flex items-center gap-1"
                    >
                      {copiedSection === 'res' ? <Check size={12} /> : <Copy size={12} />}
                      <span>{copiedSection === 'res' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-3.5 bg-black/60 border border-sentinel-border rounded-lg text-xs font-mono text-cyan-200 overflow-x-auto whitespace-pre leading-relaxed">
                    {finding.evidence.response}
                  </pre>
                </div>
              )}

              {finding.evidence.rawSnippet && (
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
                    Raw Scanner Banner Output
                  </span>
                  <pre className="p-3.5 bg-black/60 border border-sentinel-border rounded-lg text-xs font-mono text-sentinel-text/90 overflow-x-auto whitespace-pre">
                    {finding.evidence.rawSnippet}
                  </pre>
                </div>
              )}

              {finding.evidence.matchedPattern && (
                <div className="p-3 rounded-lg border border-amber-900/50 bg-amber-950/20 text-xs space-y-1">
                  <span className="font-semibold text-amber-400">Trigger Match Pattern:</span>
                  <code className="block font-mono text-amber-200 text-xs mt-1">
                    {finding.evidence.matchedPattern}
                  </code>
                </div>
              )}
            </div>
          )}

          {activeTab === 'ai' && (
            <div className="space-y-5">
              <div className="p-4 rounded-lg border border-purple-800/60 bg-purple-950/20 space-y-3">
                <div className="flex items-center gap-2">
                  <div className="p-1 rounded bg-purple-900/50 text-purple-300">
                    <Cpu size={16} />
                  </div>
                  <span className="text-xs font-bold text-purple-300 uppercase tracking-wider font-mono">
                    AI Agent Reasoning & Threat Assessment
                  </span>
                </div>
                <p className="text-sm text-sentinel-text/90 leading-relaxed">
                  {finding.aiAnalysis.summary}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3.5 rounded-lg border border-sentinel-border bg-sentinel-bg/50 space-y-1">
                  <span className="text-sentinel-dim">Attack Vector</span>
                  <p className="font-mono text-sentinel-text font-medium">{finding.aiAnalysis.attackVector}</p>
                </div>
                <div className="p-3.5 rounded-lg border border-sentinel-border bg-sentinel-bg/50 space-y-1">
                  <span className="text-sentinel-dim">Exploitation Likelihood</span>
                  <p className="font-mono text-rose-400 font-semibold">{finding.aiAnalysis.exploitLikelihood}</p>
                </div>
              </div>

              <div className="p-4 rounded-lg border border-sentinel-border bg-sentinel-surface space-y-2">
                <h5 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
                  Impact Assessment
                </h5>
                <p className="text-xs text-sentinel-text leading-relaxed">
                  {finding.aiAnalysis.impact}
                </p>
              </div>
            </div>
          )}

          {activeTab === 'remediation' && (
            <div className="space-y-5">
              <div className="p-4 rounded-lg border border-emerald-900/60 bg-emerald-950/20 space-y-2">
                <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
                  Remediation Summary
                </span>
                <p className="text-sm text-emerald-200/90 leading-relaxed">
                  {finding.remediation.summary}
                </p>
              </div>

              <div className="space-y-3">
                <h5 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
                  Implementation Steps
                </h5>
                <div className="space-y-2">
                  {finding.remediation.steps.map((step, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 text-xs text-sentinel-text">
                      <span className="flex items-center justify-center w-5 h-5 rounded-full bg-sentinel-elevated border border-sentinel-border text-sentinel-cyan shrink-0 font-mono text-[11px]">
                        {idx + 1}
                      </span>
                      <span className="pt-0.5 leading-relaxed">{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              {finding.remediation.codeSnippet && (
                <div className="space-y-2 pt-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider flex items-center gap-1.5">
                      <FileCode size={14} className="text-sentinel-cyan" />
                      Recommended Patch ({finding.remediation.codeSnippet.language})
                    </span>
                    <button
                      onClick={() => handleCopy(finding.remediation.codeSnippet?.after || '', 'patch')}
                      className="text-xs text-sentinel-muted hover:text-sentinel-cyan flex items-center gap-1"
                    >
                      {copiedSection === 'patch' ? <Check size={12} /> : <Copy size={12} />}
                      <span>{copiedSection === 'patch' ? 'Copied' : 'Copy Patch'}</span>
                    </button>
                  </div>

                  {finding.remediation.codeSnippet.before && (
                    <div>
                      <span className="text-[10px] text-rose-400 font-mono block mb-1">− Vulnerable:</span>
                      <pre className="p-2.5 bg-rose-950/20 border border-rose-900/40 rounded text-xs font-mono text-rose-300 overflow-x-auto whitespace-pre">
                        {finding.remediation.codeSnippet.before}
                      </pre>
                    </div>
                  )}

                  <div>
                    <span className="text-[10px] text-emerald-400 font-mono block mb-1">+ Secure Fix:</span>
                    <pre className="p-2.5 bg-emerald-950/20 border border-emerald-900/40 rounded text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre">
                      {finding.remediation.codeSnippet.after}
                    </pre>
                  </div>
                  <p className="text-[11px] text-sentinel-dim italic">
                    {finding.remediation.codeSnippet.description}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-sentinel-border bg-sentinel-bg/80 flex items-center justify-between">
          <span className="text-xs text-sentinel-dim font-mono">
            CyberSec AI • Normalized Finding Record
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-sentinel-elevated border border-sentinel-border text-xs text-sentinel-text hover:bg-sentinel-subtle transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
