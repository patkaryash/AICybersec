import React, { useState } from 'react';
import { Finding, FindingStatus } from '../../types/finding';
import { SeverityBadge } from './SeverityBadge';
import { X, ExternalLink, Copy, Check, Terminal, ShieldAlert, Cpu, Wrench, FileCode } from 'lucide-react';

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
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/75 backdrop-blur-sm flex justify-end transition-opacity">
      {/* Drawer Container */}
      <div
        className="w-full max-w-2xl bg-[#121214] border-l border-zinc-800 min-h-screen flex flex-col shadow-2xl animate-in slide-in-from-right duration-300 text-zinc-100"
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-modal-title"
      >
        {/* Header */}
        <div className="p-6 border-b border-zinc-800 bg-[#121214] sticky top-0 z-10 backdrop-blur-md">
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-2">
              <div className="flex items-center gap-2.5 flex-wrap">
                <SeverityBadge severity={finding.severity} size="md" />
                <span className="text-xs font-mono text-zinc-400 bg-zinc-800/80 px-2 py-0.5 rounded border border-zinc-700/80">
                  {finding.id}
                </span>
                <span className="text-xs px-2 py-0.5 rounded font-mono border border-zinc-700 bg-zinc-800/60 text-zinc-300 font-medium">
                  Verified Finding
                </span>
              </div>
              <h2 id="finding-modal-title" className="text-lg font-bold text-white leading-snug">
                {finding.title}
              </h2>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
              aria-label="Close details"
            >
              <X size={20} />
            </button>
          </div>

          {/* Quick Target / Asset bar */}
          <div className="mt-4 pt-3 border-t border-zinc-800 flex flex-wrap items-center justify-between text-xs gap-3">
            <div className="flex items-center gap-2">
              <span className="text-zinc-500 font-mono">Asset:</span>
              <code className="text-zinc-200 bg-zinc-800/80 px-2 py-0.5 rounded border border-zinc-700/80 font-mono font-medium">
                {finding.asset}
              </code>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-zinc-500 font-mono">Tool:</span>
              <span className="font-mono text-zinc-300 bg-zinc-800/80 px-2 py-0.5 rounded border border-zinc-700/80">
                {finding.tool}
              </span>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex items-center gap-2 mt-4 pt-2 border-t border-zinc-800">
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
                      ? 'bg-zinc-100 text-zinc-900 font-semibold shadow-xs'
                      : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
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
                <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider font-mono">
                  Vulnerability Description
                </h4>
                <p className="text-sm text-zinc-200 leading-relaxed bg-[#18181B] p-4 rounded-xl border border-zinc-800">
                  {finding.description}
                </p>
              </div>

              {/* Status Update Control */}
              <div className="p-4 rounded-xl border border-zinc-800 bg-[#18181B] space-y-3 shadow-xs">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-zinc-200">Triage & Remediation Status</span>
                  <span className="text-xs font-mono capitalize px-2 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-zinc-300 font-medium">
                    Current: {finding.status.replace('_', ' ')}
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {statusOptions.map((opt) => (
                    <button
                      key={opt.value}
                      onClick={() => onStatusChange && onStatusChange(finding.id, opt.value)}
                      className={`text-xs px-3 py-1.5 rounded-lg border font-medium transition-all ${
                        finding.status === opt.value
                          ? 'bg-zinc-100 text-zinc-900 border-zinc-100 font-semibold shadow-xs'
                          : 'border-zinc-800 bg-[#121214] text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800'
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Meta details grid */}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3.5 rounded-xl border border-zinc-800 bg-[#18181B] space-y-1">
                  <span className="text-zinc-500 font-mono">Confidence Score</span>
                  <p className="font-mono text-zinc-200 font-semibold capitalize">{finding.confidence}</p>
                </div>
                <div className="p-3.5 rounded-xl border border-zinc-800 bg-[#18181B] space-y-1">
                  <span className="text-zinc-500 font-mono">Detection Timestamp</span>
                  <p className="font-mono text-zinc-200">{new Date(finding.detectedAt).toLocaleString()}</p>
                </div>
              </div>

              {/* References */}
              {finding.references && finding.references.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider font-mono">
                    Standards & Security References
                  </h4>
                  <ul className="space-y-1.5">
                    {finding.references.map((ref, idx) => (
                      <li key={idx} className="flex items-center gap-2 text-xs">
                        <ExternalLink size={12} className="text-zinc-400 shrink-0" />
                        <a
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-zinc-300 hover:text-white hover:underline truncate font-mono"
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
                    <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider font-mono">
                      HTTP Request Payload
                    </span>
                    <button
                      onClick={() => handleCopy(finding.evidence.request || '', 'req')}
                      className="text-xs text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors"
                    >
                      {copiedSection === 'req' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      <span>{copiedSection === 'req' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-3.5 bg-[#09090B] border border-zinc-800 rounded-xl text-xs font-mono text-rose-300 overflow-x-auto whitespace-pre leading-relaxed shadow-inner">
                    {finding.evidence.request}
                  </pre>
                </div>
              )}

              {finding.evidence.response && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider font-mono">
                      Server Response
                    </span>
                    <button
                      onClick={() => handleCopy(finding.evidence.response || '', 'res')}
                      className="text-xs text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors"
                    >
                      {copiedSection === 'res' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      <span>{copiedSection === 'res' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-3.5 bg-[#09090B] border border-zinc-800 rounded-xl text-xs font-mono text-zinc-300 overflow-x-auto whitespace-pre leading-relaxed shadow-inner">
                    {finding.evidence.response}
                  </pre>
                </div>
              )}

              {finding.evidence.rawSnippet && (
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider font-mono">
                    Raw Scanner Banner Output
                  </span>
                  <pre className="p-3.5 bg-[#09090B] border border-zinc-800 rounded-xl text-xs font-mono text-zinc-300 overflow-x-auto whitespace-pre shadow-inner">
                    {finding.evidence.rawSnippet}
                  </pre>
                </div>
              )}

              {finding.evidence.matchedPattern && (
                <div className="p-3.5 rounded-xl border border-amber-900/50 bg-amber-950/40 text-xs space-y-1">
                  <span className="font-semibold text-amber-300 font-mono">Trigger Match Pattern:</span>
                  <code className="block font-mono text-amber-200 text-xs mt-1">
                    {finding.evidence.matchedPattern}
                  </code>
                </div>
              )}
            </div>
          )}

          {activeTab === 'ai' && (
            <div className="space-y-5">
              <div className="p-4 rounded-xl border border-zinc-800 bg-[#18181B] space-y-3">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-lg bg-zinc-800 text-zinc-200">
                    <Cpu size={16} />
                  </div>
                  <span className="text-xs font-bold text-zinc-200 uppercase tracking-wider font-mono">
                    AI Agent Reasoning & Threat Assessment
                  </span>
                </div>
                <p className="text-sm text-zinc-300 leading-relaxed">
                  {finding.aiAnalysis.summary}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3.5 rounded-xl border border-zinc-800 bg-[#18181B] space-y-1">
                  <span className="text-zinc-500 font-mono">Attack Vector</span>
                  <p className="font-mono text-zinc-200 font-medium">{finding.aiAnalysis.attackVector}</p>
                </div>
                <div className="p-3.5 rounded-xl border border-zinc-800 bg-[#18181B] space-y-1">
                  <span className="text-zinc-500 font-mono">Exploitation Likelihood</span>
                  <p className="font-mono text-red-400 font-semibold">{finding.aiAnalysis.exploitLikelihood}</p>
                </div>
              </div>

              <div className="p-4 rounded-xl border border-zinc-800 bg-[#18181B] space-y-2 shadow-xs">
                <h5 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider font-mono">
                  Impact Assessment
                </h5>
                <p className="text-xs text-zinc-300 leading-relaxed">
                  {finding.aiAnalysis.impact}
                </p>
              </div>
            </div>
          )}

          {activeTab === 'remediation' && (
            <div className="space-y-5">
              <div className="p-4 rounded-xl border border-emerald-900/50 bg-emerald-950/30 space-y-2">
                <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider font-mono">
                  Remediation Summary
                </span>
                <p className="text-sm text-emerald-200 leading-relaxed">
                  {finding.remediation.summary}
                </p>
              </div>

              <div className="space-y-3">
                <h5 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider font-mono">
                  Implementation Steps
                </h5>
                <div className="space-y-2">
                  {finding.remediation.steps.map((step, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 text-xs text-zinc-300">
                      <span className="flex items-center justify-center w-5 h-5 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-300 shrink-0 font-mono text-[11px] font-bold">
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
                    <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider font-mono flex items-center gap-1.5">
                      <FileCode size={14} className="text-zinc-400" />
                      Recommended Patch ({finding.remediation.codeSnippet.language})
                    </span>
                    <button
                      onClick={() => handleCopy(finding.remediation.codeSnippet?.after || '', 'patch')}
                      className="text-xs text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors"
                    >
                      {copiedSection === 'patch' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      <span>{copiedSection === 'patch' ? 'Copied' : 'Copy Patch'}</span>
                    </button>
                  </div>

                  {finding.remediation.codeSnippet.before && (
                    <div>
                      <span className="text-[10px] text-red-400 font-mono block mb-1">− Vulnerable:</span>
                      <pre className="p-2.5 bg-red-950/40 border border-red-900/60 rounded-lg text-xs font-mono text-red-300 overflow-x-auto whitespace-pre">
                        {finding.remediation.codeSnippet.before}
                      </pre>
                    </div>
                  )}

                  <div>
                    <span className="text-[10px] text-emerald-400 font-mono block mb-1">+ Secure Fix:</span>
                    <pre className="p-2.5 bg-emerald-950/40 border border-emerald-900/60 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre">
                      {finding.remediation.codeSnippet.after}
                    </pre>
                  </div>
                  <p className="text-[11px] text-zinc-500 italic">
                    {finding.remediation.codeSnippet.description}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-zinc-800 bg-[#121214] flex items-center justify-between">
          <span className="text-xs text-zinc-500 font-mono">
            Sentinel AI • Normalized Finding Record
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-zinc-800 border border-zinc-700 text-xs font-medium text-zinc-200 hover:bg-zinc-700 hover:text-white transition-colors shadow-xs"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
