import React, { useState, useMemo } from 'react';
import {
  Globe,
  Network,
  Server,
  Link2,
  FileCode,
  Bug,
  ChevronRight,
  ChevronDown,
  Layers,
  Search,
  AlertCircle,
  Shield,
} from 'lucide-react';
import { AssetOut, AssetType, VerificationStatus } from '../../types/contract';
import { Finding } from '../../types/finding';
import { EmptyState } from '../common/EmptyState';
import { SeverityBadge } from '../common/SeverityBadge';

export interface AttackSurfaceTreeProps {
  assets: AssetOut[];
  findings?: Finding[];
  isLoading?: boolean;
  error?: string | null;
  onSelectFinding?: (finding: Finding) => void;
}

interface AssetNode {
  asset: AssetOut;
  children: AssetNode[];
  findings: Finding[];
}

/**
 * Builds a strict hierarchy from flat AssetOut[] using parent_asset_id.
 * Run in O(N + F) time using a Map lookup. Does NOT infer or guess parents.
 */
function buildAssetHierarchy(assets: AssetOut[], findings: Finding[] = []): AssetNode[] {
  const nodeMap = new Map<string, AssetNode>();

  // 1. Group findings by assetId
  const findingsByAssetId = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.assetId) {
      const list = findingsByAssetId.get(f.assetId) || [];
      list.push(f);
      findingsByAssetId.set(f.assetId, list);
    }
  }

  // 2. Register all nodes in map
  for (const asset of assets) {
    nodeMap.set(asset.id, {
      asset,
      children: [],
      findings: findingsByAssetId.get(asset.id) || [],
    });
  }

  // 3. Connect nodes to parents in the same scan
  const roots: AssetNode[] = [];
  for (const asset of assets) {
    const node = nodeMap.get(asset.id);
    if (!node) continue;

    const parentId = asset.parent_asset_id;
    if (parentId && nodeMap.has(parentId)) {
      nodeMap.get(parentId)!.children.push(node);
    } else {
      // Roots: parent_asset_id is null OR parent not in current set
      roots.push(node);
    }
  }

  return roots;
}

function getAssetTypeIcon(type: AssetType) {
  switch (type) {
    case 'domain':
      return Globe;
    case 'subdomain':
      return Network;
    case 'host':
      return Server;
    case 'service':
      return Layers;
    case 'url':
      return Link2;
    case 'endpoint':
      return FileCode;
    default:
      return Globe;
  }
}

function getVerificationBadge(status?: VerificationStatus | string) {
  if (!status) return null;
  switch (status) {
    case 'resolved':
      return (
        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/70 border border-emerald-800 text-emerald-300">
          Resolved
        </span>
      );
    case 'unverified':
      return (
        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-950/60 border border-amber-800 text-amber-300">
          Unverified
        </span>
      );
    case 'nxdomain':
      return (
        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-950/70 border border-rose-800 text-rose-300">
          NXDOMAIN
        </span>
      );
    case 'error':
      return (
        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-950/70 border border-rose-800 text-rose-300">
          DNS Error
        </span>
      );
    default:
      return (
        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-sentinel-bg border border-sentinel-border text-sentinel-muted capitalize">
          {String(status)}
        </span>
      );
  }
}

interface TreeNodeItemProps {
  node: AssetNode;
  expandedMap: Record<string, boolean>;
  onToggle: (id: string) => void;
  onSelectFinding?: (finding: Finding) => void;
}

const TreeNodeItem: React.FC<TreeNodeItemProps> = ({
  node,
  expandedMap,
  onToggle,
  onSelectFinding,
}) => {
  const { asset, children, findings } = node;
  const hasChildren = children.length > 0;
  const isExpanded = expandedMap[asset.id] ?? true;
  const Icon = getAssetTypeIcon(asset.asset_type);

  // Extract DNS attributes safely
  const dnsA = Array.isArray(asset.attributes?.dns_a) ? asset.attributes.dns_a : [];
  const dnsAaaa = Array.isArray(asset.attributes?.dns_aaaa) ? asset.attributes.dns_aaaa : [];
  const dnsCname = Array.isArray(asset.attributes?.dns_cname) ? asset.attributes.dns_cname : [];
  const hasDns = dnsA.length > 0 || dnsAaaa.length > 0 || dnsCname.length > 0;

  // Source info
  const sourceTool = asset.source_tool || '';
  const discoverySource =
    typeof asset.attributes?.source === 'string' && asset.attributes.source !== sourceTool
      ? asset.attributes.source
      : null;

  return (
    <div className="space-y-2">
      {/* Node Row Card */}
      <div className="p-3 rounded-xl border border-sentinel-border bg-sentinel-surface/80 hover:border-sentinel-border-light transition-colors space-y-2">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          {/* Left: Expand Toggle + Icon + Asset Value */}
          <div className="flex items-center gap-2 min-w-0">
            {hasChildren ? (
              <button
                onClick={() => onToggle(asset.id)}
                className="p-1 rounded hover:bg-sentinel-elevated text-sentinel-dim hover:text-sentinel-text transition-colors shrink-0"
                aria-label={isExpanded ? 'Collapse node' : 'Expand node'}
              >
                {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              </button>
            ) : (
              <span className="w-5 shrink-0" />
            )}

            <div className="w-7 h-7 rounded-lg bg-cyan-950/50 border border-cyan-800/60 flex items-center justify-center text-sentinel-cyan shrink-0">
              <Icon size={14} />
            </div>

            <div className="min-w-0 flex items-center gap-2 flex-wrap">
              <span className="font-mono text-xs font-semibold text-sentinel-text truncate max-w-sm sm:max-w-md">
                {asset.value || 'Unnamed Asset'}
              </span>

              {/* Type Badge */}
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-sentinel-elevated border border-sentinel-border text-sentinel-dim">
                {asset.asset_type}
              </span>

              {/* Backend Verification Status */}
              {getVerificationBadge(asset.attributes?.verification_status)}
            </div>
          </div>

          {/* Right: Source Tool + Findings Count */}
          <div className="flex items-center gap-2 shrink-0 pl-7 sm:pl-0">
            {sourceTool && (
              <span
                className="px-2 py-0.5 rounded text-[10px] font-mono bg-sentinel-bg border border-sentinel-border text-sentinel-muted"
                title={discoverySource ? `Source: ${discoverySource}` : undefined}
              >
                {sourceTool}
                {discoverySource && ` (${discoverySource})`}
              </span>
            )}

            {findings.length > 0 && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/70 border border-rose-800 text-rose-300">
                <Bug size={11} />
                <span>{findings.length}</span>
              </span>
            )}
          </div>
        </div>

        {/* DNS Enrichment (Observational Data Only) */}
        {hasDns && (
          <div className="pl-7 pt-1 border-t border-sentinel-border/40 flex flex-wrap items-center gap-2 text-[11px]">
            <span className="text-[10px] font-mono text-sentinel-dim uppercase">DNS Data:</span>
            {dnsA.map((ip) => (
              <span
                key={ip}
                className="px-1.5 py-0.2 rounded bg-sentinel-bg/80 border border-sentinel-border/80 text-sentinel-muted font-mono text-[10px]"
                title="Observational IPv4 enrichment (Data only - not an authorized scan target)"
              >
                A: {ip}
              </span>
            ))}
            {dnsAaaa.map((ip) => (
              <span
                key={ip}
                className="px-1.5 py-0.2 rounded bg-sentinel-bg/80 border border-sentinel-border/80 text-sentinel-muted font-mono text-[10px]"
                title="Observational IPv6 enrichment (Data only - not an authorized scan target)"
              >
                AAAA: {ip}
              </span>
            ))}
            {dnsCname.map((cname) => (
              <span
                key={cname}
                className="px-1.5 py-0.2 rounded bg-sentinel-bg/80 border border-sentinel-border/80 text-sentinel-muted font-mono text-[10px]"
                title="Observational CNAME alias (Data only - not an authorized scan target)"
              >
                CNAME: {cname}
              </span>
            ))}
          </div>
        )}

        {/* Findings Attached via asset_id */}
        {findings.length > 0 && (
          <div className="pl-7 pt-1.5 border-t border-rose-950/40 space-y-1">
            <span className="text-[10px] font-mono text-rose-300/80 block uppercase tracking-wider">
              Linked Vulnerabilities ({findings.length}):
            </span>
            <div className="space-y-1">
              {findings.map((f) => (
                <div
                  key={f.id}
                  onClick={() => onSelectFinding?.(f)}
                  className={`flex items-center justify-between p-1.5 rounded-lg bg-sentinel-bg/60 border border-sentinel-border/60 text-xs transition-colors ${
                    onSelectFinding ? 'cursor-pointer hover:border-sentinel-border-light' : ''
                  }`}
                >
                  <div className="flex items-center gap-2 truncate">
                    <SeverityBadge severity={f.severity} size="sm" />
                    <span className="text-sentinel-text truncate font-medium text-[11px]">
                      {f.title}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-sentinel-dim shrink-0 pl-2">
                    {f.tool}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Children Hierarchy */}
      {hasChildren && isExpanded && (
        <div className="pl-4 sm:pl-6 border-l-2 border-sentinel-border/60 ml-3 sm:ml-4 space-y-2">
          {children.map((child) => (
            <TreeNodeItem
              key={child.asset.id}
              node={child}
              expandedMap={expandedMap}
              onToggle={onToggle}
              onSelectFinding={onSelectFinding}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export const AttackSurfaceTree: React.FC<AttackSurfaceTreeProps> = ({
  assets,
  findings = [],
  isLoading = false,
  error = null,
  onSelectFinding,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [expandedMap, setExpandedMap] = useState<Record<string, boolean>>({});

  // Filter assets and build hierarchy, preserving ancestor chain so matching
  // children/subdomains remain nested under their true parent_asset_id
  const { filteredAssets, treeRoots, matchCount } = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();

    // Fast path: no filter applied
    if (!query && selectedType === 'all') {
      return {
        filteredAssets: assets,
        treeRoots: buildAssetHierarchy(assets, findings),
        matchCount: assets.length,
      };
    }

    // 1. Map all assets by id for O(1) ancestor lookups
    const assetById = new Map<string, AssetOut>();
    for (const a of assets) {
      assetById.set(a.id, a);
    }

    // 2. Identify directly matching assets
    const directMatchIds = new Set<string>();
    for (const a of assets) {
      const matchesSearch =
        !query ||
        a.value.toLowerCase().includes(query) ||
        (a.host ? a.host.toLowerCase().includes(query) : false) ||
        a.source_tool.toLowerCase().includes(query);

      const matchesType = selectedType === 'all' || a.asset_type === selectedType;

      if (matchesSearch && matchesType) {
        directMatchIds.add(a.id);
      }
    }

    // 3. Include ancestors via parent_asset_id so children don't become artificial roots
    const includedIds = new Set<string>(directMatchIds);
    for (const id of directMatchIds) {
      let current = assetById.get(id);
      while (current?.parent_asset_id && assetById.has(current.parent_asset_id)) {
        const parentId = current.parent_asset_id;
        if (includedIds.has(parentId)) break;
        includedIds.add(parentId);
        current = assetById.get(parentId);
      }
    }

    // 4. Assemble filtered list preserving original array order
    const filtered: AssetOut[] = [];
    for (const a of assets) {
      if (includedIds.has(a.id)) {
        filtered.push(a);
      }
    }

    return {
      filteredAssets: filtered,
      treeRoots: buildAssetHierarchy(filtered, findings),
      matchCount: directMatchIds.size,
    };
  }, [assets, findings, searchQuery, selectedType]);

  const toggleExpand = (id: string) => {
    setExpandedMap((prev) => ({
      ...prev,
      [id]: !(prev[id] ?? true),
    }));
  };

  const expandAll = () => {
    const next: Record<string, boolean> = {};
    for (const a of assets) next[a.id] = true;
    setExpandedMap(next);
  };

  const collapseAll = () => {
    const next: Record<string, boolean> = {};
    for (const a of assets) next[a.id] = false;
    setExpandedMap(next);
  };

  if (isLoading) {
    return (
      <div className="py-12 text-center space-y-3">
        <div className="inline-block animate-spin w-6 h-6 border-2 border-sentinel-cyan border-t-transparent rounded-full" />
        <p className="text-xs text-sentinel-muted font-mono">Loading discovered attack surface...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 rounded-xl border border-rose-900/80 bg-rose-950/40 text-xs text-rose-300 flex items-center gap-2.5">
        <AlertCircle size={16} className="text-rose-400 shrink-0" />
        <span>{error}</span>
      </div>
    );
  }

  if (assets.length === 0) {
    return (
      <EmptyState
        icon={Network}
        title="No Discovered Assets"
        description="No assets or subdomains have been discovered for this scan yet. Subdomains discovered via Subfinder and verified by DNSX will populate here."
      />
    );
  }

  return (
    <div className="space-y-4">
      {/* Controls: Search, Type Filter, Expand/Collapse */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-sentinel-border/70">
        <div className="flex items-center gap-2 flex-1">
          {/* Search Input */}
          <div className="relative flex-1 max-w-sm">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search assets, hosts, subdomains..."
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs text-sentinel-text placeholder:text-sentinel-dim focus:outline-none focus:border-sentinel-cyan transition-colors"
            />
            <Search size={13} className="absolute left-2.5 top-2 text-sentinel-dim" />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1.5 text-sentinel-dim hover:text-sentinel-text text-xs"
              >
                ✕
              </button>
            )}
          </div>

          {/* Type Filter */}
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs text-sentinel-text focus:outline-none focus:border-sentinel-cyan transition-colors"
          >
            <option value="all">All Types</option>
            <option value="domain">Domain</option>
            <option value="subdomain">Subdomain</option>
            <option value="host">Host</option>
            <option value="service">Service</option>
            <option value="url">URL</option>
            <option value="endpoint">Endpoint</option>
          </select>
        </div>

        {/* Tree Action Buttons & Counts */}
        <div className="flex items-center gap-2 self-end sm:self-auto text-xs">
          <span className="font-mono text-sentinel-dim text-[11px] px-2 py-1 rounded bg-sentinel-elevated border border-sentinel-border">
            {matchCount} {matchCount === 1 ? 'match' : 'matches'}
            {matchCount !== filteredAssets.length && ` (${filteredAssets.length} in tree)`} of {assets.length} Assets
          </span>
          <button
            onClick={expandAll}
            className="px-2 py-1 rounded hover:bg-sentinel-elevated text-sentinel-muted hover:text-sentinel-text text-[11px] font-mono transition-colors"
          >
            Expand All
          </button>
          <span className="text-sentinel-border">|</span>
          <button
            onClick={collapseAll}
            className="px-2 py-1 rounded hover:bg-sentinel-elevated text-sentinel-muted hover:text-sentinel-text text-[11px] font-mono transition-colors"
          >
            Collapse All
          </button>
        </div>
      </div>

      {/* Security Disclaimer Banner */}
      <div className="px-3.5 py-2 rounded-lg bg-cyan-950/30 border border-cyan-900/50 text-[11px] text-sentinel-dim flex items-center gap-2">
        <Shield size={13} className="text-cyan-400 shrink-0" />
        <span>
          Hierarchical topology reconstructed using backend <code className="text-cyan-300">parent_asset_id</code>.
          DNS enrichment records are purely observational data.
        </span>
      </div>

      {/* Tree Roots Rendering */}
      {treeRoots.length === 0 ? (
        <div className="py-8 text-center text-xs text-sentinel-dim font-mono">
          No assets matched the specified filter criteria.
        </div>
      ) : (
        <div className="space-y-2.5">
          {treeRoots.map((root) => (
            <TreeNodeItem
              key={root.asset.id}
              node={root}
              expandedMap={expandedMap}
              onToggle={toggleExpand}
              onSelectFinding={onSelectFinding}
            />
          ))}
        </div>
      )}
    </div>
  );
};
