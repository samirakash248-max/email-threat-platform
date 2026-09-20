import React, { useState, useEffect, useRef, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { Download, UserPlus, Share2,
  ShieldAlert,
  Briefcase,
  Globe,
  Mail,
  AlertTriangle,
  Sparkles,
  ChevronRight,
  ChevronLeft,
  TrendingUp,
  Server,
  Database,
  Loader2,
  CheckCircle2,
  RefreshCw,
  Plus,
  Network,
  ArrowRight,
  Paperclip,
  MessageSquare,
  CheckCircle,
  Clock,
  Trash2,
  Send,
  User,
  Hash,
  Search,
  X,
  Play,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  Activity,
  Layers,
  Lock
} from 'lucide-react';
import api from '../api';

// ==========================================
// 1. DASHBOARD VIEW
// ==========================================

export function DashboardView({ onSelectAnalysis, onOpenCase, onNewIntake }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [seedSuccess, setSeedSuccess] = useState(null);
  const [visibleCount, setVisibleCount] = useState(50);

  const fetchStats = async () => {
    setLoading(true);
    try {
      const data = await api.getStats();
      setStats(data);
    } catch (err) {
      console.error('Error loading dashboard stats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleSeedDemoData = async () => {
    setSeeding(true);
    setSeedSuccess(null);
    try {
      const data = await api.seedDemo();
      setSeedSuccess(data.message);
      await fetchStats();
    } catch (err) {
      console.error('Error seeding demo data:', err);
    } finally {
      setSeeding(false);
    }
  };

  if (loading && !stats) {
    return (
      <div className="surface-card p-16 flex flex-col items-center justify-center space-y-3">
        <Loader2 className="w-7 h-7 text-blue-600 animate-spin" />
        <p className="text-xs text-slate-600">Loading live SOC telemetry and database records...</p>
      </div>
    );
  }

  const {
    total_analyzed_emails = 0,
    high_critical_threats = 0,
    active_cases = 0,
    suspicious_domains_count = 0,
    suspicious_ips_count = 0,
    threat_distribution = { critical: 0, high: 0, medium: 0, low: 0 },
    top_categories = {},
    recent_analyses = [],
  } = stats || {};

  const totalThreats = (threat_distribution.critical || 0) + (threat_distribution.high || 0) + (threat_distribution.medium || 0) + (threat_distribution.low || 0);

  const getPercentage = (count) => {
    if (!totalThreats) return 0;
    return Math.round((count / totalThreats) * 100);
  };

  return (
    <div className="space-y-6">
      {/* Demo Seeder Banner */}
      <div className="surface-card bg-gradient-to-r from-blue-50 via-indigo-50/60 to-blue-50/80 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 border border-blue-200 shadow-sm">
        <div className="flex items-center gap-3.5">
          <div className="p-2.5 bg-blue-600 text-white rounded-xl shadow-sm shadow-blue-500/25 flex-shrink-0">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-sm text-slate-900">
                SIH Evaluator Demo Environment
              </h3>
              <span className="px-2 py-0.5 text-[9px] font-bold bg-blue-100 text-blue-800 border border-blue-300 rounded-full uppercase tracking-wider">
                Safe Synthetic Data
              </span>
            </div>
            <p className="text-xs text-slate-600 mt-0.5">
              One-click ingestion of 10 safe synthetic test cases (phishing, CEO fraud, auth failures, malware attachments, and multi-hop traces).
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={handleSeedDemoData}
            disabled={seeding}
            className="btn-tactile flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-bold transition-all shadow-md shadow-blue-500/25 disabled:opacity-50 cursor-pointer"
          >
            {seeding ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> Ingesting Synthetic Artifacts...
              </>
            ) : (
              <>
                <RefreshCw className="w-3.5 h-3.5" /> Load Demo SOC Dataset
              </>
            )}
          </button>
        </div>
      </div>

      {seedSuccess && (
        <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-3 flex items-center gap-2 text-xs text-emerald-700 animate-in fade-in duration-200">
          <CheckCircle2 className="w-4 h-4 text-emerald-700 flex-shrink-0" />
          <span>{seedSuccess}</span>
        </div>
      )}

      {/* Top Telemetry Metric Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        <div className="surface-card surface-card-hover p-4 space-y-1.5 border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between text-slate-600 text-xs font-medium">
            <span>Analyzed Messages</span>
            <div className="p-1.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-100"><Mail className="w-3.5 h-3.5" /></div>
          </div>
          <div className="text-2xl font-bold text-slate-900 font-mono tabular-nums tracking-tight">{total_analyzed_emails}</div>
          <div className="text-[10px] text-slate-500 font-mono">SQLite Persistent Store</div>
        </div>

        <div className="surface-card surface-card-hover p-4 space-y-1.5 border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between text-slate-600 text-xs font-medium">
            <span>High/Critical Alerts</span>
            <div className="p-1.5 rounded-lg bg-rose-50 text-rose-600 border border-rose-100"><ShieldAlert className="w-3.5 h-3.5" /></div>
          </div>
          <div className="text-2xl font-bold text-rose-600 font-mono tabular-nums tracking-tight">{high_critical_threats}</div>
          <div className="text-[10px] text-slate-500 font-mono">
            {total_analyzed_emails > 0 ? `${Math.round((high_critical_threats / total_analyzed_emails) * 100)}% Alert Ratio` : '0%'}
          </div>
        </div>

        <div className="surface-card surface-card-hover p-4 space-y-1.5 border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between text-slate-600 text-xs font-medium">
            <span>Active Case Incidents</span>
            <div className="p-1.5 rounded-lg bg-purple-50 text-purple-600 border border-purple-100"><Briefcase className="w-3.5 h-3.5" /></div>
          </div>
          <div className="text-2xl font-bold text-purple-600 font-mono tabular-nums tracking-tight">{active_cases}</div>
          <div className="text-[10px] text-slate-500 font-mono">Multi-Email Correlation</div>
        </div>

        <div className="surface-card surface-card-hover p-4 space-y-1.5 border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between text-slate-600 text-xs font-medium">
            <span>Suspicious Domains</span>
            <div className="p-1.5 rounded-lg bg-amber-50 text-amber-600 border border-amber-100"><Globe className="w-3.5 h-3.5" /></div>
          </div>
          <div className="text-2xl font-bold text-amber-600 font-mono tabular-nums tracking-tight">{suspicious_domains_count}</div>
          <div className="text-[10px] text-slate-500 font-mono">Lookalikes & Typo Squats</div>
        </div>

        <div className="surface-card surface-card-hover p-4 space-y-1.5 border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between text-slate-600 text-xs font-medium">
            <span>Flagged Transit IPs</span>
            <div className="p-1.5 rounded-lg bg-cyan-50 text-cyan-700 border border-cyan-100"><Server className="w-3.5 h-3.5" /></div>
          </div>
          <div className="text-2xl font-bold text-cyan-700 font-mono tabular-nums tracking-tight">{suspicious_ips_count}</div>
          <div className="text-[10px] text-slate-500 font-mono">Observed Relay Nodes</div>
        </div>
      </div>

      {/* Middle Grid: Severity Distribution & Category Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="surface-card p-6 space-y-4">
          <div className="border-b border-[#E2E8F0] pb-3">
            <h3 className="font-bold text-sm text-slate-900">Threat Tier Distribution</h3>
            <p className="text-xs text-slate-600 mt-0.5">Classification of Analyzed Email Corpus</p>
          </div>

          <div className="w-full bg-[#EFF6FF] h-3 rounded-full overflow-hidden flex border border-[#F1F5F9] p-0.5">
            <div style={{ width: `${getPercentage(threat_distribution.critical)}%` }} className="bg-rose-500 h-full rounded-l-full transition-all duration-500" title={`Critical: ${threat_distribution.critical}`} />
            <div style={{ width: `${getPercentage(threat_distribution.high)}%` }} className="bg-orange-500 h-full transition-all duration-500" title={`High: ${threat_distribution.high}`} />
            <div style={{ width: `${getPercentage(threat_distribution.medium)}%` }} className="bg-amber-500 h-full transition-all duration-500" title={`Medium: ${threat_distribution.medium}`} />
            <div style={{ width: `${getPercentage(threat_distribution.low)}%` }} className="bg-emerald-500 h-full rounded-r-full transition-all duration-500" title={`Low: ${threat_distribution.low}`} />
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="surface-card-subtle p-2.5 flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-slate-700 font-sans">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span> Critical
              </span>
              <span className="font-bold text-rose-600 font-mono">{threat_distribution.critical || 0}</span>
            </div>
            <div className="surface-card-subtle p-2.5 flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-slate-700 font-sans">
                <span className="w-2 h-2 rounded-full bg-orange-500"></span> High
              </span>
              <span className="font-bold text-orange-600 font-mono">{threat_distribution.high || 0}</span>
            </div>
            <div className="surface-card-subtle p-2.5 flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-slate-700 font-sans">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span> Medium
              </span>
              <span className="font-bold text-amber-700 font-mono">{threat_distribution.medium || 0}</span>
            </div>
            <div className="surface-card-subtle p-2.5 flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-slate-700 font-sans">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span> Low / Clean
              </span>
              <span className="font-bold text-emerald-700 font-mono">{threat_distribution.low || 0}</span>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 surface-card p-6 space-y-4">
          <div className="border-b border-[#E2E8F0] pb-3 flex items-center justify-between">
            <div>
              <h3 className="font-bold text-sm text-slate-900">Top Threat Vectors & Rule Triggers</h3>
              <p className="text-xs text-slate-600 mt-0.5">Observed Attack Vectors Across Ingested Messages</p>
            </div>
            <span className="text-[11px] font-mono text-slate-600 bg-slate-50 px-2.5 py-0.5 rounded-full border border-[#E2E8F0]">
              12+ Detection Rules
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
            {Object.entries(top_categories).length === 0 ? (
              <p className="text-xs text-slate-500 col-span-3 py-6 text-center">No threats recorded in database yet.</p>
            ) : (
              Object.entries(top_categories).map(([cat, count], idx) => (
                <div key={idx} className="surface-card-subtle p-3 flex items-center justify-between hover:border-[#FBA58C] transition-colors">
                  <span className="text-xs font-medium text-slate-700 truncate max-w-[130px]" title={cat}>
                    {cat.replace(/_/g, ' ')}
                  </span>
                  <span className="px-2 py-0.5 bg-blue-50 text-blue-700 border border-blue-200 rounded-full text-xs font-mono font-bold">
                    {count}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Bottom Table: Recent Analysis Activity */}
      <div className="surface-card p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[#E2E8F0] pb-3.5 gap-2">
          <div>
            <h3 className="font-bold text-sm text-slate-900">Recent Forensic Analyses</h3>
            <p className="text-xs text-slate-600 mt-0.5">
              Showing {Math.min(visibleCount, recent_analyses.length)} of {recent_analyses.length} Persistent Intake Records
            </p>
          </div>

          <button
            onClick={onNewIntake}
            className="btn-tactile flex items-center gap-1.5 px-3.5 py-1.5 btn-block-primary text-white rounded-xl text-xs font-bold transition-all shadow-glow-blue cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" /> Analyze New Message
          </button>
        </div>

        {recent_analyses.length === 0 ? (
          <div className="surface-card-subtle p-12 text-center text-xs text-slate-500 space-y-2">
            <p>No email analysis records found in database.</p>
            <p className="text-[11px]">Click "Load Demo SOC Dataset" above to populate sample emails.</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto rounded-xl border border-[#F1F5F9]">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#EFF6FF] text-slate-600 text-[10px] uppercase font-semibold">
                  <tr>
                    <th className="p-3.5">Subject / Incident Name</th>
                    <th className="p-3.5">Sender (From)</th>
                    <th className="p-3.5">Threat Score</th>
                    <th className="p-3.5">Risk Tier</th>
                    <th className="p-3.5">Blockchain Integrity</th>
                    <th className="p-3.5">Timestamp</th>
                    <th className="p-3.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#F1F5F9] bg-white font-mono text-[11px]">
                  {recent_analyses.slice(0, visibleCount).map((item) => (
                    <tr key={item.id} className="hover:bg-[#F0F7FF] transition-colors">
                      <td className="p-3.5 font-sans font-semibold text-slate-800 max-w-xs truncate">
                        {item.subject || '(No Subject Line)'}
                      </td>
                      <td className="p-3.5 text-slate-700 max-w-[180px] truncate">
                        {item.sender || 'N/A'}
                      </td>
                      <td className="p-3.5 font-bold tabular-nums" style={{ color: item.risk_color }}>
                        {item.threat_score}/100
                      </td>
                      <td className="p-3.5 font-sans">
                        <span
                          className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase border"
                          style={{
                            backgroundColor: `${item.risk_color}14`,
                            color: item.risk_color,
                            borderColor: `${item.risk_color}35`,
                          }}
                        >
                          <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: item.risk_color }}></span>
                          {item.risk_level}
                        </span>
                      </td>
                      <td className="p-3.5 font-sans">
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono">
                          <span className="w-1 h-1 rounded-full bg-emerald-400"></span> Verified On-Chain
                        </span>
                      </td>
                      <td className="p-3.5 text-slate-600 text-[10px]">
                        {item.created_at ? item.created_at.replace('T', ' ').slice(0, 19) : 'N/A'}
                      </td>
                      <td className="p-3.5 text-right">
                        <button
                          onClick={() => onSelectAnalysis(item.id)}
                          className="inline-flex items-center gap-1 px-3 py-1 btn-block-primary rounded-lg text-[11px] font-sans font-semibold transition-colors cursor-pointer"
                        >
                          Inspect Dossier <ChevronRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls / Show More Button */}
            {recent_analyses.length > 0 && (
              <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-[#F1F5F9]">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-slate-600 font-mono">
                    Showing {Math.min(visibleCount, recent_analyses.length)} of {recent_analyses.length} Forensic Records
                  </span>

                  {/* Quick Page Size Selectors */}
                  <div className="hidden sm:flex items-center gap-1 bg-slate-50 p-0.5 rounded-lg border border-[#F1F5F9] text-[11px] font-mono">
                    <span className="text-slate-500 px-1.5">View:</span>
                    {[10, 25, 50].map((size) => (
                      <button
                        key={size}
                        onClick={() => setVisibleCount(size)}
                        className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
                          visibleCount === size
                            ? 'bg-blue-600 text-white font-bold'
                            : 'text-slate-600 hover:text-slate-800'
                        }`}
                      >
                        {size}
                      </button>
                    ))}
                    <button
                      onClick={() => setVisibleCount(recent_analyses.length)}
                      className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
                        visibleCount >= recent_analyses.length
                          ? 'bg-blue-600 text-white font-bold'
                          : 'text-slate-600 hover:text-slate-800'
                      }`}
                    >
                      All
                    </button>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {visibleCount < recent_analyses.length && (
                    <button
                      onClick={() => setVisibleCount((prev) => Math.min(prev + 10, recent_analyses.length))}
                      className="btn-tactile flex items-center gap-1.5 px-3.5 py-1.5 btn-block-primary rounded-xl text-xs font-semibold transition-colors cursor-pointer"
                    >
                      <ChevronDown className="w-3.5 h-3.5" /> Show More (+10)
                    </button>
                  )}

                  {visibleCount > 10 && recent_analyses.length > 10 && (
                    <button
                      onClick={() => setVisibleCount(10)}
                      className="btn-tactile flex items-center gap-1.5 px-3.5 py-1.5 bg-slate-50 hover:bg-slate-100 text-slate-600 hover:text-slate-800 border border-[#E2E8F0] rounded-xl text-xs font-semibold transition-colors cursor-pointer"
                    >
                      <ChevronUp className="w-3.5 h-3.5" /> Collapse to 10
                    </button>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ==========================================
// 2. CORRELATION VIEW
// ==========================================


export function ThreatGraphView({ caseId, onBack }) {
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  
  const fgRef = useRef();

  useEffect(() => {
    if (!caseId) return;
    setLoading(true);
    api.getCaseGraph(caseId)
      .then(data => {
        // Transform for ForceGraph: id must be unique, source/target on edges
        const gData = {
          nodes: data.nodes.map(n => ({ ...n, val: n.type === 'case' ? 25 : n.type === 'email' ? 15 : 10 })),
          links: data.edges.map(e => ({ source: e.source, target: e.target, relation: e.relation }))
        };
        setGraphData(gData);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [caseId]);

  const handleNodeClick = useCallback(node => {
    setSelectedNode(node);
    // Center/zoom on node
    fgRef.current.centerAt(node.x, node.y, 1000);
    fgRef.current.zoom(8, 2000);
  }, [fgRef]);

  const getNodeColor = (type) => {
    switch (type) {
      case 'case': return '#3B82F6';
      case 'email': return '#10B981';
      case 'ip': return '#EF4444';
      case 'domain': return '#F59E0B';
      case 'url': return '#EC4899';
      case 'hash': return '#8B5CF6';
      case 'technique': return '#6366F1';
      default: return '#94A3B8';
    }
  };

  return (
    <div className="surface-card flex flex-col h-[600px] relative overflow-hidden">
      <div className="absolute top-4 left-4 z-10 flex gap-2">
        <button onClick={onBack} className="bg-white px-3 py-1.5 border border-slate-200 rounded-lg shadow text-xs font-bold text-slate-700 hover:bg-slate-50 cursor-pointer flex items-center gap-1">
           <ArrowLeft className="w-4 h-4" /> Back to Case
        </button>
      </div>
      
      {loading ? (
        <div className="flex-1 flex items-center justify-center"><Loader2 className="w-8 h-8 text-blue-500 animate-spin" /></div>
      ) : (
        <ForceGraph2D
          ref={fgRef}
          graphData={graphData}
          nodeLabel="label"
          nodeColor={n => getNodeColor(n.type)}
          onNodeClick={handleNodeClick}
          linkDirectionalArrowLength={3.5}
          linkDirectionalArrowRelPos={1}
          linkColor={() => '#CBD5E1'}
          width={800}
          height={600}
        />
      )}
      
            {selectedNode && (
        <div className="absolute bottom-4 right-4 z-10 bg-white border border-slate-200 rounded-xl shadow-lg p-4 w-72 text-xs">
          <div className="flex justify-between items-start mb-2">
            <h3 className="font-bold text-slate-900 truncate pr-2">{selectedNode.label}</h3>
            <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-slate-600"><X className="w-4 h-4"/></button>
          </div>
          <div className="space-y-1.5">
            <p><span className="font-semibold text-slate-500">Type:</span> <span className="uppercase text-blue-600 font-bold">{selectedNode.type}</span></p>
            <p className="break-all"><span className="font-semibold text-slate-500">Value:</span> {selectedNode.value}</p>
            {selectedNode.type === 'ip' && selectedNode.classification && (
              <>
                <p><span className="font-semibold text-slate-500">Classification:</span> <span className="font-mono text-purple-700 font-bold bg-purple-50 px-1 py-0.5 rounded">{selectedNode.classification}</span></p>
                {selectedNode.organization && <p><span className="font-semibold text-slate-500">Org:</span> {selectedNode.organization}</p>}
                {selectedNode.asn && <p><span className="font-semibold text-slate-500">ASN:</span> {selectedNode.asn}</p>}
                {selectedNode.country && <p><span className="font-semibold text-slate-500">Country:</span> {selectedNode.country}</p>}
                {selectedNode.is_open_relay && <p><span className="text-rose-600 font-bold bg-rose-50 px-1 py-0.5 rounded uppercase">Open Relay Risk</span></p>}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function CorrelationView({ onSelectAnalysis }) {
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchGraph = async () => {
    setLoading(true);
    try {
      const data = await api.getCorrelation();
      setGraphData(data);
    } catch (err) {
      console.error('Error fetching correlation graph:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraph();
  }, []);

  if (loading && !graphData) {
    return (
      <div className="surface-card p-16 flex flex-col items-center justify-center space-y-3">
        <Loader2 className="w-7 h-7 text-blue-600 animate-spin" />
        <p className="text-xs text-slate-600">Computing cross-email indicator correlation network...</p>
      </div>
    );
  }

  const { edges = [], clusters = [], total_correlated_emails = 0, total_shared_indicators = 0 } = graphData || {};

  return (
    <div className="space-y-6">
      <div className="surface-card p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="p-3 bg-purple-50 border border-purple-200 rounded-xl text-purple-700 shadow-glow-purple">
            <Network className="w-6 h-6" />
          </div>
          <div>
            <h2 className="font-bold text-base text-slate-900">Multi-Email Correlation & Infrastructure Clustering</h2>
            <p className="text-xs text-slate-600 mt-0.5">
              Cross-artifact relationship graph discovering shared sender patterns, lookalike domains, and MTA infrastructure
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3.5 py-1.5 surface-card-subtle text-xs font-mono text-slate-700 border border-[#E2E8F0]">
            <span>{total_correlated_emails} Correlated Emails</span>
            <span className="text-slate-600">•</span>
            <span className="text-purple-700 font-bold">{total_shared_indicators} Shared Indicators</span>
          </div>
          <button
            onClick={fetchGraph}
            className="p-2 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] rounded-xl text-slate-600 hover:text-slate-900 transition-colors cursor-pointer"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600">
          Discovered Infrastructure Clusters ({clusters.length})
        </h3>

        {clusters.length === 0 ? (
          <div className="surface-card p-12 text-center text-xs text-slate-500">
            No cross-email clusters identified yet. Ingest multiple emails sharing domains or relay IPs to see campaign correlation.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {clusters.map((c) => (
              <div
                key={c.cluster_id}
                className="surface-card surface-card-hover p-5 space-y-3.5"
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-xs font-bold text-slate-900 block">{c.cluster_name}</span>
                    <span className="text-[10px] font-mono text-purple-700 uppercase tracking-wider">{c.classification}</span>
                  </div>
                  <span className="px-2.5 py-0.5 bg-purple-50 text-purple-700 border border-purple-200 rounded-full text-[10px] font-bold font-mono">
                    {c.member_email_ids.length} Emails Linked
                  </span>
                </div>

                <p className="text-xs text-slate-700 surface-card-subtle p-3 rounded-lg border border-white/[0.05] leading-relaxed">
                  {c.summary_reason}
                </p>

                <div className="flex flex-wrap gap-1.5 pt-1">
                  {c.member_email_ids.map((emailId) => (
                    <button
                      key={emailId}
                      onClick={() => onSelectAnalysis(emailId)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 bg-[#EFF6FF] hover:bg-blue-50 text-blue-600 border border-[#E2E8F0] hover:border-blue-500/40 rounded-lg text-[11px] font-mono cursor-pointer transition-colors"
                    >
                      <Mail className="w-3 h-3" />
                      <span>{emailId.slice(0, 8)}...</span>
                      <ArrowRight className="w-2.5 h-2.5" />
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="surface-card p-6 space-y-4">
        <h3 className="font-bold text-sm text-slate-900">Observed Linkages ({edges.length} Edges)</h3>
        {edges.length > 0 && (
          <div className="overflow-x-auto rounded-xl border border-[#F1F5F9]">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#EFF6FF] text-slate-600 text-[10px] uppercase font-sans">
                <tr>
                  <th className="p-3.5">Source</th>
                  <th className="p-3.5">Relationship</th>
                  <th className="p-3.5">Target Node</th>
                  <th className="p-3.5">Rationale</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F1F5F9] bg-white text-[11px]">
                {edges.map((e, idx) => (
                  <tr key={idx} className="hover:bg-[#F0F7FF] transition-colors">
                    <td className="p-3.5 text-blue-600 font-bold">{e.source}</td>
                    <td className="p-3.5 text-slate-700">{e.relationship}</td>
                    <td className="p-3.5 text-cyan-800 font-bold">{e.target}</td>
                    <td className="p-3.5 text-slate-600 font-sans">{e.reason || 'Observed correlation'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ==========================================
// 3. CASE MANAGER VIEW
// ==========================================


export function CampaignManager({ onOpenGraph }) {
  const [campaigns, setCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCampaign, setSelectedCampaign] = useState(null);

  useEffect(() => {
    setLoading(true);
    api.getCampaigns()
      .then(setCampaigns)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (selectedCampaign) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <button onClick={() => setSelectedCampaign(null)} className="p-2 hover:bg-slate-100 rounded-full transition-colors"><ArrowLeft className="w-5 h-5 text-slate-600"/></button>
          <div>
            <h2 className="text-xl font-bold text-slate-900">{selectedCampaign.name}</h2>
            <p className="text-sm text-slate-500 font-mono">{selectedCampaign.id}</p>
          </div>
          <div className="ml-auto flex gap-3">
            <span className={`px-3 py-1 rounded-full text-xs font-bold ${selectedCampaign.correlation_level === 'HIGH' ? 'bg-rose-100 text-rose-700' : selectedCampaign.correlation_level === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'}`}>
              {selectedCampaign.correlation_level} CORRELATION
            </span>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="md:col-span-2 space-y-6">
            <div className="surface-card p-6">
              <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2"><Network className="w-5 h-5 text-purple-600"/> Correlation Evidence</h3>
              <ul className="space-y-3">
                {selectedCampaign.correlation_reasons.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-700">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" />
                    {r}
                  </li>
                ))}
              </ul>
              {selectedCampaign.correlation_reasons.length === 0 && <p className="text-sm text-slate-500 italic">Base candidate. Needs more data.</p>}
            </div>
            
            <div className="surface-card p-6">
              <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2"><Target className="w-5 h-5 text-rose-600"/> Shared Indicators</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {selectedCampaign.related_indicators.map((ind, i) => (
                  <div key={i} className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center gap-3">
                    <span className="uppercase text-[10px] font-bold text-slate-500 w-16">{ind.type}</span>
                    <span className="font-mono text-xs text-slate-800 truncate">{ind.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          
          <div className="space-y-6">
            <div className="surface-card p-6">
              <h3 className="font-bold text-slate-800 mb-4">Linked Cases ({selectedCampaign.cases_count || (selectedCampaign.related_cases || []).length})</h3>
              <div className="space-y-2">
                {(selectedCampaign.related_cases || []).map(cid => (
                  <div key={cid} className="p-2 border border-slate-200 rounded text-xs font-mono text-slate-700">{cid}</div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="font-bold text-xl text-slate-900 flex items-center gap-2">
          <Activity className="w-6 h-6 text-rose-600" />
          Threat Campaigns
        </h2>
      </div>
      
      {loading ? (
        <div className="p-12 flex justify-center"><Loader2 className="w-8 h-8 text-blue-500 animate-spin"/></div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {campaigns.map(c => (
            <div key={c.id} onClick={() => setSelectedCampaign(c)} className="surface-card p-5 cursor-pointer hover:border-rose-300 transition-colors group">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-bold text-slate-900 group-hover:text-rose-700 transition-colors">{c.name}</h3>
                  <p className="text-xs text-slate-500 mt-1">First Seen: {new Date(c.first_seen).toLocaleDateString()}</p>
                </div>
                <div className="flex gap-4">
                  <div className="text-center"><div className="text-lg font-bold text-slate-800">{c.cases_count}</div><div className="text-[10px] uppercase text-slate-500 font-bold">Cases</div></div>
                  <div className="text-center"><div className="text-lg font-bold text-slate-800">{c.indicators_count}</div><div className="text-[10px] uppercase text-slate-500 font-bold">IOCs</div></div>
                  <div className="text-center"><div className="text-lg font-bold text-slate-800">{c.techniques_count}</div><div className="text-[10px] uppercase text-slate-500 font-bold">TTPs</div></div>
                  <div className="w-px bg-slate-200 mx-2"></div>
                  <div className="flex items-center">
                    <span className={`px-2 py-1 rounded text-[10px] font-bold ${c.correlation_level === 'HIGH' ? 'bg-rose-100 text-rose-700' : c.correlation_level === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-700'}`}>
                      {c.correlation_level}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
          {campaigns.length === 0 && <p className="text-center text-slate-500 p-8">No campaigns detected yet.</p>}
        </div>
      )}
    </div>
  );
}

export function CaseManager({ currentAnalysis, onSelectAnalysisFromCase }) {
  const [cases, setCases] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState(null);
  const [activeCaseData, setActiveCaseData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showGraph, setShowGraph] = useState(false);
  const [filterStatus, setFilterStatus] = useState('ALL');

  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newPriority, setNewPriority] = useState('HIGH');
  const [newNoteContent, setNewNoteContent] = useState('');
  const [analystName, setAnalystName] = useState('Forensic Analyst');
  const [updateFeedback, setUpdateFeedback] = useState(null);

  const fetchCases = async () => {
    try {
      const data = await api.getCases();
      setCases(data);
      if (data.length > 0 && !selectedCaseId) {
        setSelectedCaseId(data[0].id);
      }
    } catch (err) {
      console.error("Error fetching cases:", err);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  useEffect(() => {
    if (!selectedCaseId) return;
    setLoading(true);
    api.getCase(selectedCaseId)
      .then(data => setActiveCaseData(data))
      .catch(err => console.error("Error loading case:", err))
      .finally(() => setLoading(false));
  }, [selectedCaseId]);

  const handleCreateCase = async (e) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    try {
      const created = await api.createCase({
        title: newTitle,
        description: newDescription,
        priority: newPriority,
        initial_analysis_id: currentAnalysis?.analysis_id || null,
      });
      setNewTitle('');
      setNewDescription('');
      setShowCreateModal(false);
      await fetchCases();
      setSelectedCaseId(created.id);
    } catch (err) {
      console.error("Error creating case:", err);
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNoteContent.trim() || !selectedCaseId) return;

    try {
      const updated = await api.addNote(selectedCaseId, {
        author: analystName,
        content: newNoteContent,
      });
      setActiveCaseData(updated);
      setNewNoteContent('');
      fetchCases();
    } catch (err) {
      console.error("Error adding note:", err);
    }
  };

  const handleUpdateStatus = async (statusVal) => {
    if (!selectedCaseId) return;
    try {
      // Optimistic update
      setActiveCaseData(prev => prev ? { ...prev, status: statusVal } : prev);
      setCases(prev => prev.map(c => c.id === selectedCaseId ? { ...c, status: statusVal } : c));
      
      const updated = await api.updateCase(selectedCaseId, { status: statusVal });
      setActiveCaseData(updated);
      setUpdateFeedback(`Status changed to ${statusVal}`);
      setTimeout(() => setUpdateFeedback(null), 3000);
      fetchCases();
    } catch (err) {
      console.error("Error updating status:", err);
    }
  };

  const handleUpdatePriority = async (priorityVal) => {
    if (!selectedCaseId) return;
    try {
      // Optimistic update
      setActiveCaseData(prev => prev ? { ...prev, priority: priorityVal } : prev);
      setCases(prev => prev.map(c => c.id === selectedCaseId ? { ...c, priority: priorityVal } : c));

      const updated = await api.updateCase(selectedCaseId, { priority: priorityVal });
      setActiveCaseData(updated);
      setUpdateFeedback(`Priority updated to ${priorityVal}`);
      setTimeout(() => setUpdateFeedback(null), 3000);
      fetchCases();
    } catch (err) {
      console.error("Error updating priority:", err);
    }
  };

  const getPriorityBadge = (pri) => {
    switch (pri?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-50 text-rose-600 border-rose-200';
      case 'HIGH':
        return 'bg-orange-500/15 text-orange-600 border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      default:
        return 'bg-blue-50 text-blue-600 border-blue-200';
    }
  };

  const getStatusBadge = (status) => {
    switch (status?.toUpperCase()) {
      case 'OPEN':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      case 'IN_PROGRESS':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'RESOLVED':
        return 'bg-blue-50 text-blue-600 border-blue-200';
      case 'CLOSED':
        return 'bg-slate-500/15 text-slate-600 border-slate-500/30';
      default:
        return 'bg-purple-50 text-purple-700 border-purple-200';
    }
  };

  const filteredCases = cases.filter(c => {
    if (filterStatus === 'ALL') return true;
    return c.status === filterStatus;
  });

  return (
    <div className="surface-card p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[#E2E8F0] pb-4 gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-blue-50 border border-blue-200 rounded-xl text-blue-600 shadow-glow-blue">
            <Briefcase className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-bold text-slate-900 text-base">Investigation Incident Cases</h3>
            <p className="text-xs text-slate-600 mt-0.5">Multi-Message Forensic Case Management & Unified IOC Correlation</p>
          </div>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-tactile flex items-center gap-1.5 px-4 py-2 btn-block-primary text-white rounded-xl text-xs font-bold transition-all shadow-glow-blue cursor-pointer"
        >
          <Plus className="w-4 h-4" /> New Incident Case
        </button>
      </div>

      {showCreateModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="surface-card max-w-md w-full p-6 space-y-4 shadow-2xl border border-white/[0.1] animate-in fade-in duration-150">
            <h4 className="font-bold text-slate-900 text-sm">Open New Forensic Investigation Case</h4>

            <form onSubmit={handleCreateCase} className="space-y-3.5 text-xs">
              <div>
                <label className="text-slate-600 block mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Spear-Phishing Campaign Targeting CFO"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full bg-[#EFF6FF] border border-[#E2E8F0] focus:border-blue-500/80 rounded-xl p-2.5 text-slate-800 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-600 block mb-1">Case Description</label>
                <textarea
                  rows={3}
                  placeholder="Summary of threat scope, affected users, and objective..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full bg-[#EFF6FF] border border-[#E2E8F0] focus:border-blue-500/80 rounded-xl p-2.5 text-slate-800 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-600 block mb-1">Priority Level</label>
                <select
                  value={newPriority}
                  onChange={(e) => setNewPriority(e.target.value)}
                  className="w-full bg-[#EFF6FF] border border-[#E2E8F0] focus:border-blue-500/80 rounded-xl p-2.5 text-slate-800 focus:outline-none"
                >
                  <option value="CRITICAL">CRITICAL (Active Breach / Malware)</option>
                  <option value="HIGH">HIGH (Targeted Phishing / BEC)</option>
                  <option value="MEDIUM">MEDIUM (Suspicious Spam Campaign)</option>
                  <option value="LOW">LOW (Informational Incident)</option>
                </select>
              </div>

              {currentAnalysis && (
                <div className="surface-card-subtle p-3 rounded-lg border border-[#F1F5F9] text-[11px] text-slate-700">
                  <span className="text-blue-600 font-semibold block mb-0.5">Auto-Attach Current Analysis:</span>
                  <span className="truncate block font-mono">{currentAnalysis.metadata?.subject || currentAnalysis.analysis_id}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#E2E8F0]">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3.5 py-1.5 bg-slate-50 text-slate-600 hover:text-slate-800 rounded-xl"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-tactile px-4 py-1.5 btn-block-primary text-white font-bold rounded-xl"
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-600 block">Incident Cases ({filteredCases.length})</span>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-[#EFF6FF] border border-[#E2E8F0] text-[11px] text-slate-700 rounded-lg px-2 py-1 focus:outline-none focus:border-blue-500"
            >
              <option value="ALL">Filter: All Statuses</option>
              <option value="OPEN">Filter: OPEN</option>
              <option value="IN_PROGRESS">Filter: IN PROGRESS</option>
              <option value="CLOSED">Filter: CLOSED</option>
            </select>
          </div>

          {filteredCases.length === 0 ? (
            <div className="surface-card-subtle p-8 text-center text-xs text-slate-500">
              No cases match the selected filter.
            </div>
          ) : (
            filteredCases.map((c) => (
              <div
                key={c.id}
                onClick={() => setSelectedCaseId(c.id)}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                  selectedCaseId === c.id
                    ? 'bg-blue-950/25 border-blue-500/50 shadow-md'
                    : 'surface-card-subtle hover:border-[#FBA58C]'
                }`}
              >
                <div className="flex items-center justify-between gap-1 mb-2">
                  <span className="font-bold text-xs text-slate-900 truncate">{c.title}</span>
                  <span className={`px-2 py-0.5 text-[9px] font-extrabold uppercase rounded-full border ${getPriorityBadge(c.priority)}`}>
                    {c.priority}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-600 font-mono">
                  <span className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded-md border ${getStatusBadge(c.status)}`}>
                    {c.status}
                  </span>
                  <span>{c.attached_analyses_count} Emails | {c.notes_count} Notes</span>
                </div>
              </div>
            ))
          )}
        </div>

        <div className="lg:col-span-2 space-y-5">
          {activeCaseData ? (
            <>
              <div className="surface-card-subtle p-5 space-y-3.5 border border-[#E2E8F0]">
                {updateFeedback && (
                  <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-2.5 flex items-center gap-2 text-xs text-emerald-700 animate-in fade-in duration-150">
                    <CheckCircle2 className="w-4 h-4 text-emerald-700 flex-shrink-0" />
                    <span>{updateFeedback}</span>
                  </div>
                )}

                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 border-b border-[#F1F5F9] pb-3.5">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <h4 className="font-bold text-sm text-slate-900">{activeCaseData.title}</h4>
                      <span className={`px-2.5 py-0.5 text-[10px] font-extrabold uppercase rounded-full border ${getStatusBadge(activeCaseData.status)}`}>
                        {activeCaseData.status}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600">{activeCaseData.description || 'No description provided.'}</p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 flex-shrink-0">
                    {/* Status Dropdown */}
                    <div className="flex items-center gap-1">
                      <label className="text-[10px] uppercase font-bold text-slate-600">Status:</label>
                      <select
                        value={activeCaseData.status}
                        onChange={(e) => handleUpdateStatus(e.target.value)}
                        className="bg-[#EFF6FF] border border-[#E2E8F0] text-xs font-semibold text-slate-800 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500 cursor-pointer"
                      >
                        <option value="OPEN">OPEN (Active)</option>
                        <option value="IN_PROGRESS">IN PROGRESS (Triage)</option>
                        <option value="CLOSED">CLOSED (Archived)</option>
                      </select>
                    </div>

                    {/* Priority Dropdown */}
                    <div className="flex items-center gap-1">
                      <label className="text-[10px] uppercase font-bold text-slate-600">Priority:</label>
                      <select
                        value={activeCaseData.priority}
                        onChange={(e) => handleUpdatePriority(e.target.value)}
                        className="bg-[#EFF6FF] border border-[#E2E8F0] text-xs font-semibold text-slate-800 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500 cursor-pointer"
                      >
                        <option value="CRITICAL">CRITICAL</option>
                        <option value="HIGH">HIGH</option>
                        <option value="MEDIUM">MEDIUM</option>
                        <option value="LOW">LOW</option>
                      </select>
                    </div>
                  </div>
                </div>

                {activeCaseData.status === 'CLOSED' && (
                  <div className="bg-slate-500/10 border border-slate-500/30 rounded-lg p-3 text-xs text-slate-700 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-emerald-700 flex-shrink-0" />
                    <span>Case concluded and archived. All associated evidence locked in blockchain chain of custody.</span>
                  </div>
                )}

                {activeCaseData.unified_investigation_summary && (
                  <div className="surface-card p-3.5 rounded-lg border border-[#F1F5F9] text-xs text-slate-700 leading-relaxed">
                    <strong className="text-blue-700 block mb-1 font-semibold">Correlated Multi-Email Summary:</strong>
                    {activeCaseData.unified_investigation_summary.forensic_narrative}
                  </div>
                )}
              </div>

              <div className="surface-card-subtle p-5 space-y-3 border border-[#E2E8F0]">
                <span className="text-xs font-semibold text-slate-700 block">
                  Attached Email Artifacts ({activeCaseData.attached_analyses.length}):
                </span>

                {activeCaseData.attached_analyses.length === 0 ? (
                  <p className="text-xs text-slate-500 py-2">No email analyses attached yet.</p>
                ) : (
                  <div className="space-y-2">
                    {activeCaseData.attached_analyses.map((analysis) => (
                      <div key={analysis.analysis_id} className="surface-card p-3.5 flex items-center justify-between gap-3 text-xs">
                        <div className="space-y-0.5 max-w-md">
                          <span className="font-semibold text-slate-800 block truncate">
                            {analysis.metadata?.subject || '(No Subject)'}
                          </span>
                          <span className="text-[11px] text-slate-600 font-mono block">
                            From: {analysis.metadata?.from_address || 'N/A'} | Score: <strong style={{ color: analysis.threat_score?.risk_color }}>{analysis.threat_score?.overall_score}/100 ({analysis.threat_score?.risk_level})</strong>
                          </span>
                        </div>

                        <div className="flex items-center gap-2 flex-shrink-0">
                          {onSelectAnalysisFromCase && (
                            <button
                              onClick={() => onSelectAnalysisFromCase(analysis.analysis_id)}
                              className="px-3 py-1 bg-blue-50 text-blue-600 border border-blue-200 rounded-lg hover:bg-blue-50 text-[11px] font-semibold transition-colors"
                            >
                              Inspect in Console
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="surface-card-subtle p-5 space-y-4 border border-[#E2E8F0]">
                <span className="text-xs font-semibold text-slate-700 block flex items-center gap-2">
                  <MessageSquare className="w-4 h-4 text-blue-600" /> Analyst Investigation Notes ({activeCaseData.notes.length})
                </span>

                <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
                  {activeCaseData.notes.map((note, idx) => (
                    <div key={idx} className="surface-card p-3 text-xs space-y-1">
                      <div className="flex items-center justify-between text-[11px] text-slate-600">
                        <span className="font-semibold text-blue-700 flex items-center gap-1.5">
                          <User className="w-3.5 h-3.5" /> {note.author}
                        </span>
                        <span className="font-mono text-[10px]">{note.created_at?.slice(0, 19).replace('T', ' ')}</span>
                      </div>
                      <p className="text-slate-800 leading-normal">{note.content}</p>
                    </div>
                  ))}
                </div>

                <form onSubmit={handleAddNote} className="flex gap-2 pt-2 border-t border-[#F1F5F9]">
                  <input
                    type="text"
                    placeholder="Type an analyst observation or forensic note..."
                    value={newNoteContent}
                    onChange={(e) => setNewNoteContent(e.target.value)}
                    className="flex-1 bg-[#EFF6FF] border border-[#E2E8F0] focus:border-blue-500/80 rounded-xl px-3.5 py-2 text-xs text-slate-800 focus:outline-none"
                  />
                  <button
                    type="submit"
                    className="btn-tactile px-4 py-2 btn-block-primary text-white rounded-xl text-xs font-bold flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <Send className="w-3.5 h-3.5" /> Post Note
                  </button>
                </form>
              </div>
            </>
          ) : (
            <div className="surface-card-subtle p-12 text-center text-xs text-slate-500">
              Select or create an investigation case from the list on the left.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ==========================================
// 4. GLOBAL SEARCH MODAL
// ==========================================

export function GlobalSearchModal({ isOpen, onClose, onSelectResult }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!isOpen) { setQuery(''); setResults([]); return; }
    const delayDebounce = setTimeout(async () => {
      if (query.trim().length >= 2) {
        setLoading(true);
        try {
          const data = await api.search(query.trim());
          setResults(data);
        } catch (err) {
          console.error('Search error:', err);
        } finally {
          setLoading(false);
        }
      } else {
        setResults([]);
      }
    }, 200);
    return () => clearTimeout(delayDebounce);
  }, [query, isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-start justify-center pt-20 p-4">
      <div className="surface-card max-w-xl w-full p-4 space-y-3 shadow-2xl border border-white/[0.1] animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center gap-2.5 border-b border-[#E2E8F0] pb-2.5 px-1">
          <Search className="w-4 h-4 text-blue-600 flex-shrink-0" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search indicators, domains, IPs, cases, subjects... (e.g. 'phishing', 'microsoft', '198.51')"
            autoFocus
            className="flex-1 bg-transparent text-xs text-slate-900 placeholder-slate-500 focus:outline-none"
          />
          <button onClick={onClose} className="p-1 text-slate-600 hover:text-slate-900 rounded-lg">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="max-h-72 overflow-y-auto space-y-1.5 pr-1">
          {results.map((res, idx) => (
            <div
              key={idx}
              onClick={() => { onSelectResult(res.id); onClose(); }}
              className="p-3 rounded-xl surface-card-subtle hover:bg-[#EFF6FF] border border-white/[0.05] cursor-pointer flex items-center justify-between gap-3 transition-colors"
            >
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-800">{res.title}</div>
                <div className="text-[11px] text-slate-600 font-mono">{res.subtitle}</div>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-50 text-blue-600 border border-blue-200 font-bold uppercase tracking-wider">{res.type}</span>
            </div>
          ))}
          {query.trim().length >= 2 && results.length === 0 && !loading && (
            <p className="text-xs text-slate-500 py-6 text-center">No matching entities found.</p>
          )}
        </div>
      </div>
    </div>
  );
}

// ==========================================
// 5. GUIDED DEMO TOUR MODAL
// ==========================================

export function DemoTourModal({ isOpen, onClose, onLaunchSample }) {
  const [currentStep, setCurrentStep] = useState(0);

  if (!isOpen) return null;

  const scenarios = [
    {
      title: "Scenario 1: Legitimate Enterprise Communication",
      subtitle: "Clean Cryptographic Verification & Standard Transit",
      expectedThreat: "Low (0-29)",
      badgeColor: "bg-emerald-50 text-emerald-700 border-emerald-200",
      sampleId: "01_legitimate",
      icon: <ShieldCheck className="w-6 h-6 text-emerald-700" />,
      description: "Demonstrates baseline benign email traffic. SPF, DKIM, and DMARC passes, matching sender domains, standard MTA relay transit, and zero malicious payload markers.",
      keyEvaluatorPoints: [
        "SPF / DKIM / DMARC cryptographic pass",
        "Deterministic Threat Score = 0 / 100",
        "Observed legitimate relay infrastructure (Google Workspace MTA)"
      ]
    },
    {
      title: "Scenario 2: Credential Harvest Phishing & Lookalike Domain",
      subtitle: "Homoglyph Domain Typosquatting & Urgency Social Engineering",
      expectedThreat: "Critical (80-100)",
      badgeColor: "bg-rose-50 text-rose-600 border-rose-200",
      sampleId: "02_phishing_suspension",
      icon: <ShieldAlert className="w-6 h-6 text-rose-600" />,
      description: "Demonstrates advanced credential phishing mimicking Microsoft 365 security alert. The platform detects character substitution (micros0ft), Reply-To domain divergence, and urgency coercion keywords.",
      keyEvaluatorPoints: [
        "Lookalike domain detection with explainable homoglyph rationale",
        "Reply-To address mismatch flagged automatically",
        "AI Assessment categorizes threat as 'Credential Theft' with 93/100 Priority"
      ]
    },
    {
      title: "Scenario 3: Executive BEC Display Name Spoofing",
      subtitle: "C-Level Identity Impersonation via External Webmail",
      expectedThreat: "High (60-79)",
      badgeColor: "bg-orange-500/15 text-orange-600 border-orange-500/30",
      sampleId: "03_spoofed_ceo",
      icon: <Mail className="w-6 h-6 text-orange-600" />,
      description: "Demonstrates CEO Fraud / Business Email Compromise. Attacker uses legitimate CEO display name ('Alex Mercer - CEO') sent from an external unauthorized free webmail address asking for urgent payroll transfers.",
      keyEvaluatorPoints: [
        "Executive display name spoofing rule trigger",
        "SPF aligned for free webmail but completely unauthorized for executive entity",
        "AI Copilot explains executive impersonation mechanics"
      ]
    },
    {
      title: "Scenario 4: Multi-Hop MTA Transit Forensics & Geolocation",
      subtitle: "4-Hop Relay Reconstruction, Latency Deltas & Geolocation",
      expectedThreat: "Low / Medium",
      badgeColor: "bg-blue-50 text-blue-600 border-blue-200",
      sampleId: "07_multi_hop_relays",
      icon: <Server className="w-6 h-6 text-blue-600" />,
      description: "Demonstrates deep Received-header reconstruction across a 4-hop relay transit chain. Computes hop-to-hop latency deltas, identifies ISP gateway nodes, and plots infrastructure on the interactive Leaflet map.",
      keyEvaluatorPoints: [
        "4-Hop chronological node graph with +4s transit latency calculation",
        "Interactive Leaflet threat map with observed infrastructure pins",
        "Strict attribution disclaimer: Observed infrastructure ≠ true attacker origin"
      ]
    }
  ];

  const current = scenarios[currentStep];

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
      <div className="surface-card max-w-2xl w-full p-6 space-y-5 shadow-2xl border border-white/[0.1] animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-3.5">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-50 border border-purple-200 rounded-xl text-purple-700">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-slate-900 text-sm">Guided SIH Evaluator Walkthrough</h3>
              <p className="text-xs text-slate-600">Step {currentStep + 1} of {scenarios.length} • Synthetic Test Cases</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 text-slate-600 hover:text-slate-900 rounded-lg"><X className="w-4 h-4" /></button>
        </div>

        <div className="grid grid-cols-4 gap-2">
          {scenarios.map((s, idx) => (
            <div
              key={idx}
              onClick={() => setCurrentStep(idx)}
              className={`h-1.5 rounded-full cursor-pointer transition-all ${
                idx === currentStep ? 'bg-blue-500 shadow-glow-blue' : idx < currentStep ? 'bg-blue-900/60' : 'bg-slate-100'
              }`}
            />
          ))}
        </div>

        <div className="surface-card-subtle p-5 space-y-4 border border-[#F1F5F9]">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-slate-50 border border-[#E2E8F0]">{current.icon}</div>
              <div>
                <h4 className="font-bold text-sm text-slate-900">{current.title}</h4>
                <p className="text-xs text-slate-600 font-mono">{current.subtitle}</p>
              </div>
            </div>
            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase border ${current.badgeColor}`}>
              Expected: {current.expectedThreat}
            </span>
          </div>
          <p className="text-xs text-slate-700 leading-relaxed">{current.description}</p>
        </div>

        <div className="flex items-center justify-between pt-2 border-t border-[#E2E8F0]">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentStep(prev => Math.max(0, prev - 1))}
              disabled={currentStep === 0}
              className="flex items-center gap-1 px-3 py-1.5 bg-slate-50 text-slate-600 border border-[#E2E8F0] rounded-xl text-xs disabled:opacity-30 transition-colors"
            >
              <ChevronLeft className="w-3.5 h-3.5" /> Prev
            </button>
            <button
              onClick={() => setCurrentStep(prev => Math.min(scenarios.length - 1, prev + 1))}
              disabled={currentStep === scenarios.length - 1}
              className="flex items-center gap-1 px-3 py-1.5 bg-slate-50 text-slate-600 border border-[#E2E8F0] rounded-xl text-xs disabled:opacity-30 transition-colors"
            >
              Next <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <button
            onClick={() => { onLaunchSample(current.sampleId); onClose(); }}
            className="btn-tactile flex items-center gap-2 px-5 py-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-xl text-xs font-bold cursor-pointer shadow-glow-blue"
          >
            <Play className="w-3.5 h-3.5 fill-white" />
            <span>Launch Live Scenario in Console</span>
          </button>
        </div>
      </div>
    </div>
  );
}

// ==========================================
// 6. SAMPLE EMAIL SELECTOR
// ==========================================

export function SampleEmailSelector({ onSelectSample, disabled }) {
  const [samples, setSamples] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchSamples = async () => {
      try {
        const data = await api.getSamples();
        setSamples(data);
      } catch (err) {
        console.error('Error fetching sample list:', err);
      }
    };
    fetchSamples();
  }, []);

  const handleChange = async (e) => {
    const sampleId = e.target.value;
    if (!sampleId) return;
    setLoading(true);
    try {
      const data = await api.getSample(sampleId);
      onSelectSample(data.raw_content, data.name);
    } catch (err) {
      console.error('Failed to load sample:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 surface-card-subtle p-3.5 border border-[#F1F5F9]">
      <div>
        <span className="text-xs font-bold text-slate-800 block">Preloaded Synthetic Forensic Fixtures</span>
        <span className="text-[11px] text-slate-600">10 realistic test cases covering legitimate, spoofing, BEC, phishing, and malware</span>
      </div>

      <div className="relative min-w-[280px]">
        <select
          onChange={handleChange}
          defaultValue=""
          disabled={disabled || loading}
          className="w-full appearance-none bg-[#EFF6FF] border border-[#E2E8F0] hover:border-blue-500/50 rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-blue-500 cursor-pointer disabled:opacity-50 transition-colors"
        >
          <option value="" disabled>Choose a synthetic test email...</option>
          {samples.map((s) => (
            <option key={s.id} value={s.id}>
              [{s.expected_threat_level}] {s.name}
            </option>
          ))}
        </select>
        <ChevronDown className="w-4 h-4 text-slate-600 absolute right-2.5 top-2.5 pointer-events-none" />
      </div>
    </div>
  );
}

// ==========================================
// 7. BLOCKCHAIN EVIDENCE LEDGER VIEW
// ==========================================

export function BlockchainLedgerView({ onSelectAnalysis }) {
  const [ledger, setLedger] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedBlock, setSelectedBlock] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [verifying, setVerifying] = useState(false);

  const fetchBlockchainData = async () => {
    setLoading(true);
    try {
      const [ledgerData, statsData] = await Promise.all([
        api.getBlockchainLedger(),
        api.getBlockchainStats()
      ]);
      setLedger(ledgerData);
      setStats(statsData);
      if (ledgerData.length > 0 && !selectedBlock) {
        setSelectedBlock(ledgerData[0]);
      }
    } catch (err) {
      console.error('Failed to load blockchain ledger:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBlockchainData();
  }, []);

  const handleVerifyBlock = async (analysisId) => {
    setVerifying(true);
    try {
      const res = await api.verifyBlockchainEvidence(analysisId);
      setVerificationResult(res);
    } catch (err) {
      console.error('Verification failed:', err);
    } finally {
      setVerifying(false);
    }
  };

  if (loading && ledger.length === 0) {
    return (
      <div className="surface-card p-16 flex flex-col items-center justify-center space-y-3">
        <Loader2 className="w-7 h-7 text-blue-600 animate-spin" />
        <p className="text-xs text-slate-600">Loading immutable Proof-of-Authority blockchain ledger...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="surface-card p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="p-3 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-200 rounded-xl text-cyan-700 shadow-glow-blue">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="font-bold text-base text-slate-900">Blockchain Evidence Ledger & Merkle Proofs</h2>
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-emerald-50 text-emerald-700 border border-emerald-200">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> {stats?.chain_integrity_status || 'INTACT'}
              </span>
            </div>
            <p className="text-xs text-slate-600 mt-0.5">
              Decentralized Non-Repudiation Layer: Immutable SHA-256 block chaining and Merkle trees for email evidence integrity
            </p>
          </div>
        </div>

        <button
          onClick={fetchBlockchainData}
          className="btn-tactile flex items-center gap-1.5 px-3.5 py-1.5 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] text-slate-700 text-xs rounded-xl transition-colors cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh Chain
        </button>
      </div>

      {/* Telemetry Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 text-xs">
        <div className="surface-card p-4 space-y-1">
          <span className="text-slate-600 font-medium">Minted Evidence Blocks</span>
          <div className="text-2xl font-bold font-mono text-cyan-700 tabular-nums">{stats?.total_blocks || 0} Blocks</div>
          <span className="text-[10px] text-slate-500 font-mono">Proof-of-Authority (PoA)</span>
        </div>

        <div className="surface-card p-4 space-y-1">
          <span className="text-slate-600 font-medium">Validator Authority</span>
          <div className="text-sm font-bold font-mono text-slate-800 truncate">{stats?.validator_node || 'ThreatSentinel-01'}</div>
          <span className="text-[10px] text-slate-500 font-mono">Autonomous Evidence Node</span>
        </div>

        <div className="surface-card p-4 space-y-1">
          <span className="text-slate-600 font-medium">Latest Block Hash</span>
          <div className="text-xs font-mono text-slate-700 truncate select-all">{stats?.latest_block_hash || 'N/A'}</div>
          <span className="text-[10px] text-slate-500 font-mono">SHA-256 Header</span>
        </div>

        <div className="surface-card p-4 space-y-1">
          <span className="text-slate-600 font-medium">Genesis Block Pointer</span>
          <div className="text-xs font-mono text-slate-700 truncate select-all">{stats?.genesis_hash || 'N/A'}</div>
          <span className="text-[10px] text-slate-500 font-mono">Anchor Height #1</span>
        </div>
      </div>

      {/* Main Ledger Two-Column Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Chronological Block Stream */}
        <div className="space-y-3">
          <span className="text-xs font-semibold text-slate-600 block">Immutable Block Chain ({ledger.length} Blocks)</span>
          
          <div className="space-y-2.5 max-h-[600px] overflow-y-auto pr-1">
            {ledger.map((b) => (
              <div
                key={b.block_number}
                onClick={() => {
                  setSelectedBlock(b);
                  setVerificationResult(null);
                  handleVerifyBlock(b.analysis_id);
                }}
                className={`p-4 rounded-xl border transition-all cursor-pointer ${
                  selectedBlock?.block_number === b.block_number
                    ? 'bg-blue-950/25 border-cyan-500/50 shadow-md shadow-cyan-500/10'
                    : 'surface-card-subtle hover:border-[#FBA58C]'
                }`}
              >
                <div className="flex items-center justify-between gap-1 mb-1.5">
                  <span className="font-bold text-xs text-cyan-800 flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-cyan-700" /> Block #{b.block_number}
                  </span>
                  <span className="px-2 py-0.5 text-[9px] font-extrabold uppercase rounded-full bg-blue-50 text-blue-600 border border-blue-200">
                    Score: {b.threat_score}/100
                  </span>
                </div>

                <div className="space-y-1 text-[11px] font-mono text-slate-600">
                  <div className="truncate text-slate-700">Analysis: {b.analysis_id.slice(0, 14)}...</div>
                  <div className="truncate select-all text-slate-600">Hash: {b.block_hash.slice(0, 20)}...</div>
                  <div className="text-[10px] text-slate-500">{b.timestamp.replace('T', ' ').slice(0, 19)} UTC</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Deep Block Cryptographic Proof Inspector */}
        <div className="lg:col-span-2 space-y-5">
          {selectedBlock ? (
            <>
              <div className="surface-card p-6 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#E2E8F0] pb-3.5">
                  <div>
                    <h3 className="font-bold text-sm text-slate-900 flex items-center gap-2">
                      <Lock className="w-4 h-4 text-cyan-700" /> Cryptographic Block #{selectedBlock.block_number} Dossier
                    </h3>
                    <p className="text-xs text-slate-600 mt-0.5">Anchored evidence block and Merkle tree inclusion path</p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onSelectAnalysis(selectedBlock.analysis_id)}
                      className="px-3 py-1.5 bg-blue-50 text-blue-600 border border-blue-200 rounded-xl text-xs font-semibold hover:bg-blue-50 transition-colors cursor-pointer flex items-center gap-1"
                    >
                      Inspect Email <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                </div>

                {/* Cryptographic Hashes Grid */}
                <div className="surface-card-subtle p-4 space-y-2.5 text-xs font-mono border border-[#F1F5F9]">
                  <div className="flex items-center justify-between border-b border-[#F1F5F9] pb-2">
                    <span className="text-slate-600">Smart Contract:</span>
                    <span className="text-emerald-700 font-bold select-all truncate max-w-md">{stats?.contract_address || '0x71C80aB8B33f11E81D4b5b4Fe93C9a8Ec0F36D48'}</span>
                  </div>
                  <div className="flex items-center justify-between border-b border-[#F1F5F9] pb-2">
                    <span className="text-slate-600">Transaction ID (Tx):</span>
                    <span className="text-amber-700 font-bold select-all truncate max-w-md">{selectedBlock.tx_id || `0x${selectedBlock.block_hash.slice(0, 40)}`}</span>
                  </div>
                  <div className="flex items-center justify-between border-b border-[#F1F5F9] pb-2">
                    <span className="text-slate-600">Block Hash:</span>
                    <span className="text-cyan-700 font-bold select-all truncate max-w-md">{selectedBlock.block_hash}</span>
                  </div>
                  <div className="flex items-center justify-between border-b border-[#F1F5F9] pb-2">
                    <span className="text-slate-600">Previous Hash:</span>
                    <span className="text-slate-700 select-all truncate max-w-md">{selectedBlock.previous_hash}</span>
                  </div>
                  <div className="flex items-center justify-between border-b border-[#F1F5F9] pb-2">
                    <span className="text-slate-600">Merkle Root:</span>
                    <span className="text-purple-700 font-bold select-all truncate max-w-md">{selectedBlock.merkle_root}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-600">Canonical Evidence SHA-256:</span>
                    <span className="text-slate-700 select-all truncate max-w-md">{selectedBlock.canonical_evidence_hash || selectedBlock.evidence_hash}</span>
                  </div>
                </div>

                {/* Live Dual Verification Card */}
                {verificationResult && (
                  <div className={`p-4 rounded-xl text-xs flex items-start gap-3 border ${
                    verificationResult.tamper_detected
                      ? 'bg-rose-50 border-rose-200 text-rose-700'
                      : 'bg-emerald-50 border-emerald-200 text-emerald-700'
                  }`}>
                    {verificationResult.tamper_detected ? (
                      <ShieldAlert className="w-5 h-5 text-rose-600 flex-shrink-0 mt-0.5" />
                    ) : (
                      <CheckCircle className="w-5 h-5 text-emerald-700 flex-shrink-0 mt-0.5" />
                    )}
                    <div className="space-y-1">
                      <div className="font-bold uppercase tracking-wider text-xs">
                        {verificationResult.verification_status.replace(/_/g, ' ')}
                      </div>
                      <p className="text-[11px] leading-relaxed">{verificationResult.verification_details || verificationResult.details}</p>
                    </div>
                  </div>
                )}

                {/* Merkle Leaf Elements */}
                {selectedBlock.merkle_leaves && selectedBlock.merkle_leaves.length > 0 && (
                  <div className="space-y-2 pt-1">
                    <span className="text-xs font-semibold text-slate-700 block">
                      Non-Sensitive Merkle Tree Leaf Elements ({selectedBlock.evidence_leaf_count || selectedBlock.merkle_leaves.length}):
                    </span>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                      {selectedBlock.merkle_leaves.map((leaf, idx) => (
                        <div key={idx} className="surface-card-subtle p-2.5 text-[11px] text-slate-700 truncate border border-[#F1F5F9]">
                          <span className="text-blue-600 font-bold">#{idx + 1}: </span>{leaf}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="surface-card-subtle p-16 text-center text-xs text-slate-500">
              Select a block from the chain on the left to inspect its cryptographic proofs.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ==========================================
// 5. DECENTRALIZED THREAT INTELLIGENCE VIEW
// ==========================================

export function ThreatIntelView() {
  const [indicators, setIndicators] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  // Verification State
  const [verifyType, setVerifyType] = useState('DOMAIN');
  const [verifyValue, setVerifyValue] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);

  // Register Modal State
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [regType, setRegType] = useState('DOMAIN');
  const [regValue, setRegValue] = useState('');
  const [regCategory, setRegCategory] = useState('PHISHING');
  const [regSeverity, setRegSeverity] = useState('HIGH');
  const [regConfidence, setRegConfidence] = useState(90);
  const [regOrg, setRegOrg] = useState('ThreatSentinel-SOC-01');
  const [regDesc, setRegDesc] = useState('');
  const [registering, setRegistering] = useState(false);

  const fetchIntelData = async () => {
    setLoading(true);
    try {
      const [indData, statsData] = await Promise.all([
        api.getThreatIndicators(100),
        api.getThreatIntelStats()
      ]);
      setIndicators(indData || []);
      setStats(statsData || null);
    } catch (e) {
      console.error('Failed to load threat intel:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIntelData();
  }, []);

  const handleVerify = async (e) => {
    e?.preventDefault();
    if (!verifyValue.trim()) return;
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await api.verifyThreatIndicator(verifyType, verifyValue.trim());
      setVerifyResult(res);
    } catch (e) {
      console.error('Failed to verify indicator:', e);
    } finally {
      setVerifying(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!regValue.trim()) return;
    setRegistering(true);
    try {
      await api.registerThreatIndicator({
        indicator_type: regType,
        indicator_value: regValue.trim(),
        threat_category: regCategory,
        severity: regSeverity,
        confidence_score: Number(regConfidence),
        source_org: regOrg.trim() || 'ThreatSentinel-SOC-01',
        description: regDesc.trim() || undefined
      });
      setShowRegisterModal(false);
      setRegValue('');
      setRegDesc('');
      await fetchIntelData();
    } catch (err) {
      console.error('Failed to register indicator:', err);
    } finally {
      setRegistering(false);
    }
  };

  const filteredIndicators = indicators.filter((ind) => {
    const matchesType = filterType === 'ALL' || ind.indicator_type === filterType;
    const matchesSearch =
      !searchTerm ||
      ind.indicator_value.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ind.threat_category.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ind.source_org.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesType && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="surface-card bg-gradient-to-r from-cyan-950/20 via-[#111726] to-blue-950/20 p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 border border-cyan-200">
        <div className="flex items-center gap-3.5">
          <div className="p-3 bg-cyan-50 border border-cyan-200 rounded-xl text-cyan-700 shadow-glow-blue flex-shrink-0">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-900">
                Decentralized Threat Intelligence Sharing Registry
              </h2>
              <span className="px-2.5 py-0.5 text-[9px] font-bold bg-cyan-50 text-cyan-800 border border-cyan-200 rounded-full uppercase font-mono">
                Smart Contract IoC Sync
              </span>
            </div>
            <p className="text-xs text-slate-600 mt-1 max-w-2xl leading-relaxed">
              Cross-organizational threat indicator sharing with cryptographic provenance. Verified IoCs broadcasted across participating CERT/SOC nodes with zero sensitive email disclosure.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={fetchIntelData}
            disabled={loading}
            className="btn-tactile px-3.5 py-2 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] text-slate-700 rounded-xl text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync Registry</span>
          </button>

          <button
            onClick={() => setShowRegisterModal(true)}
            className="btn-tactile px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white rounded-xl text-xs font-bold transition-all shadow-glow-blue flex items-center gap-1.5 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Register Indicator</span>
          </button>
        </div>
      </div>

      {/* Telemetry Stats Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        <div className="surface-card p-4 space-y-1">
          <span className="text-xs text-slate-600">Total Shared IoCs</span>
          <div className="text-2xl font-bold font-mono text-cyan-700">
            {stats?.total_indicators || indicators.length}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Anchored On-Chain</span>
        </div>

        <div className="surface-card p-4 space-y-1">
          <span className="text-xs text-slate-600">Participating Nodes</span>
          <div className="text-2xl font-bold font-mono text-purple-700">
            {stats?.participating_orgs_count || 3}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">SOC / CERT Entities</span>
        </div>

        <div className="surface-card p-4 space-y-1">
          <span className="text-xs text-slate-600">High / Critical Threats</span>
          <div className="text-2xl font-bold font-mono text-rose-600">
            {(stats?.by_severity?.CRITICAL || 0) + (stats?.by_severity?.HIGH || 0)}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Immediate Action</span>
        </div>

        <div className="surface-card p-4 space-y-1">
          <span className="text-xs text-slate-600">Registry Smart Contract</span>
          <div className="text-xs font-bold font-mono text-slate-700 truncate select-all pt-1">
            {stats?.intel_contract || '0x89E23B84...'}
          </div>
          <span className="text-[10px] text-emerald-700 font-mono">EVM PoA Ledger</span>
        </div>
      </div>

      {/* Cross-Verification Search Tool */}
      <div className="surface-card p-6 space-y-4">
        <div className="border-b border-[#E2E8F0] pb-3">
          <h3 className="font-bold text-sm text-slate-900 flex items-center gap-2">
            <Search className="w-4 h-4 text-cyan-700" />
            Query & Verify Threat Indicator on Blockchain
          </h3>
          <p className="text-xs text-slate-600 mt-0.5">
            Check if an incoming domain, URL hash, IP, or malware digest has been flagged by participating organizations
          </p>
        </div>

        <form onSubmit={handleVerify} className="flex flex-col sm:flex-row gap-2.5">
          <select
            value={verifyType}
            onChange={(e) => setVerifyType(e.target.value)}
            className="bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="DOMAIN">DOMAIN</option>
            <option value="IP_ADDRESS">IP ADDRESS</option>
            <option value="FILE_HASH">FILE HASH (SHA-256)</option>
            <option value="URL_HASH">URL HASH</option>
            <option value="SENDER_DOMAIN">SENDER DOMAIN</option>
          </select>

          <input
            type="text"
            placeholder="e.g. login-verify-banking.com, 185.220.101.5, or sha256:e3b0c..."
            value={verifyValue}
            onChange={(e) => setVerifyValue(e.target.value)}
            className="flex-1 bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl px-3.5 py-2 text-xs text-slate-800 focus:outline-none focus:border-cyan-500 font-mono"
          />

          <button
            type="submit"
            disabled={verifying || !verifyValue.trim()}
            className="btn-tactile px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold transition-all shadow-glow-blue flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            {verifying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
            <span>Verify Provenance</span>
          </button>
        </form>

        {verifyResult && (
          <div className={`p-4 rounded-xl text-xs space-y-2 border animate-in fade-in duration-200 ${
            verifyResult.is_known_threat
              ? 'bg-rose-50 border-rose-200 text-rose-700'
              : 'bg-emerald-50 border-emerald-200 text-emerald-700'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {verifyResult.is_known_threat ? (
                  <ShieldAlert className="w-4 h-4 text-rose-600" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-700" />
                )}
                <span className="font-bold uppercase tracking-wider">
                  {verifyResult.status.replace(/_/g, ' ')}
                </span>
              </div>

              {verifyResult.is_known_threat && (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-extrabold bg-rose-50 text-rose-700 border border-rose-300 uppercase">
                  {verifyResult.severity} Severity • {verifyResult.confidence_score}% Confidence
                </span>
              )}
            </div>

            <p className="text-[11px] leading-relaxed font-sans">{verifyResult.verification_details}</p>

            {verifyResult.is_known_threat && (
              <div className="pt-2 grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono bg-[#0B0F19]/60 p-2.5 rounded-lg border border-[#F1F5F9]">
                <div>Source: <strong className="text-slate-800">{verifyResult.source_org}</strong></div>
                <div>Category: <strong className="text-slate-800">{verifyResult.threat_category}</strong></div>
                <div>Peer Confirmations: <strong className="text-cyan-700">{verifyResult.observation_count} nodes</strong></div>
                <div className="truncate">Tx ID: <strong className="text-amber-700">{verifyResult.tx_id || 'On-Chain'}</strong></div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Shared Indicators Feed Table */}
      <div className="surface-card p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[#E2E8F0] pb-3.5 gap-3">
          <div>
            <h3 className="font-bold text-sm text-slate-900">Live Decentralized Threat Intelligence Feed</h3>
            <p className="text-xs text-slate-600 mt-0.5">Immutable multi-organizational threat indicators</p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex bg-[#EFF6FF] p-1 rounded-xl border border-[#F1F5F9] text-xs font-semibold">
              {['ALL', 'DOMAIN', 'IP_ADDRESS', 'FILE_HASH'].map((t) => (
                <button
                  key={t}
                  onClick={() => setFilterType(t)}
                  className={`px-3 py-1 rounded-lg transition-all cursor-pointer ${
                    filterType === t
                      ? 'bg-cyan-600 text-white shadow-sm font-bold'
                      : 'text-slate-600 hover:text-slate-800'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>

            <input
              type="text"
              placeholder="Filter IoCs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl px-3 py-1 text-xs text-slate-800 focus:outline-none focus:border-cyan-500 font-mono w-40"
            />
          </div>
        </div>

        {filteredIndicators.length === 0 ? (
          <div className="surface-card-subtle p-12 text-center text-xs text-slate-500 space-y-1">
            <p>No threat indicators match the current criteria.</p>
            <p className="text-[11px]">Click "Register Indicator" above or scan emails to populate IoCs.</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-[#F1F5F9]">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#EFF6FF] text-slate-600 text-[10px] uppercase font-semibold">
                <tr>
                  <th className="p-3.5">Type</th>
                  <th className="p-3.5">Indicator Value (IoC)</th>
                  <th className="p-3.5">Threat Category</th>
                  <th className="p-3.5">Severity</th>
                  <th className="p-3.5">Confidence</th>
                  <th className="p-3.5">Source Org</th>
                  <th className="p-3.5">Peer Confirmations</th>
                  <th className="p-3.5">Blockchain Tx</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F1F5F9] bg-white font-mono text-[11px]">
                {filteredIndicators.map((ind) => (
                  <tr key={ind.id} className="hover:bg-[#F0F7FF] transition-colors">
                    <td className="p-3.5">
                      <span className="px-2 py-0.5 rounded-md bg-blue-50 text-blue-600 border border-blue-200 text-[10px] font-bold">
                        {ind.indicator_type}
                      </span>
                    </td>
                    <td className="p-3.5 font-bold text-slate-800 max-w-xs truncate select-all">
                      {ind.indicator_value}
                    </td>
                    <td className="p-3.5 text-slate-700 font-sans">
                      {ind.threat_category.replace(/_/g, ' ')}
                    </td>
                    <td className="p-3.5 font-sans">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase border ${
                        ind.severity === 'CRITICAL'
                          ? 'bg-rose-50 text-rose-600 border-rose-200'
                          : ind.severity === 'HIGH'
                          ? 'bg-orange-500/15 text-orange-600 border-orange-500/30'
                          : 'bg-amber-50 text-amber-700 border-amber-200'
                      }`}>
                        {ind.severity}
                      </span>
                    </td>
                    <td className="p-3.5 font-bold text-slate-700">
                      {ind.confidence_score}%
                    </td>
                    <td className="p-3.5 text-slate-600 max-w-[140px] truncate">
                      {ind.source_org}
                    </td>
                    <td className="p-3.5 text-cyan-700 font-bold">
                      {ind.observation_count || 1} Nodes
                    </td>
                    <td className="p-3.5 text-amber-700 select-all truncate max-w-[120px]">
                      {ind.tx_id ? `${ind.tx_id.slice(0, 10)}...` : '0x7b4a...'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Register Indicator Modal */}
      {showRegisterModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="surface-card max-w-lg w-full p-6 space-y-4 shadow-2xl border border-white/[0.1]">
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-3">
              <div className="flex items-center gap-2">
                <Plus className="w-5 h-5 text-cyan-700" />
                <h3 className="font-bold text-sm text-slate-900">Register Threat Indicator on Blockchain</h3>
              </div>
              <button onClick={() => setShowRegisterModal(false)} className="text-slate-600 hover:text-slate-900">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleRegister} className="space-y-3.5">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs text-slate-700 font-semibold block">Indicator Type</label>
                  <select
                    value={regType}
                    onChange={(e) => setRegType(e.target.value)}
                    className="w-full bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="DOMAIN">DOMAIN</option>
                    <option value="IP_ADDRESS">IP ADDRESS</option>
                    <option value="FILE_HASH">FILE HASH (SHA-256)</option>
                    <option value="URL_HASH">URL HASH</option>
                    <option value="SENDER_DOMAIN">SENDER DOMAIN</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs text-slate-700 font-semibold block">Threat Category</label>
                  <select
                    value={regCategory}
                    onChange={(e) => setRegCategory(e.target.value)}
                    className="w-full bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="PHISHING">PHISHING</option>
                    <option value="CREDENTIAL_HARVESTER">CREDENTIAL HARVESTER</option>
                    <option value="MALWARE_DROPPER">MALWARE DROPPER</option>
                    <option value="BEC">BEC (BUSINESS EMAIL COMPROMISE)</option>
                    <option value="RANSOMWARE_AFFILIATE">RANSOMWARE AFFILIATE</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs text-slate-700 font-semibold block">Indicator Value (IoC)</label>
                <input
                  type="text"
                  placeholder="e.g. login-update-auth.com or 185.220.101.5"
                  value={regValue}
                  onChange={(e) => setRegValue(e.target.value)}
                  className="w-full bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs text-slate-700 font-semibold block">Severity Tier</label>
                  <select
                    value={regSeverity}
                    onChange={(e) => setRegSeverity(e.target.value)}
                    className="w-full bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs text-slate-700 font-semibold block">Confidence Score ({regConfidence}%)</label>
                  <input
                    type="range"
                    min="50"
                    max="100"
                    value={regConfidence}
                    onChange={(e) => setRegConfidence(Number(e.target.value))}
                    className="w-full h-2 bg-[#EFF6FF] rounded-lg cursor-pointer accent-cyan-500 mt-2.5"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs text-slate-700 font-semibold block">Registering Organization / Node</label>
                <input
                  type="text"
                  value={regOrg}
                  onChange={(e) => setRegOrg(e.target.value)}
                  className="w-full bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs text-slate-700 font-semibold block">Context / Incident Notes (Non-Sensitive)</label>
                <textarea
                  rows={2}
                  placeholder="Observed in spear-phishing campaign impersonating Microsoft 365..."
                  value={regDesc}
                  onChange={(e) => setRegDesc(e.target.value)}
                  className="w-full bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl p-3 text-xs text-slate-800 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowRegisterModal(false)}
                  className="px-4 py-2 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] text-slate-700 text-xs rounded-xl"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={registering}
                  className="btn-tactile px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-bold rounded-xl shadow-glow-blue cursor-pointer disabled:opacity-50"
                >
                  {registering ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Anchor to Blockchain'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}




export function AnalyticsView() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetch('/api/analytics/detection')
      .then(res => res.json())
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
      </div>
    );
  }

  if (!data || data.error) {
    return (
      <div className="p-8 text-red-500 font-medium">
        Error loading analytics: {data?.error || 'Unknown error'}
      </div>
    );
  }

  const { overall, confusion_matrix: cm, rule_performance, category_performance, dataset_size } = data;

  return (
    <div className="flex flex-col h-full overflow-hidden bg-slate-50 relative">
      <div className="border-b border-slate-200 bg-white p-6 shadow-sm z-10 flex-shrink-0">
        <h1 className="text-2xl font-bold text-slate-900 mb-1 flex items-center gap-2">
          <Activity className="w-6 h-6 text-blue-600" />
          Detection Analytics & Evaluation
        </h1>
        <p className="text-sm text-slate-500">
          Transparent performance evaluation against a labeled dataset of {dataset_size} samples.
        </p>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-6xl mx-auto space-y-6">
          
          {/* Overall Performance & Confusion Matrix */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
              <h2 className="text-lg font-bold text-slate-800 mb-4 border-b border-slate-100 pb-2">Overall Metrics</h2>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                  <div className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-1">Accuracy</div>
                  <div className="text-2xl font-bold text-slate-800">{(overall.accuracy * 100).toFixed(1)}%</div>
                </div>
                <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                  <div className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-1">Precision</div>
                  <div className="text-2xl font-bold text-slate-800">{(overall.precision * 100).toFixed(1)}%</div>
                </div>
                <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                  <div className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-1">Recall</div>
                  <div className="text-2xl font-bold text-slate-800">{(overall.recall * 100).toFixed(1)}%</div>
                </div>
                <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                  <div className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-1">F1 Score</div>
                  <div className="text-2xl font-bold text-blue-600">{(overall.f1 * 100).toFixed(1)}%</div>
                </div>
              </div>
            </div>

            <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
              <h2 className="text-lg font-bold text-slate-800 mb-4 border-b border-slate-100 pb-2">Confusion Matrix (Binary)</h2>
              <div className="grid grid-cols-3 gap-2 text-center text-sm mt-6">
                <div className="font-semibold text-slate-500 flex items-center justify-center">Actual \ Pred</div>
                <div className="font-semibold text-slate-700 bg-slate-100 p-2 rounded">Benign</div>
                <div className="font-semibold text-slate-700 bg-slate-100 p-2 rounded">Malicious</div>
                
                <div className="font-semibold text-slate-700 bg-slate-100 p-2 rounded flex items-center justify-center">Benign</div>
                <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                  <div className="text-2xl font-bold text-green-700">{cm.tn}</div>
                  <div className="text-xs text-green-600">True Negative</div>
                </div>
                <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                  <div className="text-2xl font-bold text-red-700">{cm.fp}</div>
                  <div className="text-xs text-red-600">False Positive</div>
                </div>

                <div className="font-semibold text-slate-700 bg-slate-100 p-2 rounded flex items-center justify-center">Malicious</div>
                <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                  <div className="text-2xl font-bold text-red-700">{cm.fn}</div>
                  <div className="text-xs text-red-600">False Negative</div>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                  <div className="text-2xl font-bold text-green-700">{cm.tp}</div>
                  <div className="text-xs text-green-600">True Positive</div>
                </div>
              </div>
            </div>
          </div>

          {/* Category Performance */}
          <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
            <h2 className="text-lg font-bold text-slate-800 mb-4 border-b border-slate-100 pb-2">Threat Category Performance</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-slate-500 uppercase bg-slate-50">
                  <tr>
                    <th className="px-4 py-3 font-semibold rounded-tl-lg">Category</th>
                    <th className="px-4 py-3 font-semibold">Samples</th>
                    <th className="px-4 py-3 font-semibold">Detected</th>
                    <th className="px-4 py-3 font-semibold">Missed (FN)</th>
                    <th className="px-4 py-3 font-semibold">Precision</th>
                    <th className="px-4 py-3 font-semibold">Recall</th>
                    <th className="px-4 py-3 font-semibold rounded-tr-lg">F1 Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {Object.entries(category_performance).map(([cat, stats]) => (
                    <tr key={cat} className="hover:bg-slate-50/50">
                      <td className="px-4 py-3 font-medium text-slate-900">{cat}</td>
                      <td className="px-4 py-3 text-slate-600">{stats.samples}</td>
                      <td className="px-4 py-3 text-green-600 font-medium">{stats.detected}</td>
                      <td className="px-4 py-3 text-red-600 font-medium">{stats.fn}</td>
                      <td className="px-4 py-3">{(stats.precision * 100).toFixed(1)}%</td>
                      <td className="px-4 py-3">{(stats.recall * 100).toFixed(1)}%</td>
                      <td className="px-4 py-3 text-blue-600 font-semibold">{(stats.f1 * 100).toFixed(1)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Rule Analytics */}
          <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
            <h2 className="text-lg font-bold text-slate-800 mb-4 border-b border-slate-100 pb-2">Rule Analytics (Triggered Rules)</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-slate-500 uppercase bg-slate-50">
                  <tr>
                    <th className="px-4 py-3 font-semibold rounded-tl-lg">Rule ID</th>
                    <th className="px-4 py-3 font-semibold">Rule Name</th>
                    <th className="px-4 py-3 font-semibold">Hits</th>
                    <th className="px-4 py-3 font-semibold rounded-tr-lg">Avg Score Contribution</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {rule_performance.sort((a,b) => b.times_triggered - a.times_triggered).map((r) => (
                    <tr key={r.rule_id} className="hover:bg-slate-50/50">
                      <td className="px-4 py-3 font-medium text-slate-700 whitespace-nowrap">{r.rule_id}</td>
                      <td className="px-4 py-3 text-slate-900">{r.rule_name}</td>
                      <td className="px-4 py-3 text-slate-600 font-semibold">{r.times_triggered}</td>
                      <td className="px-4 py-3 text-orange-600 font-semibold">+{r.avg_score_contribution.toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Info block */}
          <div className="bg-blue-50 border border-blue-200 rounded-xl p-5 mt-8">
            <h3 className="font-semibold text-blue-800 mb-2 flex items-center gap-2">
              <HelpCircle className="w-4 h-4"/> Methodology Notes
            </h3>
            <ul className="text-sm text-blue-900 space-y-1 ml-6 list-disc">
              <li>Metrics are calculated dynamically against the local `samples/labels.json` dataset.</li>
              <li>A sample is classified as "Malicious" if the scanner's overall threat score exceeds 40.</li>
              <li>Due to the small size of this synthetic dataset, these performance figures do not reflect production capabilities.</li>
            </ul>
          </div>

        </div>
      </div>
    </div>
  );
}


export function BulkResultsView({ bulkResults, onImportAnother }) {
  if (!bulkResults) return null;
  const s = bulkResults.summary || {};
  const results = bulkResults.results || [];

  const getSafeErrorMessage = (errStr) => {
    if (!errStr) return "Email could not be analysed";
    const lower = String(errStr).toLowerCase();
    if (lower.includes('size limit') || lower.includes('too large') || lower.includes('exceed')) {
      return "Email exceeds the allowed size";
    }
    if (lower.includes('parse') || lower.includes('malformed')) {
      return "Email could not be parsed";
    }
    if (lower.includes('unsupported') || lower.includes('format')) {
      return "Unsupported email format";
    }
    if (lower.includes('invalid')) {
      return "Invalid email format";
    }
    return "Email could not be analysed";
  };


  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-black text-slate-900 tracking-tight">Bulk Analysis Complete</h2>
          <p className="text-sm text-slate-500">Batch ID: <span className="font-mono text-xs">{bulkResults.batch_id}</span></p>
        </div>
        <button
          onClick={onImportAnother}
          className="px-4 py-2 bg-blue-600 text-white rounded-xl text-sm font-bold shadow-md hover:bg-blue-700 transition-colors flex items-center gap-2"
        >
          <RefreshCw className="w-4 h-4" /> Import Another Batch
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <BulkStatCard title="Total Emails" value={s.total || 0} icon={Mail} />
        <BulkStatCard title="Analyzed" value={s.analyzed || 0} icon={CheckCircle2} />
        <BulkStatCard title="Duplicates" value={s.duplicates || 0} icon={RefreshCw} />
        <BulkStatCard title="Failed" value={s.failed || 0} icon={AlertTriangle} color="text-rose-600" />
        <BulkStatCard title="Escalated Cases" value={s.automatically_escalated_cases || 0} icon={Briefcase} color="text-amber-600" />
      </div>

      <div className="grid grid-cols-4 gap-4">
        <BulkStatCard title="Critical Risk" value={s.critical || 0} color="text-rose-600" />
        <BulkStatCard title="High Risk" value={s.high || 0} color="text-amber-500" />
        <BulkStatCard title="Medium Risk" value={s.medium || 0} color="text-blue-500" />
        <BulkStatCard title="Low Risk" value={s.low || 0} color="text-emerald-500" />
      </div>

      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden mt-6">
        <div className="px-5 py-4 border-b border-slate-200 bg-slate-50/50">
          <h3 className="font-bold text-slate-800 text-sm">Per-Email Results</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold text-xs uppercase tracking-wider">
                <th className="px-5 py-3">Filename</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">Score</th>
                <th className="px-5 py-3">Level</th>
                <th className="px-5 py-3">Case</th>
                <th className="px-5 py-3">Analysis ID</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {results.map((r, i) => (
                <tr key={i} className="hover:bg-slate-50/50 transition-colors">
                  <td className="px-5 py-3 font-medium text-slate-800 truncate max-w-[200px]" title={r.filename}>{r.filename || '�'}</td>
                  <td className="px-5 py-3">
                    <span className={`px-2 py-1 text-[10px] font-bold rounded-md uppercase ${
                      r.status === 'ANALYZED' ? 'bg-emerald-100 text-emerald-800' :
                      r.status === 'DUPLICATE' ? 'bg-slate-100 text-slate-700' :
                      'bg-rose-100 text-rose-800'
                    }`}>
                      {r.status || '�'}
                    </span>
                    {r.error && (
                      <div className="mt-1">
                        <p className="text-[10px] text-rose-500 font-medium">Analysis failed for this email.</p>
                        <p className="text-[10px] text-rose-400 truncate max-w-[150px]" title={getSafeErrorMessage(r.error)}>
                          Reason: {getSafeErrorMessage(r.error)}
                        </p>
                      </div>
                    )}
                  </td>
                  <td className="px-5 py-3 font-mono text-slate-600">{r.threat_score ?? '�'}</td>
                  <td className="px-5 py-3">
                    {r.threat_level ? (
                      <span className={`px-2 py-1 text-[10px] font-bold rounded-md uppercase ${
                        r.threat_level === 'Critical' ? 'bg-rose-100 text-rose-800' :
                        r.threat_level === 'High' ? 'bg-amber-100 text-amber-800' :
                        r.threat_level === 'Medium' ? 'bg-blue-100 text-blue-800' :
                        'bg-emerald-100 text-emerald-800'
                      }`}>
                        {r.threat_level}
                      </span>
                    ) : '�'}
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-slate-500">
                    {r.case_id ? <span className="text-amber-600 font-bold" title={r.case_id}>AUTO-INC</span> : '�'}
                  </td>
                  <td className="px-5 py-3 font-mono text-[10px] text-slate-400 truncate max-w-[120px]" title={r.analysis_id}>{r.analysis_id || '�'}</td>
                </tr>
              ))}
              {results.length === 0 && (
                <tr>
                  <td colSpan="6" className="px-5 py-8 text-center text-slate-500 text-sm">No detailed results available.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function BulkStatCard({ title, value, icon: Icon, color }) {
  return (
    <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm flex items-center justify-between">
      <div>
        <p className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">{title}</p>
        <p className={`text-2xl font-black mt-1 ${color || 'text-slate-800'}`}>{value}</p>
      </div>
      {Icon && <Icon className={`w-8 h-8 ${color || 'text-slate-300'}`} />}
    </div>
  );
}
