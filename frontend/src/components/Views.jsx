import React, { useState, useEffect } from 'react';
import {
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
  ChevronDown
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
      <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-16 flex flex-col items-center justify-center space-y-3">
        <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
        <p className="text-xs text-slate-400">Loading live SOC telemetry and database records...</p>
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
      <div className="bg-gradient-to-r from-blue-950/40 via-[#131B2A] to-purple-950/40 border border-blue-500/30 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-lg">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600/20 border border-blue-500/30 rounded-lg text-blue-400">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
              SIH Evaluator Demo Environment
              <span className="px-2 py-0.5 text-[9px] font-extrabold bg-blue-500/20 text-blue-300 border border-blue-500/40 rounded uppercase">
                Safe Synthetic Data
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              One-click ingestion of 10 safe synthetic test cases (phishing, CEO fraud, auth failures, malware attachments, and multi-hop traces).
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleSeedDemoData}
            disabled={seeding}
            className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold transition-all shadow-md shadow-blue-600/20 disabled:opacity-50 cursor-pointer"
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
        <div className="bg-emerald-500/15 border border-emerald-500/30 rounded-xl p-3 flex items-center gap-2 text-xs text-emerald-300 animate-in fade-in duration-200">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>{seedSuccess}</span>
        </div>
      )}

      {/* Top Telemetry Metric Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <div className="bg-[#131B2A] border border-[#1E293B] p-4 rounded-xl shadow-lg space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Analyzed Messages</span>
            <Mail className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-extrabold text-white font-mono">{total_analyzed_emails}</div>
          <div className="text-[10px] text-slate-500 font-mono">SQLite Persistent Store</div>
        </div>

        <div className="bg-[#131B2A] border border-[#1E293B] p-4 rounded-xl shadow-lg space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>High/Critical Alerts</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-extrabold text-red-400 font-mono">{high_critical_threats}</div>
          <div className="text-[10px] text-slate-500 font-mono">
            {total_analyzed_emails > 0 ? `${Math.round((high_critical_threats / total_analyzed_emails) * 100)}% Alert Ratio` : '0%'}
          </div>
        </div>

        <div className="bg-[#131B2A] border border-[#1E293B] p-4 rounded-xl shadow-lg space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Active Case Incidents</span>
            <Briefcase className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-extrabold text-purple-400 font-mono">{active_cases}</div>
          <div className="text-[10px] text-slate-500 font-mono">Multi-Email Correlation</div>
        </div>

        <div className="bg-[#131B2A] border border-[#1E293B] p-4 rounded-xl shadow-lg space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Suspicious Domains</span>
            <Globe className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-extrabold text-amber-400 font-mono">{suspicious_domains_count}</div>
          <div className="text-[10px] text-slate-500 font-mono">Lookalikes & Typo Squats</div>
        </div>

        <div className="bg-[#131B2A] border border-[#1E293B] p-4 rounded-xl shadow-lg space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Flagged Transit IPs</span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-extrabold text-cyan-400 font-mono">{suspicious_ips_count}</div>
          <div className="text-[10px] text-slate-500 font-mono">Observed Relay Nodes</div>
        </div>
      </div>

      {/* Middle Grid: Severity Distribution & Category Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-4">
          <div className="border-b border-[#1E293B] pb-2">
            <h3 className="font-bold text-sm text-slate-100">Threat Tier Distribution</h3>
            <p className="text-xs text-slate-400">Classification of Analyzed Email Corpus</p>
          </div>

          <div className="w-full bg-[#0B0F17] h-3.5 rounded-full overflow-hidden flex border border-[#1E293B]">
            <div style={{ width: `${getPercentage(threat_distribution.critical)}%` }} className="bg-red-500 h-full" title={`Critical: ${threat_distribution.critical}`} />
            <div style={{ width: `${getPercentage(threat_distribution.high)}%` }} className="bg-orange-500 h-full" title={`High: ${threat_distribution.high}`} />
            <div style={{ width: `${getPercentage(threat_distribution.medium)}%` }} className="bg-amber-500 h-full" title={`Medium: ${threat_distribution.medium}`} />
            <div style={{ width: `${getPercentage(threat_distribution.low)}%` }} className="bg-emerald-500 h-full" title={`Low: ${threat_distribution.low}`} />
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="bg-[#0B0F17] p-2.5 rounded-lg border border-[#1E293B] flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-slate-300 font-sans">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> Critical
              </span>
              <span className="font-bold text-red-400">{threat_distribution.critical || 0}</span>
            </div>
            <div className="bg-[#0B0F17] p-2.5 rounded-lg border border-[#1E293B] flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-slate-300 font-sans">
                <span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span> High
              </span>
              <span className="font-bold text-orange-400">{threat_distribution.high || 0}</span>
            </div>
            <div className="bg-[#0B0F17] p-2.5 rounded-lg border border-[#1E293B] flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-slate-300 font-sans">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span> Medium
              </span>
              <span className="font-bold text-amber-400">{threat_distribution.medium || 0}</span>
            </div>
            <div className="bg-[#0B0F17] p-2.5 rounded-lg border border-[#1E293B] flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-slate-300 font-sans">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Low / Clean
              </span>
              <span className="font-bold text-emerald-400">{threat_distribution.low || 0}</span>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-3">
          <div className="border-b border-[#1E293B] pb-2 flex items-center justify-between">
            <div>
              <h3 className="font-bold text-sm text-slate-100">Top Threat Vectors & Rule Triggers</h3>
              <p className="text-xs text-slate-400">Observed Attack Vectors Across Ingested Messages</p>
            </div>
            <span className="text-[11px] font-mono text-slate-400 bg-[#0B0F17] px-2 py-0.5 rounded border border-[#1E293B]">
              12+ Detection Rules
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
            {Object.entries(top_categories).length === 0 ? (
              <p className="text-xs text-slate-500 col-span-3 py-4 text-center">No threats recorded in database yet.</p>
            ) : (
              Object.entries(top_categories).map(([cat, count], idx) => (
                <div key={idx} className="bg-[#0B0F17] p-3 rounded-lg border border-[#1E293B] flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300 truncate max-w-[130px]" title={cat}>
                    {cat.replace(/_/g, ' ')}
                  </span>
                  <span className="px-2 py-0.5 bg-blue-600/20 text-blue-300 border border-blue-500/30 rounded text-xs font-mono font-bold">
                    {count}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Bottom Table: Recent Analysis Activity */}
      <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[#1E293B] pb-3 gap-2">
          <div>
            <h3 className="font-bold text-sm text-slate-100">Recent Forensic Analyses</h3>
            <p className="text-xs text-slate-400">Live Intake Log from SQLite Persistence Layer</p>
          </div>

          <button
            onClick={onNewIntake}
            className="flex items-center gap-1 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold transition-colors cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" /> Analyze New Message
          </button>
        </div>

        {recent_analyses.length === 0 ? (
          <div className="bg-[#0B0F17] p-8 rounded-xl border border-[#1E293B] text-center text-xs text-slate-500 space-y-2">
            <p>No email analysis records found in database.</p>
            <p className="text-[11px]">Click "Load Demo SOC Dataset" above to populate sample emails.</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-[#1E293B]">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0B0F17] text-slate-400 text-[10px] uppercase font-semibold">
                <tr>
                  <th className="p-3">Subject / Incident Name</th>
                  <th className="p-3">Sender (From)</th>
                  <th className="p-3">Threat Score</th>
                  <th className="p-3">Risk Tier</th>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E293B] bg-[#131B2A]/40 font-mono text-[11px]">
                {recent_analyses.map((item) => (
                  <tr key={item.id} className="hover:bg-[#1E293B]/40 transition-colors">
                    <td className="p-3 font-sans font-semibold text-slate-200 max-w-xs truncate">
                      {item.subject || '(No Subject Line)'}
                    </td>
                    <td className="p-3 text-slate-300 max-w-[180px] truncate">
                      {item.sender || 'N/A'}
                    </td>
                    <td className="p-3 font-bold" style={{ color: item.risk_color }}>
                      {item.threat_score}/100
                    </td>
                    <td className="p-3 font-sans">
                      <span
                        className="px-2 py-0.5 rounded text-[10px] font-bold uppercase border"
                        style={{
                          backgroundColor: `${item.risk_color}18`,
                          color: item.risk_color,
                          borderColor: `${item.risk_color}40`,
                        }}
                      >
                        {item.risk_level}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400 text-[10px]">
                      {item.created_at ? item.created_at.replace('T', ' ').slice(0, 19) : 'N/A'}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => onSelectAnalysis(item.id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded text-[11px] font-sans font-semibold transition-colors cursor-pointer"
                      >
                        Inspect Dossier <ChevronRight className="w-3 h-3" />
                      </button>
                    </td>
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
// 2. CORRELATION VIEW
// ==========================================

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
      <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-16 flex flex-col items-center justify-center space-y-3">
        <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
        <p className="text-xs text-slate-400">Computing cross-email indicator correlation network...</p>
      </div>
    );
  }

  const { edges = [], clusters = [], total_correlated_emails = 0, total_shared_indicators = 0 } = graphData || {};

  return (
    <div className="space-y-6">
      <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-purple-600/20 border border-purple-500/30 rounded-xl text-purple-400">
            <Network className="w-6 h-6" />
          </div>
          <div>
            <h2 className="font-bold text-base text-slate-100">Multi-Email Correlation & Infrastructure Clustering</h2>
            <p className="text-xs text-slate-400">
              Cross-artifact relationship graph discovering shared sender patterns, lookalike domains, and MTA infrastructure
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-3 py-1 bg-[#0B0F17] rounded-lg border border-[#1E293B] text-xs font-mono text-slate-300">
            <span>{total_correlated_emails} Correlated Emails</span>
            <span>•</span>
            <span className="text-purple-400 font-bold">{total_shared_indicators} Shared Indicators</span>
          </div>
          <button
            onClick={fetchGraph}
            className="p-2 bg-[#0B0F17] hover:bg-[#1E293B] border border-[#1E293B] rounded-lg text-slate-400 hover:text-white transition-colors cursor-pointer"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
          Discovered Infrastructure Clusters ({clusters.length})
        </h3>

        {clusters.length === 0 ? (
          <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-8 text-center text-xs text-slate-500">
            No cross-email clusters identified yet. Ingest multiple emails sharing domains or relay IPs to see campaign correlation.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {clusters.map((c) => (
              <div
                key={c.cluster_id}
                className="bg-[#131B2A] border border-[#1E293B] hover:border-purple-500/50 rounded-xl p-4 space-y-3 transition-all shadow-lg"
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-xs font-bold text-slate-100 block">{c.cluster_name}</span>
                    <span className="text-[10px] font-mono text-purple-400 uppercase">{c.classification}</span>
                  </div>
                  <span className="px-2 py-0.5 bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded text-[10px] font-bold font-mono">
                    {c.member_email_ids.length} Emails Linked
                  </span>
                </div>

                <p className="text-xs text-slate-300 bg-[#0B0F17] p-2.5 rounded-lg border border-[#1E293B] leading-relaxed">
                  {c.summary_reason}
                </p>

                <div className="flex flex-wrap gap-1.5 pt-1">
                  {c.member_email_ids.map((emailId) => (
                    <button
                      key={emailId}
                      onClick={() => onSelectAnalysis(emailId)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 bg-[#0B0F17] hover:bg-blue-600/20 text-blue-400 border border-[#1E293B] hover:border-blue-500/40 rounded text-[11px] font-mono cursor-pointer"
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

      <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-4">
        <h3 className="font-bold text-sm text-slate-100">Observed Linkages ({edges.length} Edges)</h3>
        {edges.length > 0 && (
          <div className="overflow-x-auto rounded-lg border border-[#1E293B]">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0B0F17] text-slate-400 text-[10px] uppercase font-sans">
                <tr>
                  <th className="p-3">Source</th>
                  <th className="p-3">Relationship</th>
                  <th className="p-3">Target Node</th>
                  <th className="p-3">Rationale</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E293B] bg-[#131B2A]/40 text-[11px]">
                {edges.map((e, idx) => (
                  <tr key={idx} className="hover:bg-[#1E293B]/40">
                    <td className="p-3 text-blue-400 font-bold">{e.source}</td>
                    <td className="p-3 text-slate-300">{e.relationship}</td>
                    <td className="p-3 text-cyan-300 font-bold">{e.target}</td>
                    <td className="p-3 text-slate-400 font-sans">{e.reason || 'Observed correlation'}</td>
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

export function CaseManager({ currentAnalysis, onSelectAnalysisFromCase }) {
  const [cases, setCases] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState(null);
  const [activeCaseData, setActiveCaseData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);

  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newPriority, setNewPriority] = useState('HIGH');
  const [newNoteContent, setNewNoteContent] = useState('');
  const [analystName, setAnalystName] = useState('Forensic Analyst');

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
      const updated = await api.updateCase(selectedCaseId, { status: statusVal });
      setActiveCaseData(updated);
      fetchCases();
    } catch (err) {
      console.error("Error updating status:", err);
    }
  };

  const getPriorityBadge = (pri) => {
    switch (pri?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
    }
  };

  return (
    <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[#1E293B] pb-3 gap-3">
        <div className="flex items-center gap-2.5">
          <Briefcase className="w-5 h-5 text-blue-400" />
          <div>
            <h3 className="font-bold text-slate-100 text-base">Investigation Incident Cases</h3>
            <p className="text-xs text-slate-400">Multi-Message Forensic Case Management & Unified IOC Correlation</p>
          </div>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-1.5 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold transition-colors cursor-pointer shadow"
        >
          <Plus className="w-4 h-4" /> New Investigation Case
        </button>
      </div>

      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl max-w-md w-full p-5 space-y-4 shadow-2xl animate-in fade-in duration-200">
            <h4 className="font-bold text-slate-100 text-sm">Open New Forensic Investigation Case</h4>

            <form onSubmit={handleCreateCase} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Spear-Phishing Campaign Targeting CFO"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full bg-[#0B0F17] border border-[#1E293B] rounded-lg p-2 text-slate-200 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Case Description</label>
                <textarea
                  rows={3}
                  placeholder="Summary of threat scope, affected users, and objective..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full bg-[#0B0F17] border border-[#1E293B] rounded-lg p-2 text-slate-200 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Priority Level</label>
                <select
                  value={newPriority}
                  onChange={(e) => setNewPriority(e.target.value)}
                  className="w-full bg-[#0B0F17] border border-[#1E293B] rounded-lg p-2 text-slate-200 focus:outline-none focus:border-blue-500"
                >
                  <option value="CRITICAL">CRITICAL (Active Breach / Malware)</option>
                  <option value="HIGH">HIGH (Targeted Phishing / BEC)</option>
                  <option value="MEDIUM">MEDIUM (Suspicious Spam Campaign)</option>
                  <option value="LOW">LOW (Informational Incident)</option>
                </select>
              </div>

              {currentAnalysis && (
                <div className="bg-[#0B0F17] p-2.5 rounded border border-[#1E293B] text-[11px] text-slate-300">
                  <span className="text-blue-400 font-semibold block mb-0.5">Auto-Attach Current Analysis:</span>
                  <span className="truncate block font-mono">{currentAnalysis.metadata?.subject || currentAnalysis.analysis_id}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#1E293B]">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 bg-[#0B0F17] text-slate-400 hover:text-slate-200 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg"
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="space-y-2">
          <span className="text-xs font-semibold text-slate-400 block mb-1">Active Cases ({cases.length})</span>
          {cases.length === 0 ? (
            <div className="bg-[#0B0F17] p-4 rounded-xl border border-[#1E293B] text-center text-xs text-slate-500">
              No cases created yet. Click "New Investigation Case" above to start an investigation.
            </div>
          ) : (
            cases.map((c) => (
              <div
                key={c.id}
                onClick={() => setSelectedCaseId(c.id)}
                className={`p-3 rounded-xl border transition-all cursor-pointer ${
                  selectedCaseId === c.id
                    ? 'bg-blue-950/30 border-blue-500/60 shadow-lg'
                    : 'bg-[#0B0F17] border-[#1E293B] hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between gap-1 mb-1">
                  <span className="font-bold text-xs text-slate-100 truncate">{c.title}</span>
                  <span className={`px-2 py-0.5 text-[9px] font-extrabold uppercase rounded border ${getPriorityBadge(c.priority)}`}>
                    {c.priority}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                  <span>Status: <strong className="text-slate-200 font-sans">{c.status}</strong></span>
                  <span>{c.attached_analyses_count} Emails | {c.notes_count} Notes</span>
                </div>
              </div>
            ))
          )}
        </div>

        <div className="lg:col-span-2 space-y-5">
          {activeCaseData ? (
            <>
              <div className="bg-[#0B0F17] p-4 rounded-xl border border-[#1E293B] space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E293B] pb-3">
                  <div>
                    <h4 className="font-bold text-sm text-slate-100">{activeCaseData.title}</h4>
                    <p className="text-xs text-slate-400">{activeCaseData.description || 'No description provided.'}</p>
                  </div>

                  <div className="flex items-center gap-2">
                    <select
                      value={activeCaseData.status}
                      onChange={(e) => handleUpdateStatus(e.target.value)}
                      className="bg-[#131B2A] border border-[#1E293B] text-xs text-slate-200 rounded px-2.5 py-1 focus:outline-none focus:border-blue-500"
                    >
                      <option value="OPEN">Status: OPEN</option>
                      <option value="IN_PROGRESS">Status: IN PROGRESS</option>
                      <option value="CLOSED">Status: CLOSED</option>
                    </select>
                  </div>
                </div>

                {activeCaseData.unified_investigation_summary && (
                  <div className="bg-[#131B2A] p-3 rounded-lg border border-[#1E293B] text-xs text-slate-300 leading-relaxed">
                    <strong className="text-blue-300 block mb-1 font-semibold">Correlated Multi-Email Summary:</strong>
                    {activeCaseData.unified_investigation_summary.forensic_narrative}
                  </div>
                )}
              </div>

              <div className="bg-[#0B0F17] p-4 rounded-xl border border-[#1E293B] space-y-3">
                <span className="text-xs font-semibold text-slate-300 block">
                  Attached Email Artifacts ({activeCaseData.attached_analyses.length}):
                </span>

                {activeCaseData.attached_analyses.length === 0 ? (
                  <p className="text-xs text-slate-500 py-2">No email analyses attached yet.</p>
                ) : (
                  <div className="space-y-2">
                    {activeCaseData.attached_analyses.map((analysis) => (
                      <div key={analysis.analysis_id} className="bg-[#131B2A] p-3 rounded-lg border border-[#1E293B] flex items-center justify-between gap-3 text-xs">
                        <div className="space-y-0.5 max-w-md">
                          <span className="font-semibold text-slate-200 block truncate">
                            {analysis.metadata?.subject || '(No Subject)'}
                          </span>
                          <span className="text-[11px] text-slate-400 font-mono block">
                            From: {analysis.metadata?.from_address || 'N/A'} | Threat Score: <strong style={{ color: analysis.threat_score?.risk_color }}>{analysis.threat_score?.overall_score}/100 ({analysis.threat_score?.risk_level})</strong>
                          </span>
                        </div>

                        <div className="flex items-center gap-2 flex-shrink-0">
                          {onSelectAnalysisFromCase && (
                            <button
                              onClick={() => onSelectAnalysisFromCase(analysis.analysis_id)}
                              className="px-2.5 py-1 bg-blue-600/20 text-blue-400 border border-blue-500/30 rounded hover:bg-blue-600/30 text-[11px] font-semibold transition-colors"
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

              <div className="bg-[#0B0F17] p-4 rounded-xl border border-[#1E293B] space-y-4">
                <span className="text-xs font-semibold text-slate-300 block flex items-center gap-1.5">
                  <MessageSquare className="w-3.5 h-3.5 text-blue-400" /> Analyst Investigation Notes ({activeCaseData.notes.length})
                </span>

                <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
                  {activeCaseData.notes.map((note, idx) => (
                    <div key={idx} className="bg-[#131B2A] p-3 rounded-lg border border-[#1E293B] text-xs space-y-1">
                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span className="font-semibold text-blue-300 flex items-center gap-1">
                          <User className="w-3 h-3" /> {note.author}
                        </span>
                        <span className="font-mono text-[10px]">{note.created_at?.slice(0, 19).replace('T', ' ')}</span>
                      </div>
                      <p className="text-slate-200 leading-normal">{note.content}</p>
                    </div>
                  ))}
                </div>

                <form onSubmit={handleAddNote} className="flex gap-2 pt-2 border-t border-[#1E293B]">
                  <input
                    type="text"
                    placeholder="Type an analyst observation or forensic note..."
                    value={newNoteContent}
                    onChange={(e) => setNewNoteContent(e.target.value)}
                    className="flex-1 bg-[#131B2A] border border-[#1E293B] rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                  />
                  <button
                    type="submit"
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <Send className="w-3.5 h-3.5" /> Post Note
                  </button>
                </form>
              </div>
            </>
          ) : (
            <div className="bg-[#0B0F17] p-8 rounded-xl border border-[#1E293B] text-center text-xs text-slate-500">
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
    }, 250);
    return () => clearTimeout(delayDebounce);
  }, [query, isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-start justify-center pt-20 p-4">
      <div className="bg-[#131B2A] border border-[#1E293B] rounded-2xl max-w-xl w-full p-4 space-y-3 shadow-2xl">
        <div className="flex items-center gap-2 border-b border-[#1E293B] pb-2">
          <Search className="w-4 h-4 text-blue-400" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search indicators, domains, IPs, cases, subjects..."
            autoFocus
            className="flex-1 bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
          />
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-white rounded">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="max-h-72 overflow-y-auto space-y-1">
          {results.map((res, idx) => (
            <div
              key={idx}
              onClick={() => { onSelectResult(res.id); onClose(); }}
              className="p-2.5 rounded-lg bg-[#0B0F17] hover:bg-[#1E293B] border border-[#1E293B] cursor-pointer flex items-center justify-between gap-2"
            >
              <div>
                <div className="text-xs font-bold text-slate-200">{res.title}</div>
                <div className="text-[11px] text-slate-400 font-mono">{res.subtitle}</div>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 font-bold uppercase">{res.type}</span>
            </div>
          ))}
          {query.trim().length >= 2 && results.length === 0 && !loading && (
            <p className="text-xs text-slate-500 py-4 text-center">No matching entities found.</p>
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
      badgeColor: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
      sampleId: "01_legitimate",
      icon: <ShieldCheck className="w-6 h-6 text-emerald-400" />,
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
      badgeColor: "bg-red-500/20 text-red-400 border-red-500/40",
      sampleId: "02_phishing_suspension",
      icon: <ShieldAlert className="w-6 h-6 text-red-400" />,
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
      badgeColor: "bg-orange-500/20 text-orange-400 border-orange-500/40",
      sampleId: "03_spoofed_ceo",
      icon: <Mail className="w-6 h-6 text-orange-400" />,
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
      badgeColor: "bg-blue-500/20 text-blue-400 border-blue-500/40",
      sampleId: "07_multi_hop_relays",
      icon: <Server className="w-6 h-6 text-blue-400" />,
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
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-[#131B2A] border border-[#1E293B] rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl">
        <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
          <div className="flex items-center gap-2.5">
            <Sparkles className="w-5 h-5 text-purple-400" />
            <div>
              <h3 className="font-bold text-slate-100 text-sm">Guided SIH Evaluator Walkthrough</h3>
              <p className="text-xs text-slate-400">Step {currentStep + 1} of {scenarios.length} • Synthetic Test Cases</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-white rounded"><X className="w-4 h-4" /></button>
        </div>

        <div className="grid grid-cols-4 gap-2">
          {scenarios.map((s, idx) => (
            <div
              key={idx}
              onClick={() => setCurrentStep(idx)}
              className={`h-1.5 rounded-full cursor-pointer transition-all ${
                idx === currentStep ? 'bg-blue-500' : idx < currentStep ? 'bg-blue-800' : 'bg-[#0B0F17]'
              }`}
            />
          ))}
        </div>

        <div className="bg-[#0B0F17] p-5 rounded-xl border border-[#1E293B] space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-[#131B2A] border border-[#1E293B]">{current.icon}</div>
              <div>
                <h4 className="font-bold text-sm text-slate-100">{current.title}</h4>
                <p className="text-xs text-slate-400 font-mono">{current.subtitle}</p>
              </div>
            </div>
            <span className={`px-2.5 py-0.5 rounded text-[10px] font-extrabold uppercase border ${current.badgeColor}`}>
              Expected: {current.expectedThreat}
            </span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">{current.description}</p>
        </div>

        <div className="flex items-center justify-between pt-2 border-t border-[#1E293B]">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentStep(prev => Math.max(0, prev - 1))}
              disabled={currentStep === 0}
              className="flex items-center gap-1 px-3 py-1.5 bg-[#0B0F17] text-slate-400 border border-[#1E293B] rounded-lg text-xs disabled:opacity-30"
            >
              <ChevronLeft className="w-3.5 h-3.5" /> Prev
            </button>
            <button
              onClick={() => setCurrentStep(prev => Math.min(scenarios.length - 1, prev + 1))}
              disabled={currentStep === scenarios.length - 1}
              className="flex items-center gap-1 px-3 py-1.5 bg-[#0B0F17] text-slate-400 border border-[#1E293B] rounded-lg text-xs disabled:opacity-30"
            >
              Next <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <button
            onClick={() => { onLaunchSample(current.sampleId); onClose(); }}
            className="flex items-center gap-2 px-5 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white rounded-lg text-xs font-bold cursor-pointer"
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
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0B0F17] p-3 rounded-lg border border-[#1E293B]">
      <div>
        <span className="text-xs font-bold text-slate-200 block">Preloaded Synthetic Forensic Fixtures</span>
        <span className="text-[11px] text-slate-400">10 realistic test cases covering legitimate, spoofing, BEC, phishing, and malware</span>
      </div>

      <div className="relative min-w-[280px]">
        <select
          onChange={handleChange}
          defaultValue=""
          disabled={disabled || loading}
          className="w-full appearance-none bg-[#131B2A] border border-[#1E293B] hover:border-blue-500/50 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 cursor-pointer disabled:opacity-50"
        >
          <option value="" disabled>Choose a synthetic test email...</option>
          {samples.map((s) => (
            <option key={s.id} value={s.id}>
              [{s.expected_threat_level}] {s.name}
            </option>
          ))}
        </select>
        <ChevronDown className="w-4 h-4 text-slate-400 absolute right-2.5 top-2.5 pointer-events-none" />
      </div>
    </div>
  );
}
