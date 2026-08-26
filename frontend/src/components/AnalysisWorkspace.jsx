import React, { useState } from 'react';
import {
  Shield, FileCode, Network, Globe, Link2, Key, ShieldAlert,
  Database, Clock, Download, CheckCircle, FileText, X, Share2,
  Check, Bot, Sparkles, AlertTriangle, HelpCircle, CheckCircle2,
  Lock, Loader2, Send, User, ChevronRight, Server, ArrowRight,
  ExternalLink, Copy, Search, CornerDownRight, Hash
} from 'lucide-react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import api from '../api';

const customMarkerIcon = new L.DivIcon({
  className: 'custom-leaflet-marker',
  html: `<div style="background-color: #3B82F6; width: 14px; height: 14px; border-radius: 50%; border: 2px solid #FFFFFF; box-shadow: 0 0 8px rgba(59, 130, 246, 0.8);"></div>`,
  iconSize: [14, 14],
  iconAnchor: [7, 7]
});

export default function AnalysisWorkspace({ analysis, onNewIntake }) {
  const [activeTab, setActiveTab] = useState('synthesis');
  const [showExportModal, setShowExportModal] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [copiedMd, setCopiedMd] = useState(false);

  // Tamper Seal Modal State
  const [showSealModal, setShowSealModal] = useState(false);
  const [verifyingSeal, setVerifyingSeal] = useState(false);
  const [sealVerification, setSealVerification] = useState(null);

  // Copilot Chat State
  const [chatMessages, setChatMessages] = useState([
    {
      sender: 'assistant',
      content: `Hello Analyst. I have evaluated this message artifact (ID: ${analysis?.analysis_id?.slice(0, 8) || 'Current'}). The deterministic threat score is ${analysis?.threat_score?.overall_score || 0}/100 (${analysis?.threat_score?.risk_level || 'Low'} Risk). How can I assist your investigation?`
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);

  // Header Search Filter
  const [headerFilter, setHeaderFilter] = useState('');

  if (!analysis) {
    return (
      <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-16 flex flex-col items-center justify-center space-y-4 text-center">
        <ShieldAlert className="w-12 h-12 text-slate-600" />
        <h3 className="text-base font-bold text-slate-200">No Forensic Dossier Selected</h3>
        <p className="text-xs text-slate-400 max-w-md">
          Select an existing analysis from the SOC Dashboard or ingest a new email artifact using the button below.
        </p>
        <button
          onClick={onNewIntake}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold transition-all shadow-md"
        >
          Open New Intake Console
        </button>
      </div>
    );
  }

  const {
    analysis_id,
    timestamp,
    metadata = {},
    authentication = {},
    relays = [],
    relay_graph = {},
    extracted_urls = [],
    url_forensics = [],
    ip_intelligence = {},
    domain_intelligence = {},
    attachments = [],
    detection_findings = [],
    threat_score = { overall_score: 0, risk_level: 'Low', risk_color: '#10B981', explanation: '' },
    investigation_summary = {},
    timeline = [],
    iocs = [],
    ai_assessment = {},
    tamper_seal = {}
  } = analysis;

  const validRelays = relays.filter(r => r.latitude && r.longitude);
  const polylineCoords = validRelays.map(r => [r.latitude, r.longitude]);
  const centerCoord = validRelays.length > 0 ? [validRelays[0].latitude, validRelays[0].longitude] : [20, 0];

  const handleVerifySeal = async () => {
    setVerifyingSeal(true);
    try {
      const res = await api.verifySeal(analysis_id);
      setSealVerification(res);
    } catch (err) {
      console.error('Failed to verify seal:', err);
    } finally {
      setVerifyingSeal(false);
    }
  };

  const handleExportReport = async () => {
    try {
      const data = await api.getReport(analysis_id);
      setReportData(data);
      setShowExportModal(true);
    } catch (err) {
      console.error('Error fetching report:', err);
    }
  };

  const handleSendChat = async (e) => {
    e.preventDefault();
    if (!chatInput.trim() || chatLoading) return;

    const userQuery = chatInput;
    setChatInput('');
    setChatMessages(prev => [...prev, { sender: 'user', content: userQuery }]);
    setChatLoading(true);

    try {
      const res = await api.chat(analysis_id, userQuery);
      setChatMessages(prev => [
        ...prev,
        {
          sender: 'assistant',
          content: res.answer,
          referenced_evidence: res.referenced_evidence,
          suggested_followups: res.suggested_followups
        }
      ]);
    } catch (err) {
      setChatMessages(prev => [
        ...prev,
        { sender: 'assistant', content: 'Apologies, I encountered an error answering your investigation query.' }
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  const filteredHeaders = Object.entries(metadata.all_headers || {}).filter(([k, v]) => {
    if (!headerFilter.trim()) return true;
    const q = headerFilter.toLowerCase();
    return k.toLowerCase().includes(q) || String(v).toLowerCase().includes(q);
  });

  return (
    <div className="space-y-6">
      {/* Top Dossier Header Card */}
      <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1E293B] pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span
                className="px-2.5 py-0.5 rounded text-[11px] font-extrabold uppercase tracking-wider border"
                style={{
                  backgroundColor: `${threat_score.risk_color}18`,
                  color: threat_score.risk_color,
                  borderColor: `${threat_score.risk_color}50`
                }}
              >
                {threat_score.risk_level} Risk Tier
              </span>
              <span className="text-xs font-mono text-slate-400">ID: {analysis_id.slice(0, 12)}</span>
              <span className="text-xs text-slate-500">•</span>
              <span className="text-xs text-slate-400 font-mono">
                {timestamp ? timestamp.replace('T', ' ').slice(0, 19) + ' UTC' : 'N/A'}
              </span>
            </div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              {metadata.subject || '(No Subject Header)'}
            </h2>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 font-mono">
              <div>From: <span className="text-slate-200 font-semibold">{metadata.from_address || 'N/A'}</span></div>
              {metadata.reply_to && <div>Reply-To: <span className="text-amber-400">{metadata.reply_to}</span></div>}
              {metadata.return_path && <div>Return-Path: <span className="text-slate-300">{metadata.return_path}</span></div>}
            </div>
          </div>

          <div className="flex items-center gap-4 flex-shrink-0">
            <div className="text-right">
              <div className="text-3xl font-extrabold font-mono" style={{ color: threat_score.risk_color }}>
                {threat_score.overall_score}<span className="text-xs text-slate-500">/100</span>
              </div>
              <div className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Threat Score</div>
            </div>

            <div className="flex items-center gap-2 border-l border-[#1E293B] pl-4">
              <button
                onClick={() => { setShowSealModal(true); handleVerifySeal(); }}
                className="p-2 bg-[#0B0F17] hover:bg-[#1E293B] border border-[#1E293B] rounded-lg text-slate-300 hover:text-blue-400 transition-colors cursor-pointer"
                title="Verify Cryptographic SHA-256 Tamper Seal"
              >
                <Lock className="w-4 h-4" />
              </button>
              <button
                onClick={handleExportReport}
                className="p-2 bg-[#0B0F17] hover:bg-[#1E293B] border border-[#1E293B] rounded-lg text-slate-300 hover:text-emerald-400 transition-colors cursor-pointer"
                title="Export Forensic Investigation Report (TLP:AMBER)"
              >
                <Download className="w-4 h-4" />
              </button>
              <button
                onClick={onNewIntake}
                className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold transition-all shadow-md cursor-pointer"
              >
                New Intake
              </button>
            </div>
          </div>
        </div>

        {/* Quick Authentication Summary Pills */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
          <div className="bg-[#0B0F17] p-2.5 rounded-lg border border-[#1E293B] flex items-center justify-between">
            <span className="text-slate-400 font-sans">SPF Protocol</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border ${
              authentication.spf?.status === 'pass' ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : 'bg-red-500/20 text-red-400 border-red-500/30'
            }`}>
              {authentication.spf?.status || 'none'}
            </span>
          </div>

          <div className="bg-[#0B0F17] p-2.5 rounded-lg border border-[#1E293B] flex items-center justify-between">
            <span className="text-slate-400 font-sans">DKIM Signature</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border ${
              authentication.dkim?.status === 'pass' ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : 'bg-red-500/20 text-red-400 border-red-500/30'
            }`}>
              {authentication.dkim?.status || 'none'}
            </span>
          </div>

          <div className="bg-[#0B0F17] p-2.5 rounded-lg border border-[#1E293B] flex items-center justify-between">
            <span className="text-slate-400 font-sans">DMARC Policy</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border ${
              authentication.dmarc?.status === 'pass' ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : 'bg-red-500/20 text-red-400 border-red-500/30'
            }`}>
              {authentication.dmarc?.status || 'none'}
            </span>
          </div>

          <div className="bg-[#0B0F17] p-2.5 rounded-lg border border-[#1E293B] flex items-center justify-between">
            <span className="text-slate-400 font-sans">Transit Hops</span>
            <span className="text-cyan-400 font-bold">{relays.length} MTA Nodes</span>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex border-b border-[#1E293B] gap-1 overflow-x-auto text-xs font-semibold">
        {[
          { id: 'synthesis', label: 'Executive Synthesis', icon: ShieldAlert },
          { id: 'headers', label: 'Headers & Auth Forensics', icon: FileCode },
          { id: 'relays', label: `Relay Forensics & Geolocation (${relays.length})`, icon: Server },
          { id: 'intel', label: `URLs, Domains & IP Intel (${extracted_urls.length})`, icon: Globe },
          { id: 'attachments', label: `Attachments & Hashes (${attachments.length})`, icon: Database },
          { id: 'detection', label: `Detection Rules & Scoring (${detection_findings.length})`, icon: Key },
          { id: 'copilot', label: 'SOC Copilot & Chat', icon: Bot },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-400 bg-blue-500/10 rounded-t-lg font-bold'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-[#1E293B]/40'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: EXECUTIVE SYNTHESIS */}
      {activeTab === 'synthesis' && (
        <div className="space-y-6">
          <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <div>
                <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-purple-400" />
                  AI Threat Assessment & Investigation Priority
                </h3>
                <p className="text-xs text-slate-400">Ground-truth evidence breakdown and recommended actions</p>
              </div>

              {ai_assessment?.threat_category && (
                <span className="px-3 py-1 bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded-lg text-xs font-bold font-mono">
                  {ai_assessment.threat_category} ({Math.round((ai_assessment.confidence_score || 0.9) * 100)}% Confidence)
                </span>
              )}
            </div>

            <div className="bg-[#0B0F17] p-4 rounded-xl border border-[#1E293B] text-xs leading-relaxed text-slate-200">
              <strong className="text-blue-400 block mb-1 text-xs">Primary Rationale:</strong>
              {ai_assessment?.primary_rationale || threat_score.explanation}
            </div>

            {/* 3-Way Evidence Breakdown */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="bg-[#0B0F17] p-4 rounded-xl border border-emerald-500/30 space-y-2">
                <span className="font-bold text-emerald-400 block flex items-center gap-1.5">
                  <CheckCircle className="w-3.5 h-3.5" /> Observed Ground Facts
                </span>
                <ul className="space-y-1.5 text-slate-300 text-[11px] list-disc list-inside">
                  {(ai_assessment?.observed_evidence || []).map((item, idx) => (
                    <li key={idx} className="leading-snug">{item}</li>
                  ))}
                  {(!ai_assessment?.observed_evidence || ai_assessment.observed_evidence.length === 0) && (
                    <li className="text-slate-500">No observed anomalies.</li>
                  )}
                </ul>
              </div>

              <div className="bg-[#0B0F17] p-4 rounded-xl border border-amber-500/30 space-y-2">
                <span className="font-bold text-amber-400 block flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" /> Inferred Hypotheses
                </span>
                <ul className="space-y-1.5 text-slate-300 text-[11px] list-disc list-inside">
                  {(ai_assessment?.inferred_evidence || []).map((item, idx) => (
                    <li key={idx} className="leading-snug">{item}</li>
                  ))}
                  {(!ai_assessment?.inferred_evidence || ai_assessment.inferred_evidence.length === 0) && (
                    <li className="text-slate-500">None inferred.</li>
                  )}
                </ul>
              </div>

              <div className="bg-[#0B0F17] p-4 rounded-xl border border-slate-700 space-y-2">
                <span className="font-bold text-slate-400 block flex items-center gap-1.5">
                  <HelpCircle className="w-3.5 h-3.5" /> Unknown Gaps
                </span>
                <ul className="space-y-1.5 text-slate-400 text-[11px] list-disc list-inside">
                  {(ai_assessment?.unknown_gaps || []).map((item, idx) => (
                    <li key={idx} className="leading-snug">{item}</li>
                  ))}
                  {(!ai_assessment?.unknown_gaps || ai_assessment.unknown_gaps.length === 0) && (
                    <li className="text-slate-500">No critical evidence gaps.</li>
                  )}
                </ul>
              </div>
            </div>

            {/* Recommended Analyst Actions */}
            <div className="space-y-2">
              <span className="text-xs font-bold text-slate-300 block">Recommended SOC Analyst Actions:</span>
              <div className="space-y-1.5">
                {(ai_assessment?.recommended_analyst_actions || []).map((act, idx) => (
                  <div key={idx} className="bg-[#0B0F17] p-2.5 rounded-lg border border-[#1E293B] text-xs text-slate-300 flex items-center gap-2">
                    <ChevronRight className="w-3.5 h-3.5 text-blue-400 flex-shrink-0" />
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: HEADERS & AUTH FORENSICS */}
      {activeTab === 'headers' && (
        <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1E293B] pb-3">
            <div>
              <h3 className="font-bold text-sm text-slate-100">RFC 5322 Raw & Structured Transport Headers</h3>
              <p className="text-xs text-slate-400">Complete header map with cryptographic proof verification</p>
            </div>

            <div className="relative min-w-[220px]">
              <input
                type="text"
                placeholder="Filter header keys / values..."
                value={headerFilter}
                onChange={(e) => setHeaderFilter(e.target.value)}
                className="w-full bg-[#0B0F17] border border-[#1E293B] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
              />
              <Search className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 top-2.5 pointer-events-none" />
            </div>
          </div>

          <div className="bg-[#0B0F17] p-4 rounded-xl border border-[#1E293B] max-h-[500px] overflow-y-auto font-mono text-xs text-slate-300 space-y-2">
            {filteredHeaders.map(([k, v], idx) => (
              <div key={idx} className="border-b border-[#1E293B]/50 pb-2">
                <span className="text-blue-400 font-bold select-all">{k}: </span>
                <span className="text-slate-300 whitespace-pre-wrap select-all">
                  {Array.isArray(v) ? v.join('\n  ') : String(v)}
                </span>
              </div>
            ))}
            {filteredHeaders.length === 0 && (
              <p className="text-xs text-slate-500 py-4 text-center">No headers match the filter.</p>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: RELAY FORENSICS & GEOLOCATION */}
      {activeTab === 'relays' && (
        <div className="space-y-5">
          {/* Leaflet Dark Map */}
          <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl overflow-hidden shadow-xl">
            <div className="p-3 bg-[#0B0F17] border-b border-[#1E293B] flex items-center justify-between text-xs">
              <span className="font-bold text-slate-200 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-blue-400" /> Observed MTA Mail Relay Path
              </span>
              <span className="text-[10px] text-slate-400 font-mono">
                {validRelays.length} Geocoded Hops • Latency Deltas & Autonomous Systems
              </span>
            </div>

            <div className="h-72 w-full">
              <MapContainer
                center={centerCoord}
                zoom={2}
                scrollWheelZoom={false}
                className="dark-map-tiles"
                style={{ height: '100%', width: '100%', backgroundColor: '#0B0F17' }}
              >
                <TileLayer
                  attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                  url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                />
                {polylineCoords.length > 1 && (
                  <Polyline positions={polylineCoords} color="#3B82F6" weight={2} dashArray="4, 6" />
                )}
                {validRelays.map((r, idx) => (
                  <Marker key={idx} position={[r.latitude, r.longitude]} icon={customMarkerIcon}>
                    <Popup className="dark-popup">
                      <div className="text-xs space-y-1 font-sans">
                        <strong>Hop #{r.hop_number} ({r.role})</strong>
                        <div className="font-mono text-[11px]">IP: {r.ip_address}</div>
                        <div>Location: {r.city}, {r.country}</div>
                        <div>Org: {r.organization}</div>
                      </div>
                    </Popup>
                  </Marker>
                ))}
              </MapContainer>
            </div>
          </div>

          {/* Relays Table */}
          <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-4">
            <h3 className="font-bold text-sm text-slate-100">Chronological Relay Transit Chain ({relays.length} Hops)</h3>
            <div className="overflow-x-auto rounded-lg border border-[#1E293B]">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#0B0F17] text-slate-400 text-[10px] uppercase font-sans">
                  <tr>
                    <th className="p-3">Hop</th>
                    <th className="p-3">Received By / From</th>
                    <th className="p-3">IP Address</th>
                    <th className="p-3">Location / ISP</th>
                    <th className="p-3">Delay</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1E293B] bg-[#131B2A]/40 text-[11px]">
                  {relays.map((r) => (
                    <tr key={r.hop_number} className="hover:bg-[#1E293B]/40">
                      <td className="p-3 font-bold text-blue-400">#{r.hop_number}</td>
                      <td className="p-3 text-slate-300 max-w-xs truncate">
                        <div>by {r.by_host || 'N/A'}</div>
                        <div className="text-[10px] text-slate-500">from {r.from_host || 'N/A'}</div>
                      </td>
                      <td className="p-3 font-bold text-slate-200">{r.ip_address || 'Private/Unknown'}</td>
                      <td className="p-3 text-slate-400 font-sans">
                        {r.city ? `${r.city}, ${r.country}` : 'Internal'} ({r.organization || 'N/A'})
                      </td>
                      <td className="p-3 text-cyan-400 font-bold">
                        {r.delay_seconds !== null && r.delay_seconds !== undefined ? `+${r.delay_seconds}s` : '0s'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: INTEL & URLS */}
      {activeTab === 'intel' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-4">
            <h3 className="font-bold text-sm text-slate-100">Domain & Lookalike Forensics</h3>
            <div className="space-y-2">
              {Object.entries(domain_intelligence).map(([dom, info], idx) => (
                <div key={idx} className="bg-[#0B0F17] p-3 rounded-lg border border-[#1E293B] space-y-1 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-blue-400">{dom}</span>
                    {info.is_lookalike_typosquat && (
                      <span className="px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-[10px] font-bold uppercase">
                        Homoglyph Typosquatting
                      </span>
                    )}
                  </div>
                  {info.lookalike_target_brand && (
                    <div className="text-[11px] text-slate-400 font-sans">
                      Impersonating brand: <strong className="text-slate-200">{info.lookalike_target_brand}</strong>
                    </div>
                  )}
                </div>
              ))}
              {Object.keys(domain_intelligence).length === 0 && (
                <p className="text-xs text-slate-500 py-4 text-center">No domain anomalies discovered.</p>
              )}
            </div>
          </div>

          <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-4">
            <h3 className="font-bold text-sm text-slate-100">Extracted Hyperlinks ({extracted_urls.length})</h3>
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {extracted_urls.map((u, idx) => (
                <div key={idx} className="bg-[#0B0F17] p-3 rounded-lg border border-[#1E293B] space-y-1 text-xs font-mono">
                  <div className="text-blue-400 font-bold truncate max-w-full">{u.url}</div>
                  <div className="text-[11px] text-slate-400 font-sans flex items-center gap-2">
                    <span>Domain: <strong className="text-slate-300 font-mono">{u.domain}</strong></span>
                    {u.is_ip_host && <span className="text-red-400 font-bold">(Raw IP Address)</span>}
                  </div>
                  {u.has_anchor_mismatch && (
                    <div className="text-[10px] text-red-400 font-sans">
                      ⚠️ Anchor text mismatch: Displayed "{u.anchor_text}" differs from destination.
                    </div>
                  )}
                </div>
              ))}
              {extracted_urls.length === 0 && (
                <p className="text-xs text-slate-500 py-4 text-center">No hyperlinks found in message.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: ATTACHMENTS & HASHES */}
      {activeTab === 'attachments' && (
        <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-4">
          <h3 className="font-bold text-sm text-slate-100">Extracted Attachments & In-Memory Cryptographic Hashes</h3>
          {attachments.length === 0 ? (
            <div className="bg-[#0B0F17] p-8 rounded-xl border border-[#1E293B] text-center text-xs text-slate-500">
              No attached binary or document payloads found in this message.
            </div>
          ) : (
            <div className="space-y-3">
              {attachments.map((a, idx) => (
                <div key={idx} className="bg-[#0B0F17] p-4 rounded-xl border border-[#1E293B] space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-100 text-sm">{a.filename}</span>
                    {a.is_suspicious && (
                      <span className="px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-[10px] font-bold uppercase">
                        Suspicious / Executable Payload
                      </span>
                    )}
                  </div>
                  <div className="text-slate-400 font-sans">
                    Size: <strong className="text-slate-200">{(a.size_bytes / 1024).toFixed(1)} KB</strong> | MIME Type: <strong className="text-slate-200">{a.content_type}</strong>
                  </div>
                  <div className="text-[11px] text-slate-400 select-all">SHA-256: <span className="text-cyan-400">{a.sha256}</span></div>
                  <div className="text-[11px] text-slate-400 select-all">MD5: <span className="text-purple-400">{a.md5}</span></div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 6: DETECTION RULES */}
      {activeTab === 'detection' && (
        <div className="space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
            Triggered Security Findings ({detection_findings.length})
          </h3>

          {detection_findings.length === 0 ? (
            <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-8 text-center text-xs text-slate-400">
              <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
              <p className="font-semibold text-slate-200">Zero Security Findings Triggered</p>
              <p className="text-[11px] text-slate-500">Clean authentication and normal transit patterns.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {detection_findings.map((f, idx) => (
                <div key={idx} className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-4 space-y-2 shadow-md">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 text-[10px] font-mono font-bold">
                        {f.rule_id}
                      </span>
                      <h4 className="font-bold text-xs text-slate-100">{f.rule_name}</h4>
                    </div>
                    <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                      {f.severity} (+{f.points} PTS)
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{f.explanation}</p>
                  {f.evidence && (
                    <div className="text-[11px] font-mono text-slate-400 bg-[#0B0F17] p-2.5 rounded-lg border border-[#1E293B]">
                      Evidence: {f.evidence}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 7: SOC COPILOT & CHAT */}
      {activeTab === 'copilot' && (
        <div className="bg-[#131B2A] border border-[#1E293B] rounded-xl p-5 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
            <div className="flex items-center gap-2.5">
              <Bot className="w-5 h-5 text-blue-400" />
              <div>
                <h3 className="font-bold text-sm text-slate-100">SOC Forensic Copilot</h3>
                <p className="text-xs text-slate-400">Conversational AI assistant answering queries directly from email evidence</p>
              </div>
            </div>
          </div>

          <div className="bg-[#0B0F17] p-4 rounded-xl border border-[#1E293B] h-80 overflow-y-auto space-y-3">
            {chatMessages.map((m, idx) => (
              <div
                key={idx}
                className={`p-3.5 rounded-xl text-xs max-w-xl leading-relaxed space-y-2 ${
                  m.sender === 'user'
                    ? 'ml-auto bg-blue-600 text-white font-medium'
                    : 'mr-auto bg-[#131B2A] text-slate-200 border border-[#1E293B]'
                }`}
              >
                <div className="flex items-center gap-1.5 text-[10px] text-slate-400 font-mono">
                  <User className="w-3 h-3" />
                  <span>{m.sender === 'user' ? 'You' : 'Forensic Assistant'}</span>
                </div>
                <p>{m.content}</p>
              </div>
            ))}
            {chatLoading && (
              <div className="mr-auto bg-[#131B2A] p-3 rounded-xl border border-[#1E293B] text-xs text-slate-400 flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-blue-400" /> Evaluating indicators...
              </div>
            )}
          </div>

          <form onSubmit={handleSendChat} className="flex gap-2">
            <input
              type="text"
              placeholder="Ask Copilot about sender authentication, lookalike domains, or MTA hops..."
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              className="flex-1 bg-[#0B0F17] border border-[#1E293B] rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            />
            <button
              type="submit"
              disabled={chatLoading || !chatInput.trim()}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" /> Send
            </button>
          </form>
        </div>
      )}

      {/* Tamper Seal Modal */}
      {showSealModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#131B2A] border border-[#1E293B] rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <div className="flex items-center gap-2">
                <Lock className="w-5 h-5 text-blue-400" />
                <h3 className="font-bold text-sm text-slate-100">Cryptographic Chain-of-Custody Proof</h3>
              </div>
              <button onClick={() => setShowSealModal(false)} className="text-slate-400 hover:text-white"><X className="w-4 h-4" /></button>
            </div>

            <div className="bg-[#0B0F17] p-4 rounded-xl border border-[#1E293B] space-y-2 text-xs font-mono">
              <div className="text-slate-400">Seal ID: <span className="text-slate-200">{tamper_seal.seal_id}</span></div>
              <div className="text-slate-400">Timestamp: <span className="text-slate-200">{tamper_seal.timestamp_utc}</span></div>
              <div className="text-slate-400 select-all">SHA-256 Payload Hash: <span className="text-cyan-400">{tamper_seal.payload_sha256}</span></div>
              <div className="text-slate-400 select-all">Seal Hash: <span className="text-purple-400">{tamper_seal.current_seal_hash}</span></div>
            </div>

            {sealVerification && (
              <div className="p-3 bg-emerald-500/15 border border-emerald-500/30 rounded-xl text-xs text-emerald-300 flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>{sealVerification.verification_details}</span>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowSealModal(false)}
                className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-lg"
              >
                Close Proof
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Export Report Modal */}
      {showExportModal && reportData && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#131B2A] border border-[#1E293B] rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-emerald-400" />
                <h3 className="font-bold text-sm text-slate-100">Forensic Investigation Report (TLP:AMBER)</h3>
              </div>
              <button onClick={() => setShowExportModal(false)} className="text-slate-400 hover:text-white"><X className="w-4 h-4" /></button>
            </div>

            <textarea
              readOnly
              rows={12}
              value={reportData.report_markdown}
              className="w-full bg-[#0B0F17] border border-[#1E293B] rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none"
            />

            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] text-slate-400">Report ID: {reportData.report_id}</span>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(reportData.report_markdown);
                    setCopiedMd(true);
                    setTimeout(() => setCopiedMd(false), 2000);
                  }}
                  className="px-3.5 py-1.5 bg-[#0B0F17] border border-[#1E293B] text-slate-300 hover:text-white text-xs rounded-lg flex items-center gap-1.5"
                >
                  {copiedMd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedMd ? 'Copied Markdown' : 'Copy Markdown'}</span>
                </button>
                <button
                  onClick={() => setShowExportModal(false)}
                  className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-lg"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
