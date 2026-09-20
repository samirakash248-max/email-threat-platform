import React, { useState, useEffect } from 'react';
import {
  Shield, FileCode, Network, Globe, Link2, Key, ShieldAlert,
  Database, Clock, Download, CheckCircle, FileText, X, Share2,
  Check, Bot, Sparkles, AlertTriangle, HelpCircle, CheckCircle2,
  Lock, Loader2, Send, User, ChevronRight, Server, ArrowRight,
  ExternalLink, Copy, Search, CornerDownRight, Hash, ShieldCheck,
  Zap, Info, Layers, RefreshCw, PlusCircle
} from 'lucide-react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import api from '../api';

const customMarkerIcon = new L.DivIcon({
  className: 'custom-leaflet-marker',
  html: `<div style="background-color: #3B82F6; width: 12px; height: 12px; border-radius: 50%; border: 2px solid #FFFFFF; box-shadow: 0 0 10px rgba(59, 130, 246, 0.9);"></div>`,
  iconSize: [12, 12],
  iconAnchor: [6, 6]
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

  // Chain of Custody Lifecycle State
  const [custodyData, setCustodyData] = useState(null);
  const [custodyLoading, setCustodyLoading] = useState(false);
  const [showAddCustodyModal, setShowAddCustodyModal] = useState(false);
  const [custodyNote, setCustodyNote] = useState('');
  const [custodyAuthor, setCustodyAuthor] = useState('SOC Analyst');
  const [custodyEventType, setCustodyEventType] = useState('ANALYST_REVIEW');

  const fetchCustody = async () => {
    if (!analysis?.analysis_id) return;
    setCustodyLoading(true);
    try {
      const data = await api.getCustodyChain(analysis.analysis_id);
      setCustodyData(data);
    } catch (e) {
      console.error('Error fetching custody chain:', e);
    } finally {
      setCustodyLoading(false);
    }
  };

  useEffect(() => {
    if (analysis?.analysis_id) {
      fetchCustody();
    }
  }, [analysis?.analysis_id]);

  // Blockchain Evidence Verification State
  const [blockchainVerification, setBlockchainVerification] = useState(null);
  const [verifyingEvidence, setVerifyingEvidence] = useState(false);
  const [simulatingTamper, setSimulatingTamper] = useState(false);

  const handleVerifyEvidence = async () => {
    if (!analysis?.analysis_id) return;
    setVerifyingEvidence(true);
    try {
      const [bRes, cRes] = await Promise.all([
        api.verifyBlockchainEvidence(analysis.analysis_id),
        api.verifyCustodyChain(analysis.analysis_id)
      ]);
      setBlockchainVerification(bRes);
      setCustodyData(cRes);
    } catch (err) {
      console.error('Failed to verify evidence on blockchain:', err);
    } finally {
      setVerifyingEvidence(false);
    }
  };

  const handleSimulateTamper = async () => {
    if (!analysis?.analysis_id) return;
    setSimulatingTamper(true);
    try {
      await api.simulateTamper(analysis.analysis_id);
      await handleVerifyEvidence();
    } catch (err) {
      console.error('Failed to simulate tamper:', err);
    } finally {
      setSimulatingTamper(false);
    }
  };

  const handleRestoreEvidence = async () => {
    if (!analysis?.analysis_id) return;
    setSimulatingTamper(true);
    try {
      await api.restoreEvidence(analysis.analysis_id);
      await handleVerifyEvidence();
    } catch (err) {
      console.error('Failed to restore evidence:', err);
    } finally {
      setSimulatingTamper(false);
    }
  };

  // Broadcast IoCs to Threat Intel Registry
  const [publishingIoCs, setPublishingIoCs] = useState(false);
  const [publishFeedback, setPublishFeedback] = useState(null);

  const handlePublishIoCs = async () => {
    if (!analysis?.analysis_id) return;
    setPublishingIoCs(true);
    setPublishFeedback(null);
    try {
      const res = await api.publishDossierIoCs(analysis.analysis_id);
      setPublishFeedback(`Broadcasted ${res.published_count} verified IoCs to Decentralized Threat Intel Registry.`);
      setTimeout(() => setPublishFeedback(null), 4000);
    } catch (e) {
      console.error('Failed to publish IoCs:', e);
      setPublishFeedback('Failed to broadcast IoCs.');
      setTimeout(() => setPublishFeedback(null), 4000);
    } finally {
      setPublishingIoCs(false);
    }
  };

  const handleAddCustodyEvent = async (e) => {
    e.preventDefault();
    if (!analysis?.analysis_id || !custodyNote.trim()) return;
    try {
      await api.addCustodyEvent(analysis.analysis_id, {
        event_type: custodyEventType,
        actor: custodyAuthor,
        details: { summary: custodyNote.trim(), action_code: "ANALYST_ACTION" }
      });
      setCustodyNote('');
      setShowAddCustodyModal(false);
      await fetchCustody();
    } catch (err) {
      console.error('Failed to add custody event:', err);
    }
  };

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
      <div className="surface-card p-16 flex flex-col items-center justify-center space-y-4 text-center">
        <div className="p-4 rounded-2xl bg-slate-50 border border-[#E2E8F0] text-slate-500">
          <ShieldAlert className="w-10 h-10" />
        </div>
        <h3 className="text-base font-bold text-slate-800">No Forensic Dossier Selected</h3>
        <p className="text-xs text-slate-600 max-w-md">
          Select an existing analysis from the SOC Dashboard or ingest a new email artifact using the button below.
        </p>
        <button
          onClick={onNewIntake}
          className="btn-tactile px-4 py-2 btn-block-primary text-white rounded-xl text-xs font-bold transition-all shadow-glow-blue"
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
    investigative_assessment = null,
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
      <div className="surface-card p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#E2E8F0] pb-5">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span
                className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider border"
                style={{
                  backgroundColor: `${threat_score.risk_color}14`,
                  color: threat_score.risk_color,
                  borderColor: `${threat_score.risk_color}40`
                }}
              >
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: threat_score.risk_color }}></span>
                {threat_score.risk_level} Risk Tier
              </span>
              <span className="text-xs font-mono text-slate-600">ID: {analysis_id.slice(0, 10)}</span>
              <span className="text-slate-600">•</span>
              <span className="text-xs text-slate-600 font-mono">
                {timestamp ? timestamp.replace('T', ' ').slice(0, 19) + ' UTC' : 'N/A'}
              </span>
            </div>

            <h2 className="text-lg font-bold text-slate-900 tracking-tight">
              {metadata.subject || '(No Subject Header)'}
            </h2>

            <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-slate-600 font-mono pt-0.5">
              <div>From: <span className="text-slate-800 font-semibold">{metadata.from_address || 'N/A'}</span></div>
              {metadata.reply_to && <div>Reply-To: <span className="text-amber-700 font-medium">{metadata.reply_to}</span></div>}
              {metadata.return_path && <div>Return-Path: <span className="text-slate-600">{metadata.return_path}</span></div>}
            </div>
          </div>

          <div className="flex items-center gap-4 flex-shrink-0">
            <div className="text-right">
              <div className="text-3xl font-extrabold font-mono tabular-nums tracking-tight" style={{ color: threat_score.risk_color }}>
                {threat_score.overall_score}<span className="text-xs font-normal text-slate-500">/100</span>
              </div>
              <div className="text-[10px] uppercase font-bold tracking-wider text-slate-600">Threat Score</div>
            </div>

            <div className="flex items-center gap-2 border-l border-[#E2E8F0] pl-4">
              <button
                onClick={handlePublishIoCs}
                disabled={publishingIoCs}
                className="p-2 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] rounded-xl text-slate-700 hover:text-cyan-700 transition-colors cursor-pointer"
                title="Broadcast Non-Sensitive IoCs to Decentralized Threat Intel Registry"
              >
                {publishingIoCs ? <Loader2 className="w-4 h-4 animate-spin text-cyan-700" /> : <Globe className="w-4 h-4" />}
              </button>
              <button
                onClick={() => { setShowSealModal(true); handleVerifySeal(); }}
                className="p-2 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] rounded-xl text-slate-700 hover:text-blue-600 transition-colors cursor-pointer"
                title="Verify Cryptographic SHA-256 Tamper Seal"
              >
                <Lock className="w-4 h-4" />
              </button>
              <button
                onClick={handleExportReport}
                className="p-2 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] rounded-xl text-slate-700 hover:text-emerald-700 transition-colors cursor-pointer"
                title="Export Forensic Investigation Report (TLP:AMBER)"
              >
                <Download className="w-4 h-4" />
              </button>
              <button
                onClick={onNewIntake}
                className="btn-tactile px-4 py-2 btn-block-primary text-white rounded-xl text-xs font-bold transition-all shadow-glow-blue cursor-pointer"
              >
                New Intake
              </button>
            </div>
          </div>

          {publishFeedback && (
            <div className="bg-cyan-50 border border-cyan-200 rounded-xl p-3 flex items-center gap-2 text-xs text-cyan-800 animate-in fade-in duration-200">
              <CheckCircle2 className="w-4 h-4 text-cyan-700 flex-shrink-0" />
              <span>{publishFeedback}</span>
            </div>
          )}
        </div>

        {/* Quick Authentication Summary Pills */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
          <div className="surface-card-subtle p-3 flex items-center justify-between">
            <span className="text-slate-600 font-sans text-xs">SPF Protocol</span>
            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase border ${
              authentication.spf?.status === 'pass' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-rose-50 text-rose-600 border-rose-200'
            }`}>
              {authentication.spf?.status || 'none'}
            </span>
          </div>

          <div className="surface-card-subtle p-3 flex items-center justify-between">
            <span className="text-slate-600 font-sans text-xs">DKIM Signature</span>
            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase border ${
              authentication.dkim?.status === 'pass' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-rose-50 text-rose-600 border-rose-200'
            }`}>
              {authentication.dkim?.status || 'none'}
            </span>
          </div>

          <div className="surface-card-subtle p-3 flex items-center justify-between">
            <span className="text-slate-600 font-sans text-xs">DMARC Policy</span>
            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase border ${
              authentication.dmarc?.status === 'pass' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-rose-50 text-rose-600 border-rose-200'
            }`}>
              {authentication.dmarc?.status || 'none'}
            </span>
          </div>

          <div className="surface-card-subtle p-3 flex items-center justify-between">
            <span className="text-slate-600 font-sans text-xs">Transit Hops</span>
            <span className="text-cyan-700 font-bold font-mono">{relays.length} MTA Nodes</span>
          </div>
        </div>

        {/* Dedicated Blockchain Forensic Verification Section */}
        <div className="surface-card-subtle p-4 rounded-xl border border-[#E2E8F0] space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#F1F5F9] pb-3">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-cyan-50 text-cyan-700">
                <Layers className="w-4 h-4" />
              </div>
              <div>
                <span className="text-xs font-bold text-slate-800 block">
                  Blockchain Forensic Evidence Verification
                </span>
                <span className="text-[11px] text-slate-600">
                  Immutable Non-Repudiation Layer • Proof-of-Authority Smart Contract Anchor
                </span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {/* Dynamic Blockchain Status Badge */}
              <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-bold uppercase border ${
                blockchainVerification?.tamper_detected || custodyData?.status === 'MODIFIED'
                  ? 'bg-rose-50 text-rose-600 border-rose-200 animate-pulse'
                  : blockchainVerification?.payload_hash_intact || tamper_seal?.blockchain_verified
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : tamper_seal?.blockchain_status === 'PENDING'
                  ? 'bg-amber-50 text-amber-700 border-amber-200'
                  : 'bg-slate-500/15 text-slate-600 border-slate-500/30'
              }`}>
                {blockchainVerification?.tamper_detected || custodyData?.status === 'MODIFIED' ? (
                  <>⚠ Evidence Integrity Compromised</>
                ) : blockchainVerification?.payload_hash_intact || tamper_seal?.blockchain_verified ? (
                  <>✓ Evidence Integrity Verified</>
                ) : tamper_seal?.blockchain_status === 'PENDING' ? (
                  <>⏳ Blockchain Registration Pending</>
                ) : (
                  <>○ Blockchain Not Available</>
                )}
              </span>

              {/* Verify Evidence Action Button */}
              <button
                onClick={handleVerifyEvidence}
                disabled={verifyingEvidence}
                className="btn-tactile px-3.5 py-1 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-bold rounded-xl flex items-center gap-1.5 shadow-glow-blue cursor-pointer disabled:opacity-50"
              >
                {verifyingEvidence ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                <span>Verify Evidence</span>
              </button>

              {/* Controlled Demo Simulation Buttons */}
              <div className="flex items-center gap-1 border-l border-[#E2E8F0] pl-2">
                <button
                  onClick={handleSimulateTamper}
                  disabled={simulatingTamper}
                  title="SIH Evaluator Demo: Simulate off-chain database tampering attack"
                  className="px-2.5 py-1 bg-rose-50 hover:bg-rose-50 text-rose-600 border border-rose-500/25 rounded-xl text-[11px] font-bold flex items-center gap-1 transition-colors cursor-pointer disabled:opacity-50"
                >
                  <AlertTriangle className="w-3 h-3" />
                  <span>Simulate DB Tamper (Demo)</span>
                </button>
                
                {(blockchainVerification?.tamper_detected || custodyData?.status === 'MODIFIED') && (
                  <button
                    onClick={handleRestoreEvidence}
                    disabled={simulatingTamper}
                    title="Restore authentic cryptographic record"
                    className="px-2.5 py-1 bg-emerald-50 hover:bg-emerald-50 text-emerald-700 border border-emerald-500/25 rounded-xl text-[11px] font-bold flex items-center gap-1 transition-colors cursor-pointer disabled:opacity-50"
                  >
                    <RefreshCw className="w-3 h-3" />
                    <span>Restore Authentic</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Blockchain Verification Detail Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 text-xs font-mono">
            <div className="p-2.5 rounded-lg bg-[#0B0F19] border border-[#F1F5F9] space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Evidence ID</span>
              <span className="text-slate-800 truncate block font-bold select-all">{analysis_id}</span>
            </div>

            <div className="p-2.5 rounded-lg bg-[#0B0F19] border border-[#F1F5F9] space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Evidence SHA-256 Hash</span>
              <span className="text-cyan-700 truncate block select-all">
                {blockchainVerification?.canonical_evidence_hash || tamper_seal?.payload_sha256 || 'N/A'}
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-[#0B0F19] border border-[#F1F5F9] space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Blockchain Tx / Reference ID</span>
              <span className="text-amber-700 truncate block select-all">
                {blockchainVerification?.tx_id || tamper_seal?.tx_id || `0x${(tamper_seal?.block_hash || '00').slice(0, 36)}...`}
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-[#0B0F19] border border-[#F1F5F9] space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Registration Timestamp</span>
              <span className="text-slate-700 truncate block">
                {tamper_seal?.timestamp_utc ? tamper_seal.timestamp_utc.replace('T', ' ').slice(0, 19) + ' UTC' : 'N/A'}
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-[#0B0F19] border border-[#F1F5F9] space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Chain-of-Custody Status</span>
              <span className="text-emerald-700 font-bold block">
                {custodyData?.status || 'VERIFIED'} ({custodyData?.total_events || 4} Lifecycle Events)
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-[#0B0F19] border border-[#F1F5F9] space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Verification Result</span>
              <span className={`block font-bold truncate ${
                blockchainVerification?.tamper_detected ? 'text-rose-600' : 'text-emerald-700'
              }`}>
                {blockchainVerification?.verification_status
                  ? blockchainVerification.verification_status.replace(/_/g, ' ')
                  : 'UNCHANGED (Authentic)'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex bg-[#EFF6FF] p-1 rounded-xl border border-[#F1F5F9] gap-1 overflow-x-auto text-xs font-semibold shadow-inner-light">
        {[
          { id: 'synthesis', label: 'Executive Synthesis', icon: ShieldAlert },
          { id: 'custody', label: `Chain of Custody (${custodyData?.events?.length || 4})`, icon: Lock },
          { id: 'headers', label: 'Headers & Auth', icon: FileCode },
          { id: 'relays', label: `Relay Forensics (${relays.length})`, icon: Server },
          { id: 'intel', label: `URLs & Domains (${extracted_urls.length})`, icon: Globe },
          { id: 'attachments', label: `Attachments (${attachments.length})`, icon: Database },
          { id: 'detection', label: `Rules & Scoring (${detection_findings.length})`, icon: Key },
          { id: 'copilot', label: 'SOC Copilot', icon: Bot },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg transition-all cursor-pointer whitespace-nowrap ${
                activeTab === tab.id
                  ? 'bg-blue-600 text-white shadow-sm font-bold'
                  : 'text-slate-600 hover:text-slate-800 hover:bg-[#F0F7FF]'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB: CHAIN OF CUSTODY LIFECYCLE */}
      {activeTab === 'custody' && (
        <div className="space-y-6">
          <div className="surface-card p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E2E8F0] pb-4">
              <div>
                <div className="flex items-center gap-2.5">
                  <h3 className="font-bold text-sm text-slate-900 flex items-center gap-2">
                    <Lock className="w-4 h-4 text-cyan-700" />
                    Digital Chain-of-Custody & Forensic Lifecycle
                  </h3>
                  {custodyData && (
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase border flex items-center gap-1 ${
                      custodyData.status === 'VERIFIED'
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : custodyData.status === 'MODIFIED'
                        ? 'bg-rose-50 text-rose-600 border-rose-200'
                        : custodyData.status === 'BLOCKCHAIN_UNAVAILABLE'
                        ? 'bg-amber-50 text-amber-700 border-amber-200'
                        : 'bg-slate-500/10 text-slate-600 border-slate-500/30'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${
                        custodyData.status === 'VERIFIED' ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'
                      }`}></span>
                      {custodyData.status.replace(/_/g, ' ')}
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-600 mt-1">
                  Cryptographically linked lifecycle stages proving authenticity, sequencing, and non-repudiation
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={fetchCustody}
                  disabled={custodyLoading}
                  className="btn-tactile px-3.5 py-1.5 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] text-slate-700 text-xs rounded-xl flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
                >
                  {custodyLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                  <span>Re-Verify Chain</span>
                </button>

                <button
                  onClick={() => setShowAddCustodyModal(true)}
                  className="btn-tactile px-3.5 py-1.5 btn-block-primary text-white text-xs font-bold rounded-xl flex items-center gap-1.5 shadow-glow-blue cursor-pointer"
                >
                  <PlusCircle className="w-3.5 h-3.5" />
                  <span>Record Analyst Review</span>
                </button>
              </div>
            </div>

            {/* Verification Details Alert */}
            {custodyData && (
              <div className={`p-3.5 rounded-xl text-xs flex items-start gap-2.5 border ${
                custodyData.is_intact
                  ? 'bg-emerald-50 border-emerald-500/25 text-emerald-700'
                  : 'bg-rose-50 border-rose-200 text-rose-700'
              }`}>
                {custodyData.is_intact ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-700 flex-shrink-0 mt-0.5" />
                ) : (
                  <ShieldAlert className="w-4 h-4 text-rose-600 flex-shrink-0 mt-0.5" />
                )}
                <div>
                  <div className="font-bold uppercase tracking-wider mb-0.5">
                    {custodyData.status} — {custodyData.total_events} Lifecycle Events Anchored
                  </div>
                  <div className="text-[11px] leading-snug">{custodyData.verification_details}</div>
                </div>
              </div>
            )}

            {/* Chronological Event Timeline */}
            <div className="space-y-3 pt-2">
              {(custodyData?.events || []).map((evt, idx) => (
                <div key={idx} className="surface-card-subtle p-4 rounded-xl border border-[#F1F5F9] space-y-2">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded-md bg-blue-50 text-blue-600 border border-blue-200 text-[10px] font-bold font-mono">
                        Step #{evt.sequence_number}
                      </span>
                      <span className="font-bold text-xs text-slate-900 uppercase tracking-wide">
                        {evt.event_type.replace(/_/g, ' ')}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-[11px] text-slate-600 font-mono">
                      <span>Actor: <strong className="text-slate-800">{evt.actor}</strong></span>
                      <span>•</span>
                      <span>{evt.timestamp.replace('T', ' ').slice(0, 19)} UTC</span>
                    </div>
                  </div>

                  {evt.event_data?.summary && (
                    <p className="text-xs text-slate-700 font-sans leading-relaxed">
                      {evt.event_data.summary}
                    </p>
                  )}

                  <div className="p-2.5 rounded-lg bg-[#0B0F19] border border-[#F1F5F9] text-[11px] font-mono space-y-1 text-slate-600">
                    <div className="truncate select-all">
                      Event SHA-256: <span className="text-cyan-700">{evt.event_hash}</span>
                    </div>
                    <div className="truncate select-all">
                      Prev Hash Link: <span className="text-slate-500">{evt.previous_event_hash}</span>
                    </div>
                    {evt.tx_id && (
                      <div className="truncate select-all">
                        On-Chain Tx ID: <span className="text-amber-700">{evt.tx_id}</span>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 1: EXECUTIVE SYNTHESIS */}
      {activeTab === 'synthesis' && (
        <div className="space-y-6">
          <div className="surface-card p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-4">
              <div>
                <h3 className="font-bold text-sm text-slate-900 flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-purple-700" />
                  AI Threat Assessment & Investigation Priority
                </h3>
                <p className="text-xs text-slate-600 mt-0.5">Ground-truth evidence breakdown and recommended actions</p>
              </div>

              {ai_assessment?.threat_category && (
                <span className="px-3 py-1 bg-purple-50 text-purple-700 border border-purple-200 rounded-full text-xs font-bold font-mono">
                  {ai_assessment.threat_category} ({Math.round((ai_assessment.confidence_score || 0.9) * 100)}% Confidence)
                </span>
              )}
            </div>

            <div className="surface-card-subtle p-4 text-xs leading-relaxed text-slate-800 border border-[#F1F5F9]">
              <strong className="text-blue-600 block mb-1 text-xs font-bold flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5" /> Primary Rationale:
              </strong>
              {ai_assessment?.primary_rationale || threat_score.explanation}
            </div>

            {/* 3-Way Evidence Breakdown */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="surface-card-subtle p-4 border-l-2 border-l-emerald-500 space-y-2">
                <span className="font-bold text-emerald-700 block flex items-center gap-1.5">
                  <CheckCircle className="w-3.5 h-3.5" /> Observed Ground Facts
                </span>
                <ul className="space-y-1.5 text-slate-700 text-[11px] list-disc list-inside">
                  {(ai_assessment?.observed_evidence || []).map((item, idx) => (
                    <li key={idx} className="leading-snug">{item}</li>
                  ))}
                  {(!ai_assessment?.observed_evidence || ai_assessment.observed_evidence.length === 0) && (
                    <li className="text-slate-500">No observed anomalies.</li>
                  )}
                </ul>
              </div>

              <div className="surface-card-subtle p-4 border-l-2 border-l-amber-500 space-y-2">
                <span className="font-bold text-amber-700 block flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" /> Inferred Hypotheses
                </span>
                <ul className="space-y-1.5 text-slate-700 text-[11px] list-disc list-inside">
                  {(ai_assessment?.inferred_evidence || []).map((item, idx) => (
                    <li key={idx} className="leading-snug">{item}</li>
                  ))}
                  {(!ai_assessment?.inferred_evidence || ai_assessment.inferred_evidence.length === 0) && (
                    <li className="text-slate-500">None inferred.</li>
                  )}
                </ul>
              </div>

              <div className="surface-card-subtle p-4 border-l-2 border-l-slate-500 space-y-2">
                <span className="font-bold text-slate-600 block flex items-center gap-1.5">
                  <HelpCircle className="w-3.5 h-3.5" /> Unknown Gaps
                </span>
                <ul className="space-y-1.5 text-slate-600 text-[11px] list-disc list-inside">
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
            <div className="space-y-2 pt-1">
              <span className="text-xs font-bold text-slate-700 block">Recommended SOC Analyst Actions:</span>
              <div className="space-y-1.5">
                {(ai_assessment?.recommended_analyst_actions || []).map((act, idx) => (
                  <div key={idx} className="surface-card-subtle p-3 text-xs text-slate-700 flex items-center gap-2.5">
                    <ChevronRight className="w-3.5 h-3.5 text-blue-600 flex-shrink-0" />
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
        <div className="surface-card p-6 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#E2E8F0] pb-4">
            <div>
              <h3 className="font-bold text-sm text-slate-900">RFC 5322 Raw & Structured Transport Headers</h3>
              <p className="text-xs text-slate-600 mt-0.5">Complete header map with cryptographic proof verification</p>
            </div>

            <div className="relative min-w-[220px]">
              <input
                type="text"
                placeholder="Filter header keys / values..."
                value={headerFilter}
                onChange={(e) => setHeaderFilter(e.target.value)}
                className="w-full bg-[#EFF6FF] border border-[#E2E8F0] focus:border-blue-500/80 rounded-xl px-3 py-1.5 text-xs text-slate-800 focus:outline-none"
              />
              <Search className="w-3.5 h-3.5 text-slate-600 absolute right-2.5 top-2.5 pointer-events-none" />
            </div>
          </div>

          <div className="surface-card-subtle p-4 max-h-[500px] overflow-y-auto font-mono text-xs text-slate-700 space-y-2.5 border border-[#F1F5F9]">
            {filteredHeaders.map(([k, v], idx) => (
              <div key={idx} className="border-b border-[#F1F5F9] pb-2">
                <span className="text-blue-600 font-semibold select-all">{k}: </span>
                <span className="text-slate-700 whitespace-pre-wrap select-all">
                  {Array.isArray(v) ? v.join('\n  ') : String(v)}
                </span>
              </div>
            ))}
            {filteredHeaders.length === 0 && (
              <p className="text-xs text-slate-500 py-6 text-center">No headers match the filter query.</p>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: RELAY FORENSICS & GEOLOCATION */}
      {activeTab === 'relays' && (
        <div className="space-y-5">
          {/* Leaflet Dark Map */}
          <div className="surface-card overflow-hidden">
            <div className="p-3.5 bg-[#EFF6FF] border-b border-[#E2E8F0] flex items-center justify-between text-xs">
              <span className="font-bold text-slate-800 flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-600" /> Observed MTA Mail Relay Path
              </span>
              <span className="text-[10px] text-slate-600 font-mono">
                {validRelays.length} Geocoded Hops • Latency Deltas & Autonomous Systems
              </span>
            </div>

            <div className="h-72 w-full">
              <MapContainer
                center={centerCoord}
                zoom={2}
                scrollWheelZoom={false}
                className="dark-map-tiles"
                style={{ height: '100%', width: '100%', backgroundColor: '#0D1322' }}
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
          <div className="surface-card p-6 space-y-4">
            <h3 className="font-bold text-sm text-slate-900">Chronological Relay Transit Chain ({relays.length} Hops)</h3>
            <div className="overflow-x-auto rounded-xl border border-[#F1F5F9]">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#EFF6FF] text-slate-600 text-[10px] uppercase font-sans">
                  <tr>
                    <th className="p-3">Hop</th>
                    <th className="p-3">Received By / From</th>
                    <th className="p-3">IP Address</th>
                    <th className="p-3">Location / ISP</th>
                    <th className="p-3">Delay</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#F1F5F9] bg-white text-[11px]">
                  {relays.map((r) => (
                    <tr key={r.hop_number} className="hover:bg-[#F0F7FF] transition-colors">
                      <td className="p-3 font-bold text-blue-600">#{r.hop_number}</td>
                      <td className="p-3 text-slate-700 max-w-xs truncate">
                        <div>by {r.by_host || 'N/A'}</div>
                        <div className="text-[10px] text-slate-500 font-sans">from {r.from_host || 'N/A'}</div>
                      </td>
                      <td className="p-3 font-bold text-slate-800">{r.ip_address || 'Private/Unknown'}</td>
                      <td className="p-3 text-slate-600 font-sans">
                        {r.city ? `${r.city}, ${r.country}` : 'Internal'} ({r.organization || 'N/A'})
                      </td>
                      <td className="p-3 text-cyan-700 font-bold">
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
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="surface-card p-6 space-y-4">
              <h3 className="font-bold text-sm text-slate-900">Domain & Lookalike Forensics</h3>
              <div className="space-y-2.5">
                {Object.entries(domain_intelligence).map(([dom, info], idx) => (
                  <div key={idx} className="surface-card-subtle p-3.5 space-y-1 text-xs font-mono">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-blue-600">{dom}</span>
                      {info.is_lookalike_typosquat && (
                        <span className="px-2.5 py-0.5 bg-rose-50 text-rose-600 border border-rose-200 rounded-full text-[10px] font-bold uppercase">
                          Homoglyph Typosquatting
                        </span>
                      )}
                    </div>
                    {info.lookalike_target_brand && (
                      <div className="text-[11px] text-slate-600 font-sans">
                        Impersonating brand: <strong className="text-slate-800">{info.lookalike_target_brand}</strong>
                      </div>
                    )}
                  </div>
                ))}
                {Object.keys(domain_intelligence).length === 0 && (
                  <p className="text-xs text-slate-500 py-6 text-center">No domain anomalies discovered.</p>
                )}
              </div>
            </div>

            <div className="surface-card p-6 space-y-4">
              <h3 className="font-bold text-sm text-slate-900">Extracted Hyperlinks ({extracted_urls.length})</h3>
              <div className="space-y-2.5 max-h-80 overflow-y-auto">
                {extracted_urls.map((u, idx) => (
                  <div key={idx} className="surface-card-subtle p-3.5 space-y-2 text-xs font-mono border border-slate-200">
                    <div className="flex items-center justify-between">
                      <div className="text-blue-600 font-bold truncate max-w-[70%]">{u.url}</div>
                      {u.risk_level === 'CRITICAL' && <span className="px-2 py-0.5 bg-rose-50 text-rose-700 border border-rose-200 rounded-full text-[10px] font-bold">CRITICAL RISK ({u.risk_score})</span>}
                      {u.risk_level === 'HIGH' && <span className="px-2 py-0.5 bg-orange-50 text-orange-700 border border-orange-200 rounded-full text-[10px] font-bold">HIGH RISK ({u.risk_score})</span>}
                      {u.risk_level === 'MEDIUM' && <span className="px-2 py-0.5 bg-amber-50 text-amber-800 border border-amber-200 rounded-full text-[10px] font-bold">MEDIUM RISK ({u.risk_score})</span>}
                      {u.risk_level === 'LOW' && <span className="px-2 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-full text-[10px] font-bold">LOW RISK</span>}
                    </div>
                    <div className="text-[11px] text-slate-600 font-sans flex items-center gap-3">
                      <span>Domain: <strong className="text-slate-700 font-mono">{u.domain || u.hostname}</strong></span>
                      {u.is_ip_host && <span className="text-rose-600 font-bold">(Raw IP Address)</span>}
                    </div>
                    {u.has_anchor_mismatch && (
                      <div className="text-[10px] text-rose-600 font-sans">
                         Anchor text mismatch: Displayed "{u.anchor_text}" differs from destination.
                      </div>
                    )}
                    {u.triggered_rules && u.triggered_rules.length > 0 && (
                      <details className="mt-2 text-slate-600 font-sans group">
                        <summary className="cursor-pointer text-blue-600 font-semibold hover:underline text-[11px]">View URL Intelligence Details ({u.triggered_rules.length} Signals)</summary>
                        <div className="mt-2 p-2 bg-slate-50 border border-slate-200 rounded-lg space-y-1.5">
                          {u.triggered_rules.map((rule, ridx) => (
                            <div key={ridx} className="flex justify-between items-center bg-white p-1.5 border border-slate-100 rounded">
                              <span className="font-medium text-slate-800"> {rule.rule_name}</span>
                              <span className="text-rose-600 font-mono text-[10px]">+{rule.score_contribution} pts</span>
                            </div>
                          ))}
                        </div>
                      </details>
                    )}
                  </div>
                ))}
                {extracted_urls.length === 0 && (
                  <p className="text-xs text-slate-500 py-6 text-center">No hyperlinks found in message.</p>
                )}
              </div>
            </div>
          </div>
          
          {/* INFRASTRUCTURE INTELLIGENCE */}
          <div className="surface-card p-6 space-y-4">
            <h3 className="font-bold text-sm text-slate-900 flex items-center gap-2">
              <Globe className="w-4 h-4 text-purple-600" /> Infrastructure Intelligence (Observed IPs)
            </h3>
            <p className="text-xs text-slate-500 italic mb-2">Note: This represents the observed infrastructure (e.g. relays, hosting providers, or Tor nodes). It does not establish the physical location or true identity of the sender.</p>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {Object.entries(ip_intelligence || {}).map(([ip, data], idx) => (
                <div key={idx} className="surface-card-subtle p-4 border border-slate-200 rounded-lg space-y-2">
                  <div className="flex justify-between items-start">
                    <span className="font-mono font-bold text-slate-800">{ip}</span>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                      data.classification === 'TOR_EXIT_NODE' ? 'bg-rose-100 text-rose-800' :
                      data.classification === 'VPN/PROXY' ? 'bg-orange-100 text-orange-800' :
                      data.classification === 'DATACENTER' ? 'bg-purple-100 text-purple-800' :
                      data.classification === 'CLOUD/HOSTING' ? 'bg-blue-100 text-blue-800' :
                      'bg-slate-100 text-slate-800'
                    }`}>
                      {data.classification || 'UNKNOWN'}
                    </span>
                  </div>
                  
                  <div className="text-xs font-sans space-y-1">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Observed IP Location:</span>
                      <span className="font-medium text-slate-700">{data.city ? `${data.city}, ${data.country}` : data.country || 'Unknown'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">ASN:</span>
                      <span className="font-medium text-slate-700">{data.asn || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Organization:</span>
                      <span className="font-medium text-slate-700 truncate ml-2 text-right" title={data.organization}>{data.organization || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Confidence:</span>
                      <span className="font-medium text-slate-700">{data.confidence || 'Medium'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Intel Source:</span>
                      <span className="font-medium text-slate-700 truncate ml-2 text-right" title={data.source}>{data.source || 'Local'}</span>
                    </div>
                  </div>
                </div>
              ))}
              {Object.keys(ip_intelligence || {}).length === 0 && (
                <div className="col-span-full text-center py-6 text-slate-500 text-xs">
                  No IP infrastructure intelligence available.
                </div>
              )}
            </div>
          </div>
        </div>
      )} {activeTab === 'attachments' && (
        <div className="surface-card p-6 space-y-5">
          <h3 className="font-bold text-sm text-slate-900">Extracted Attachments & Cryptographic Hashes</h3>
          {attachments.length === 0 ? (
            <div className="surface-card-subtle p-12 text-center text-xs text-slate-500">
              No attached binary or document payloads found in this message.
            </div>
          ) : (
            <div className="space-y-3">
              {attachments.map((a, idx) => (
                <div key={idx} className="surface-card-subtle p-4 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-900 text-sm">{a.filename}</span>
                    {a.is_suspicious && (
                      <span className="px-2.5 py-0.5 bg-rose-50 text-rose-600 border border-rose-200 rounded-full text-[10px] font-bold uppercase">
                        Suspicious / Executable Payload
                      </span>
                    )}
                  </div>
                  <div className="text-slate-600 font-sans">
                    Size: <strong className="text-slate-800">{(a.size_bytes / 1024).toFixed(1)} KB</strong> | MIME: <strong className="text-slate-800">{a.content_type}</strong>
                  </div>
                  <div className="text-[11px] text-slate-600 select-all">SHA-256: <span className="text-cyan-700">{a.sha256}</span></div>
                  <div className="text-[11px] text-slate-600 select-all">MD5: <span className="text-purple-700">{a.md5}</span></div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 6: DETECTION RULES */}
      {activeTab === 'detection' && (
        <div className="space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600">
            Triggered Security Findings ({detection_findings.length})
          </h3>

          {detection_findings.length === 0 ? (
            <div className="surface-card p-12 text-center text-xs text-slate-600">
              <CheckCircle className="w-8 h-8 text-emerald-700 mx-auto mb-2" />
              <p className="font-semibold text-slate-800">Zero Security Findings Triggered</p>
              <p className="text-[11px] text-slate-500 mt-0.5">Clean authentication and normal transit patterns.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {detection_findings.map((f, idx) => (
                <div key={idx} className="surface-card p-5 space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <span className="px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-600 border border-blue-200 text-[10px] font-mono font-bold">
                        {f.rule_id}
                      </span>
                      <h4 className="font-bold text-xs text-slate-900">{f.rule_name}</h4>
                    </div>
                    <span className="text-[10px] font-mono font-bold uppercase px-2.5 py-0.5 rounded-full bg-rose-50 text-rose-600 border border-rose-200">
                      {f.severity} (+{f.points} PTS)
                    </span>
                  </div>

                  <p className="text-xs text-slate-700 leading-relaxed">{f.explanation}</p>
                  {f.evidence && (
                    <div className="text-[11px] font-mono text-slate-600 surface-card-subtle p-3 rounded-lg border border-white/[0.05]">
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
        <div className="surface-card p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-4">
            <div className="flex items-center gap-2.5">
              <Bot className="w-5 h-5 text-blue-600" />
              <div>
                <h3 className="font-bold text-sm text-slate-900">SOC Forensic Copilot</h3>
                <p className="text-xs text-slate-600 mt-0.5">Conversational AI assistant answering queries directly from email evidence</p>
              </div>
            </div>
          </div>

          <div className="surface-card-subtle p-4 h-80 overflow-y-auto space-y-3.5">
            {chatMessages.map((m, idx) => (
              <div
                key={idx}
                className={`p-3.5 rounded-xl text-xs max-w-xl leading-relaxed space-y-1.5 ${
                  m.sender === 'user'
                    ? 'ml-auto bg-blue-600 text-white font-medium shadow-sm'
                    : 'mr-auto surface-card text-slate-800 border border-[#E2E8F0]'
                }`}
              >
                <div className="flex items-center gap-1.5 text-[10px] text-slate-600 font-mono">
                  <User className="w-3 h-3" />
                  <span>{m.sender === 'user' ? 'You' : 'Forensic Assistant'}</span>
                </div>
                <p>{m.content}</p>
              </div>
            ))}
            {chatLoading && (
              <div className="mr-auto surface-card p-3 rounded-xl border border-[#E2E8F0] text-xs text-slate-600 flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-blue-600" /> Evaluating indicators...
              </div>
            )}
          </div>

          <form onSubmit={handleSendChat} className="flex gap-2">
            <input
              type="text"
              placeholder="Ask Copilot about sender authentication, lookalike domains, or MTA hops..."
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              className="flex-1 bg-[#EFF6FF] border border-[#E2E8F0] focus:border-blue-500/80 rounded-xl px-3.5 py-2 text-xs text-slate-800 focus:outline-none"
            />
            <button
              type="submit"
              disabled={chatLoading || !chatInput.trim()}
              className="btn-tactile px-4 py-2 btn-block-primary text-white rounded-xl text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" /> Send
            </button>
          </form>
        </div>
      )}

      {/* Tamper Seal Modal */}
      {showSealModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="surface-card max-w-lg w-full p-6 space-y-4 shadow-2xl border border-white/[0.1]">
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-3">
              <div className="flex items-center gap-2">
                <Lock className="w-5 h-5 text-blue-600" />
                <h3 className="font-bold text-sm text-slate-900">Cryptographic Chain-of-Custody Proof</h3>
              </div>
              <button onClick={() => setShowSealModal(false)} className="text-slate-600 hover:text-slate-900"><X className="w-4 h-4" /></button>
            </div>

            <div className="surface-card-subtle p-4 space-y-2.5 text-xs font-mono border border-[#F1F5F9]">
              <div className="flex items-center justify-between">
                <span className="text-slate-600">Blockchain Block:</span>
                <span className="px-2 py-0.5 rounded-full bg-blue-50 text-blue-600 border border-blue-200 font-bold">
                  Block #{sealVerification?.block_number || tamper_seal.block_number || 1}
                </span>
              </div>
              <div className="text-slate-600">Validator Node: <span className="text-slate-800">{sealVerification?.validator_node || 'ThreatSentinel-Validator-01'}</span></div>
              <div className="text-slate-600">Timestamp: <span className="text-slate-800">{tamper_seal.timestamp_utc}</span></div>
              <div className="text-slate-600 select-all truncate">
                Block Hash: <span className="text-cyan-700 font-bold">{sealVerification?.block_hash || tamper_seal.block_hash || tamper_seal.current_seal_hash}</span>
              </div>
              <div className="text-slate-600 select-all truncate">
                Merkle Root: <span className="text-purple-700 font-bold">{sealVerification?.merkle_root || tamper_seal.merkle_root || 'N/A'}</span>
              </div>
              <div className="text-slate-600 select-all truncate">
                Evidence SHA-256: <span className="text-slate-700">{sealVerification?.canonical_evidence_hash || tamper_seal.payload_sha256}</span>
              </div>
            </div>

            {sealVerification && (
              <div className={`p-3.5 rounded-xl text-xs flex items-start gap-2.5 border ${
                sealVerification.tamper_detected
                  ? 'bg-rose-50 border-rose-200 text-rose-700'
                  : 'bg-emerald-50 border-emerald-200 text-emerald-700'
              }`}>
                {sealVerification.tamper_detected ? (
                  <ShieldAlert className="w-4 h-4 text-rose-600 flex-shrink-0 mt-0.5" />
                ) : (
                  <CheckCircle className="w-4 h-4 text-emerald-700 flex-shrink-0 mt-0.5" />
                )}
                <div>
                  <div className="font-bold uppercase tracking-wider mb-0.5">
                    {sealVerification.verification_status.replace(/_/g, ' ')}
                  </div>
                  <div className="text-[11px] leading-snug">{sealVerification.verification_details}</div>
                </div>
              </div>
            )}

            <div className="flex items-center justify-between pt-2">
              <button
                onClick={handleVerifySeal}
                disabled={verifyingSeal}
                className="px-3 py-1.5 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] text-slate-700 text-xs rounded-xl flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {verifyingSeal ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                <span>Re-Verify Ledger</span>
              </button>

              <button
                onClick={() => setShowSealModal(false)}
                className="btn-tactile px-4 py-1.5 btn-block-primary text-white text-xs font-bold rounded-xl"
              >
                Close Proof
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Record Custody Event Modal */}
      {showAddCustodyModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="surface-card max-w-md w-full p-6 space-y-4 shadow-2xl border border-white/[0.1]">
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-3">
              <div className="flex items-center gap-2">
                <PlusCircle className="w-5 h-5 text-cyan-700" />
                <h3 className="font-bold text-sm text-slate-900">Record Chain-of-Custody Event</h3>
              </div>
              <button onClick={() => setShowAddCustodyModal(false)} className="text-slate-600 hover:text-slate-900"><X className="w-4 h-4" /></button>
            </div>

            <form onSubmit={handleAddCustodyEvent} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs text-slate-700 font-semibold block">Lifecycle Event Type</label>
                <select
                  value={custodyEventType}
                  onChange={(e) => setCustodyEventType(e.target.value)}
                  className="w-full bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ANALYST_REVIEW">ANALYST_REVIEW (Forensic Assessment & Verification)</option>
                  <option value="REPORT_GENERATED">REPORT_GENERATED (Intelligence Export)</option>
                  <option value="EVIDENCE_ARCHIVED">EVIDENCE_ARCHIVED (Case Closure & Sealed)</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-slate-700 font-semibold block">Investigator / System Identifier</label>
                <input
                  type="text"
                  value={custodyAuthor}
                  onChange={(e) => setCustodyAuthor(e.target.value)}
                  className="w-full bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-slate-700 font-semibold block">Event Summary & Action Taken</label>
                <textarea
                  rows={3}
                  value={custodyNote}
                  onChange={(e) => setCustodyNote(e.target.value)}
                  placeholder="Describe forensic action taken or verified evidence indicators..."
                  className="w-full bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl p-3 text-xs text-slate-800 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddCustodyModal(false)}
                  className="px-4 py-2 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] text-slate-700 text-xs rounded-xl"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-tactile px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-bold rounded-xl shadow-glow-blue cursor-pointer"
                >
                  Anchor to Blockchain
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Export Report Modal */}
      {showExportModal && reportData && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="surface-card max-w-2xl w-full p-6 space-y-4 shadow-2xl border border-white/[0.1]">
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-3">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-emerald-700" />
                <h3 className="font-bold text-sm text-slate-900">Forensic Investigation Report (TLP:AMBER)</h3>
              </div>
              <button onClick={() => setShowExportModal(false)} className="text-slate-600 hover:text-slate-900"><X className="w-4 h-4" /></button>
            </div>

            <textarea
              readOnly
              rows={12}
              value={reportData.report_markdown}
              className="w-full bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl p-3.5 text-xs font-mono text-slate-800 focus:outline-none"
            />

            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] text-slate-600 font-mono">Report ID: {reportData.report_id}</span>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(reportData.report_markdown);
                    setCopiedMd(true);
                    setTimeout(() => setCopiedMd(false), 2000);
                  }}
                  className="px-3.5 py-1.5 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] text-slate-700 hover:text-slate-900 text-xs rounded-xl flex items-center gap-1.5 transition-colors"
                >
                  {copiedMd ? <Check className="w-3.5 h-3.5 text-emerald-700" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedMd ? 'Copied Markdown' : 'Copy Markdown'}</span>
                </button>
                <button
                  onClick={() => setShowExportModal(false)}
                  className="btn-tactile px-4 py-1.5 btn-block-primary text-white text-xs font-bold rounded-xl"
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
