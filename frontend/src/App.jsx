import React, { useState, useEffect } from 'react';
import {
  Shield, UploadCloud, Play, RotateCcw, Loader2,
  AlertCircle, Briefcase, Search, LayoutDashboard,
  FileSearch, Plus, Network, Sparkles, RefreshCw, CheckCircle2,
  X, HelpCircle, Activity, Command, Layers, Globe
} from 'lucide-react';

import api, { useScanner } from './api';
import AnalysisWorkspace from './components/AnalysisWorkspace';
import {
  DashboardView,
  CorrelationView,
  CaseManager,
  BlockchainLedgerView,
  ThreatIntelView,
  GlobalSearchModal,
  DemoTourModal,
  SampleEmailSelector
} from './components/Views';

export default function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isTourOpen, setIsTourOpen] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [resetFeedback, setResetFeedback] = useState(null);

  const {
    result: analysis,
    loading,
    error,
    setError,
    scanText,
    scanUpload,
    scanFields,
    loadScan
  } = useScanner();

  // Intake Drawer / Modal State
  const [isIntakeOpen, setIsIntakeOpen] = useState(false);
  const [intakeMode, setIntakeMode] = useState('paste'); // 'paste', 'upload', 'fields'
  const [rawPastedEmail, setRawPastedEmail] = useState('');
  const [uploadedFile, setUploadedFile] = useState(null);

  // Structured fields
  const [formSubject, setFormSubject] = useState('');
  const [formSender, setFormSender] = useState('');
  const [formRecipient, setFormRecipient] = useState('');
  const [formHeaders, setFormHeaders] = useState('');
  const [formBody, setFormBody] = useState('');

  // Keyboard shortcut for search
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsSearchOpen(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleResetDemoData = async () => {
    if (!window.confirm('Reset SQLite database to original baseline state with 10 synthetic demo emails?')) {
      return;
    }
    setResetting(true);
    setResetFeedback(null);
    try {
      const data = await api.resetDemo();
      setResetFeedback(data.message || 'Database reset successfully.');
      setTimeout(() => setResetFeedback(null), 4000);
      if (currentView === 'workspace') {
        setCurrentView('dashboard');
      }
    } catch (err) {
      console.error('Reset error:', err);
      setError('Failed to reset database.');
    } finally {
      setResetting(false);
    }
  };

  const handleAnalyzeEmail = async () => {
    setError(null);
    try {
      let res;
      if (intakeMode === 'paste') {
        if (!rawPastedEmail.trim()) {
          setError('Please paste raw RFC 5322 email headers and body content.');
          return;
        }
        res = await scanText(rawPastedEmail);
      } else if (intakeMode === 'upload') {
        if (!uploadedFile) {
          setError('Please select an .eml or raw message file to upload.');
          return;
        }
        res = await scanUpload(uploadedFile);
      } else if (intakeMode === 'fields') {
        if (!formSender && !formSubject && !formBody && !formHeaders) {
          setError('Please provide at least a sender, subject, or headers.');
          return;
        }
        res = await scanFields({
          subject: formSubject,
          sender: formSender,
          recipient: formRecipient,
          headers: formHeaders,
          body: formBody
        });
      }

      setIsIntakeOpen(false);
      setCurrentView('workspace');
      setRawPastedEmail('');
      setUploadedFile(null);
    } catch (err) {
      console.error('Analysis failed:', err);
    }
  };

  const handleLaunchSampleScenario = async (sampleId) => {
    try {
      const sample = await api.getSample(sampleId);
      await scanText(sample.raw_content);
      setCurrentView('workspace');
    } catch (err) {
      console.error('Failed to launch scenario:', err);
    }
  };

  const handleSelectAnalysis = async (analysisId) => {
    try {
      await loadScan(analysisId);
      setCurrentView('workspace');
    } catch (err) {
      console.error('Failed to load analysis:', err);
    }
  };

  return (
    <div className="min-h-screen bg-[#F8FAFC] bg-ambient-mesh text-slate-900 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      {/* Top Header Navbar */}
      <header className="border-b border-blue-100 bg-white/95 backdrop-blur-xl sticky top-0 z-40 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative p-2 bg-blue-600 rounded-xl shadow-md shadow-blue-500/25 text-white flex items-center justify-center border border-blue-700">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-bold text-sm tracking-tight text-slate-900 flex items-center gap-1.5">
                  ThreatSentinel
                </h1>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-bold bg-blue-50 text-blue-700 border border-blue-200 rounded-full uppercase tracking-wider">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-600 animate-pulse"></span> SOC Console
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-normal">AI-Powered Email Threat Detection & Forensic Intelligence</p>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <nav className="hidden md:flex items-center gap-1 bg-blue-50/60 p-1 rounded-xl border border-blue-100">
              <button
                onClick={() => setCurrentView('dashboard')}
                className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  currentView === 'dashboard'
                    ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/25 font-bold'
                    : 'text-slate-600 hover:text-blue-600 hover:bg-white'
                }`}
              >
                <LayoutDashboard className="w-3.5 h-3.5" /> Dashboard
              </button>

              <button
                onClick={() => {
                  if (analysis) setCurrentView('workspace');
                  else setIsIntakeOpen(true);
                }}
                className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  currentView === 'workspace'
                    ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/25 font-bold'
                    : 'text-slate-600 hover:text-blue-600 hover:bg-white'
                }`}
              >
                <FileSearch className="w-3.5 h-3.5" /> Workspace
              </button>

              <button
                onClick={() => setCurrentView('correlation')}
                className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  currentView === 'correlation'
                    ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/25 font-bold'
                    : 'text-slate-600 hover:text-blue-600 hover:bg-white'
                }`}
              >
                <Network className="w-3.5 h-3.5" /> Correlation
              </button>

              <button
                onClick={() => setCurrentView('cases')}
                className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  currentView === 'cases'
                    ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/25 font-bold'
                    : 'text-slate-600 hover:text-blue-600 hover:bg-white'
                }`}
              >
                <Briefcase className="w-3.5 h-3.5" /> Cases
              </button>

              <button
                onClick={() => setCurrentView('blockchain')}
                className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  currentView === 'blockchain'
                    ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/25 font-bold'
                    : 'text-slate-600 hover:text-blue-600 hover:bg-white'
                }`}
              >
                <Layers className="w-3.5 h-3.5" /> Blockchain
              </button>

              <button
                onClick={() => setCurrentView('intel')}
                className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  currentView === 'intel'
                    ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/25 font-bold'
                    : 'text-slate-600 hover:text-blue-600 hover:bg-white'
                }`}
              >
                <Globe className="w-3.5 h-3.5" /> Threat Intel
              </button>
            </nav>

            <button
              onClick={() => setIsSearchOpen(true)}
              className="flex items-center gap-2 px-2.5 py-1.5 bg-white hover:bg-blue-50 border border-slate-200 rounded-xl text-slate-600 hover:text-blue-600 transition-colors text-xs cursor-pointer shadow-sm"
              title="Global Search"
            >
              <Search className="w-3.5 h-3.5" />
              <span className="hidden sm:inline text-[11px] text-slate-500">Search</span>
              <kbd className="hidden sm:inline px-1.5 py-0.5 text-[9px] font-mono bg-slate-100 border border-slate-200 rounded text-slate-600">⌘K</kbd>
            </button>

            <button
              onClick={() => setIsTourOpen(true)}
              className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 rounded-xl text-xs font-bold transition-all cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5 text-indigo-600" /> Tour
            </button>

            <button
              onClick={() => setIsIntakeOpen(true)}
              className="btn-tactile bg-blue-600 hover:bg-blue-700 text-white flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all shadow-md shadow-blue-500/25 cursor-pointer"
            >
              <Plus className="w-4 h-4" /> Ingest Email
            </button>
          </div>
        </div>
      </header>

      {/* Global Modals */}
      <GlobalSearchModal
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        onSelectResult={(id) => handleSelectAnalysis(id)}
      />

      <DemoTourModal
        isOpen={isTourOpen}
        onClose={() => setIsTourOpen(false)}
        onLaunchSample={handleLaunchSampleScenario}
      />

      {/* Intake Drawer / Modal */}
      {isIntakeOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="surface-card max-w-2xl w-full p-6 space-y-5 shadow-2xl animate-in fade-in zoom-in-95 duration-150 border border-white/[0.1]">
            <div className="flex items-center justify-between border-b border-white/[0.08] pb-3.5">
              <div>
                <h3 className="font-bold text-slate-100 text-sm">Ingest Email for Forensic Threat Evaluation</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Submit RFC 5322 raw email text, upload an .eml artifact, or choose from synthetic test fixtures
                </p>
              </div>
              <button
                onClick={() => setIsIntakeOpen(false)}
                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-white/[0.06] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {error && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs text-rose-300 flex items-center gap-2 animate-in fade-in">
                <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Preloaded Samples Dropdown */}
            <SampleEmailSelector
              disabled={loading}
              onSelectSample={(raw) => {
                setRawPastedEmail(raw);
                setIntakeMode('paste');
              }}
            />

            {/* Mode Switcher */}
            <div className="flex bg-slate-100 p-1 rounded-xl border border-slate-200 text-xs font-semibold">
              <button
                onClick={() => setIntakeMode('paste')}
                className={`flex-1 py-1.5 rounded-lg transition-all cursor-pointer ${
                  intakeMode === 'paste' ? 'bg-blue-600 text-white shadow-sm font-bold' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Paste Raw RFC 5322
              </button>
              <button
                onClick={() => setIntakeMode('upload')}
                className={`flex-1 py-1.5 rounded-lg transition-all cursor-pointer ${
                  intakeMode === 'upload' ? 'bg-blue-600 text-white shadow-sm font-bold' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Upload .EML File
              </button>
              <button
                onClick={() => setIntakeMode('fields')}
                className={`flex-1 py-1.5 rounded-lg transition-all cursor-pointer ${
                  intakeMode === 'fields' ? 'bg-blue-600 text-white shadow-sm font-bold' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Structured Form
              </button>
            </div>

            {/* Mode Inputs */}
            {intakeMode === 'paste' && (
              <textarea
                rows={8}
                placeholder="Paste raw email content (Received headers, From, To, Subject, Body)..."
                value={rawPastedEmail}
                onChange={(e) => setRawPastedEmail(e.target.value)}
                className="w-full bg-white border border-slate-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 rounded-xl p-3.5 text-xs font-mono text-slate-900 focus:outline-none transition-all"
              />
            )}

            {intakeMode === 'upload' && (
              <div className="border-2 border-dashed border-blue-200 hover:border-blue-500 rounded-xl p-8 text-center space-y-3 bg-blue-50/40 transition-colors">
                <UploadCloud className="w-9 h-9 text-blue-600 mx-auto" />
                <div>
                  <label className="text-xs font-bold text-slate-800 block cursor-pointer hover:text-blue-600 transition-colors">
                    Click to browse .eml or .txt message file
                    <input
                      type="file"
                      accept=".eml,message/rfc822,text/plain"
                      className="hidden"
                      onChange={(e) => setUploadedFile(e.target.files?.[0] || null)}
                    />
                  </label>
                  <span className="text-[11px] text-slate-500 font-mono mt-1 block">
                    {uploadedFile ? uploadedFile.name : 'Max upload size: 15 MB'}
                  </span>
                </div>
              </div>
            )}

            {intakeMode === 'fields' && (
              <div className="grid grid-cols-2 gap-3 text-xs">
                <input
                  type="text"
                  placeholder="Subject Line"
                  value={formSubject}
                  onChange={(e) => setFormSubject(e.target.value)}
                  className="col-span-2 bg-white border border-slate-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 rounded-lg p-2.5 text-slate-900 focus:outline-none"
                />
                <input
                  type="text"
                  placeholder="From (e.g. security@company.com)"
                  value={formSender}
                  onChange={(e) => setFormSender(e.target.value)}
                  className="bg-white border border-slate-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 rounded-lg p-2.5 text-slate-900 focus:outline-none"
                />
                <input
                  type="text"
                  placeholder="To (e.g. user@domain.com)"
                  value={formRecipient}
                  onChange={(e) => setFormRecipient(e.target.value)}
                  className="bg-white border border-slate-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 rounded-lg p-2.5 text-slate-900 focus:outline-none"
                />
                <textarea
                  rows={3}
                  placeholder="Raw Transport Headers (optional)..."
                  value={formHeaders}
                  onChange={(e) => setFormHeaders(e.target.value)}
                  className="col-span-2 bg-white border border-slate-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 rounded-lg p-2.5 font-mono text-slate-900 focus:outline-none"
                />
                <textarea
                  rows={3}
                  placeholder="Email Plain Body Text..."
                  value={formBody}
                  onChange={(e) => setFormBody(e.target.value)}
                  className="col-span-2 bg-white border border-slate-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 rounded-lg p-2.5 text-slate-900 focus:outline-none"
                />
              </div>
            )}

            <div className="flex items-center justify-between pt-3 border-t border-slate-200">
              <button
                type="button"
                onClick={() => setIsIntakeOpen(false)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 hover:text-slate-900 text-xs rounded-xl transition-colors font-medium cursor-pointer"
              >
                Cancel
              </button>

              <button
                onClick={handleAnalyzeEmail}
                disabled={loading}
                className="btn-tactile bg-blue-600 hover:bg-blue-700 text-white flex items-center gap-2 px-5 py-2 rounded-xl text-xs font-bold shadow-md shadow-blue-500/25 disabled:opacity-50 cursor-pointer"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" /> Evaluating Forensics...
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-white" /> Execute Threat Analysis
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reset Feedback Notification */}
      {resetFeedback && (
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-4 w-full">
          <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-3 flex items-center justify-between text-xs text-emerald-800 animate-in fade-in duration-200">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              <span>{resetFeedback}</span>
            </div>
          </div>
        </div>
      )}

      {/* Main App Body */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex-1 w-full">
        {currentView === 'dashboard' && (
          <DashboardView
            onSelectAnalysis={handleSelectAnalysis}
            onNewIntake={() => setIsIntakeOpen(true)}
            onOpenCase={() => setCurrentView('cases')}
          />
        )}

        {currentView === 'workspace' && (
          <AnalysisWorkspace
            analysis={analysis}
            onNewIntake={() => setIsIntakeOpen(true)}
          />
        )}

        {currentView === 'correlation' && (
          <CorrelationView
            onSelectAnalysis={handleSelectAnalysis}
          />
        )}

        {currentView === 'cases' && (
          <CaseManager
            currentAnalysis={analysis}
            onSelectAnalysisFromCase={(analysisId) => handleSelectAnalysis(analysisId)}
          />
        )}

        {currentView === 'blockchain' && (
          <BlockchainLedgerView
            onSelectAnalysis={handleSelectAnalysis}
          />
        )}

        {currentView === 'intel' && (
          <ThreatIntelView />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-4 text-xs text-slate-600 mt-auto">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>ThreatSentinel SOC Platform • Active Telemetry Ready</span>
          </div>
          <button
            onClick={handleResetDemoData}
            disabled={resetting}
            className="text-[11px] text-slate-500 hover:text-amber-400 transition-colors flex items-center gap-1 cursor-pointer"
          >
            <RotateCcw className="w-3 h-3" /> Reset Database Baseline
          </button>
        </div>
      </footer>
    </div>
  );
}
