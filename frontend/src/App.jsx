import React, { useState } from 'react';
import {
  Shield, UploadCloud, Play, RotateCcw, Loader2,
  AlertCircle, Briefcase, Search, LayoutDashboard,
  FileSearch, Plus, Network, Sparkles, RefreshCw, CheckCircle2
} from 'lucide-react';

import api, { useScanner } from './api';
import AnalysisWorkspace from './components/AnalysisWorkspace';
import {
  DashboardView,
  CorrelationView,
  CaseManager,
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
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      {/* Top Header Navbar */}
      <header className="border-b border-[#1E293B] bg-[#131B2A]/90 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-tr from-blue-600 via-indigo-600 to-cyan-500 rounded-xl shadow-lg shadow-blue-500/20 text-white flex items-center justify-center">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-extrabold text-base tracking-tight text-white flex items-center gap-1.5">
                  ThreatSentinel
                </h1>
                <span className="px-2 py-0.5 text-[9px] font-extrabold bg-blue-500/20 text-blue-300 border border-blue-500/30 rounded uppercase tracking-wider">
                  SOC Edition
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-medium">AI-Powered Email Threat Detection & Forensic Intelligence</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <nav className="hidden md:flex items-center gap-1 bg-[#0B0F17] p-1 rounded-xl border border-[#1E293B]">
              <button
                onClick={() => setCurrentView('dashboard')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  currentView === 'dashboard'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#1E293B]/50'
                }`}
              >
                <LayoutDashboard className="w-3.5 h-3.5" /> Dashboard
              </button>

              <button
                onClick={() => {
                  if (analysis) setCurrentView('workspace');
                  else setIsIntakeOpen(true);
                }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  currentView === 'workspace'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#1E293B]/50'
                }`}
              >
                <FileSearch className="w-3.5 h-3.5" /> Analysis Workspace
              </button>

              <button
                onClick={() => setCurrentView('correlation')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  currentView === 'correlation'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#1E293B]/50'
                }`}
              >
                <Network className="w-3.5 h-3.5" /> Correlation
              </button>

              <button
                onClick={() => setCurrentView('cases')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  currentView === 'cases'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#1E293B]/50'
                }`}
              >
                <Briefcase className="w-3.5 h-3.5" /> Incident Cases
              </button>
            </nav>

            <button
              onClick={() => setIsSearchOpen(true)}
              className="p-2 bg-[#0B0F17] hover:bg-[#1E293B] border border-[#1E293B] rounded-xl text-slate-400 hover:text-white transition-colors cursor-pointer"
              title="Global Search (Ctrl+K)"
            >
              <Search className="w-4 h-4" />
            </button>

            <button
              onClick={() => setIsTourOpen(true)}
              className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 bg-purple-950/40 hover:bg-purple-900/50 text-purple-300 border border-purple-500/30 rounded-xl text-xs font-semibold transition-all cursor-pointer shadow-sm"
            >
              <Sparkles className="w-3.5 h-3.5 text-purple-400" /> Demo Tour
            </button>

            <button
              onClick={() => setIsIntakeOpen(true)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white rounded-xl text-xs font-bold transition-all shadow-md shadow-blue-600/20 cursor-pointer"
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
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#131B2A] border border-[#1E293B] rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl animate-in fade-in duration-200">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <div>
                <h3 className="font-bold text-slate-100 text-sm">Ingest Email for Forensic Threat Evaluation</h3>
                <p className="text-xs text-slate-400">
                  Submit RFC 5322 raw email text, upload an .eml artifact, or choose from synthetic test fixtures
                </p>
              </div>
              <button
                onClick={() => setIsIntakeOpen(false)}
                className="p-1 text-slate-400 hover:text-white rounded-lg"
              >
                ✕
              </button>
            </div>

            {error && (
              <div className="p-3 bg-red-500/15 border border-red-500/30 rounded-xl text-xs text-red-300 flex items-center gap-2 animate-in fade-in">
                <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
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
            <div className="flex bg-[#0B0F17] p-1 rounded-xl border border-[#1E293B] text-xs font-semibold">
              <button
                onClick={() => setIntakeMode('paste')}
                className={`flex-1 py-1.5 rounded-lg transition-all cursor-pointer ${
                  intakeMode === 'paste' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Paste Raw RFC 5322
              </button>
              <button
                onClick={() => setIntakeMode('upload')}
                className={`flex-1 py-1.5 rounded-lg transition-all cursor-pointer ${
                  intakeMode === 'upload' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Upload .EML File
              </button>
              <button
                onClick={() => setIntakeMode('fields')}
                className={`flex-1 py-1.5 rounded-lg transition-all cursor-pointer ${
                  intakeMode === 'fields' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Structured Input
              </button>
            </div>

            {/* Mode Inputs */}
            {intakeMode === 'paste' && (
              <textarea
                rows={8}
                placeholder="Paste raw email (Received headers, From, To, Subject, Body)..."
                value={rawPastedEmail}
                onChange={(e) => setRawPastedEmail(e.target.value)}
                className="w-full bg-[#0B0F17] border border-[#1E293B] rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-blue-500"
              />
            )}

            {intakeMode === 'upload' && (
              <div className="border-2 border-dashed border-[#1E293B] hover:border-blue-500/50 rounded-xl p-8 text-center space-y-3 bg-[#0B0F17]">
                <UploadCloud className="w-8 h-8 text-blue-400 mx-auto" />
                <div>
                  <label className="text-xs font-bold text-slate-200 block cursor-pointer">
                    Click to select .eml or .txt message file
                    <input
                      type="file"
                      accept=".eml,message/rfc822,text/plain"
                      className="hidden"
                      onChange={(e) => setUploadedFile(e.target.files?.[0] || null)}
                    />
                  </label>
                  <span className="text-[11px] text-slate-400 font-mono">
                    {uploadedFile ? uploadedFile.name : 'Max file size: 15 MB'}
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
                  className="col-span-2 bg-[#0B0F17] border border-[#1E293B] rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                />
                <input
                  type="text"
                  placeholder="From (e.g. security@company.com)"
                  value={formSender}
                  onChange={(e) => setFormSender(e.target.value)}
                  className="bg-[#0B0F17] border border-[#1E293B] rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                />
                <input
                  type="text"
                  placeholder="To (e.g. user@domain.com)"
                  value={formRecipient}
                  onChange={(e) => setFormRecipient(e.target.value)}
                  className="bg-[#0B0F17] border border-[#1E293B] rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                />
                <textarea
                  rows={3}
                  placeholder="Raw Transport Headers (optional)..."
                  value={formHeaders}
                  onChange={(e) => setFormHeaders(e.target.value)}
                  className="col-span-2 bg-[#0B0F17] border border-[#1E293B] rounded-lg p-2.5 font-mono text-slate-200 focus:outline-none focus:border-blue-500"
                />
                <textarea
                  rows={3}
                  placeholder="Email Plain Body Text..."
                  value={formBody}
                  onChange={(e) => setFormBody(e.target.value)}
                  className="col-span-2 bg-[#0B0F17] border border-[#1E293B] rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-blue-500"
                />
              </div>
            )}

            <div className="flex items-center justify-between pt-2 border-t border-[#1E293B]">
              <button
                type="button"
                onClick={() => setIsIntakeOpen(false)}
                className="px-4 py-2 bg-[#0B0F17] text-slate-400 hover:text-slate-200 text-xs rounded-xl"
              >
                Cancel
              </button>

              <button
                onClick={handleAnalyzeEmail}
                disabled={loading}
                className="flex items-center gap-2 px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold transition-all shadow-md shadow-blue-600/20 disabled:opacity-50 cursor-pointer"
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
          <div className="bg-emerald-500/15 border border-emerald-500/30 rounded-xl p-3 flex items-center justify-between text-xs text-emerald-300 animate-in fade-in duration-200">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
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
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1E293B] bg-[#0B0F17] py-4 text-center text-xs text-slate-500 mt-auto">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>ThreatSentinel • Smart India Hackathon 2026 (PS 26106)</span>
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
