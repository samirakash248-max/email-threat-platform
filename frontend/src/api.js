import { useState, useEffect, useCallback } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE || '/api';

// Helper for standard JSON requests
async function fetchJson(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const headers = options.headers || {};
  
  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const res = await fetch(url, { ...options, headers });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || data.message || `Request failed (${res.status})`);
  }
  return data;
}

export const api = {
  // Email analysis
  scanRaw: (payload) => fetchJson('/analyze-email', { method: 'POST', body: JSON.stringify(payload) }),
  scanFile: (file) => {
    const fd = new FormData();
    fd.append('file', file);
    return fetchJson('/analyze-file', { method: 'POST', body: fd });
  },
  getScan: (id) => fetchJson(`/analysis/${id}`),
  deleteScan: (id) => fetchJson(`/analysis/${id}`, { method: 'DELETE' }),
  getReport: (id) => fetchJson(`/analysis/${id}/report`),
  verifySeal: (id) => fetchJson(`/analysis/${id}/verify-seal`),
  chat: (id, question) => fetchJson(`/analysis/${id}/chat`, { method: 'POST', body: JSON.stringify({ question }) }),

  // Telemetry & stats
  getStats: () => fetchJson('/dashboard/stats'),
  getCorrelation: () => fetchJson('/correlation/graph'),
  search: (q) => fetchJson(`/search?q=${encodeURIComponent(q)}`),

  // Cases
  getCases: () => fetchJson('/cases'),
  getCase: (id) => fetchJson(`/cases/${id}`),
  createCase: (data) => fetchJson('/cases', { method: 'POST', body: JSON.stringify(data) }),
  updateCase: (id, data) => fetchJson(`/cases/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  addNote: (id, data) => fetchJson(`/cases/${id}/notes`, { method: 'POST', body: JSON.stringify(data) }),

  // Demo samples
  getSamples: () => fetchJson('/sample-emails'),
  getSample: (id) => fetchJson(`/sample-emails/${id}`),
  seedDemo: () => fetchJson('/demo/seed', { method: 'POST' }),
  resetDemo: () => fetchJson('/demo/reset', { method: 'POST' }),
};

export default api;

// React Hook for scanning emails
export function useScanner() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const scanText = async (text) => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.scanRaw({ raw_email: text });
      setResult(res);
      return res;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const scanUpload = async (file) => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.scanFile(file);
      setResult(res);
      return res;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const scanFields = async (fields) => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.scanRaw(fields);
      setResult(res);
      return res;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const loadScan = async (id) => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getScan(id);
      setResult(res);
      return res;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  return {
    result,
    setResult,
    loading,
    error,
    setError,
    scanText,
    scanUpload,
    scanFields,
    loadScan,
  };
}

// React Hook for cases
export function useCases() {
  const [cases, setCases] = useState([]);
  const [activeCase, setActiveCase] = useState(null);
  const [loading, setLoading] = useState(false);

  const reloadCases = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getCases();
      setCases(data);
    } catch (err) {
      console.error("Failed to load cases:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  const selectCase = async (id) => {
    try {
      const data = await api.getCase(id);
      setActiveCase(data);
    } catch (err) {
      console.error("Failed to load case details:", err);
    }
  };

  useEffect(() => {
    reloadCases();
  }, [reloadCases]);

  return {
    cases,
    activeCase,
    setActiveCase,
    loading,
    reloadCases,
    selectCase,
  };
}
