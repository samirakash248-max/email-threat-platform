# ThreatSentinel — AI-Powered Email Threat Detection & Forensic Intelligence

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React_%2B_Vite_%2B_Tailwind-61DAFB.svg)](https://react.dev)
[![Leaflet](https://img.shields.io/badge/Maps-Leaflet_%2B_React--Leaflet-199900.svg)](https://leafletjs.com)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)]()

**ThreatSentinel** is a lightweight Security Operations Center (SOC) investigation platform for analyzing suspicious email headers, relay transit hops, phishing links, and malware indicators.

---

## 🏗️ Project Architecture

A clean, human-crafted codebase with clear modular boundaries:

```
email-threat-platform/
├── backend/
│   ├── app/
│   │   ├── models.py              # Pydantic schemas & SQLite database models
│   │   ├── scanner.py             # Forensic parser, relay trace & 12 heuristic rules
│   │   └── main.py                # FastAPI REST endpoints & SPA server
│   ├── tests/
│   │   └── test_scanner.py        # Automated test suite
│   ├── email_threat_platform.db   # SQLite database
│   └── requirements.txt           # Python dependencies
│
├── frontend/src/
│   ├── components/
│   │   ├── ThreatReport.jsx       # Investigation console, Leaflet map & Copilot
│   │   ├── Dashboard.jsx          # Telemetry stats & sample test fixtures
│   │   └── Cases.jsx              # Incident case tracker & analyst notes
│   ├── api.js                     # Simple API client & React state hooks
│   ├── App.jsx                    # Navigation shell & modal
│   └── main.jsx & index.css
│
├── samples/                       # 10 Test .eml email fixtures
└── run.bat                        # One-click Windows runner
```

---

## ⚡ Core Capabilities

1. **Header & Authentication Forensics**: Parses RFC 5322 headers, display name spoofing, and SPF / DKIM / DMARC verification.
2. **Relay Hop Reconstruction & Map**: Reverses Received headers to trace chronological MTA hops and hop latency delays on an interactive Leaflet dark map.
3. **0–100 Explainable Threat Score**: Calculates composite risk levels decomposed across detected indicators.
4. **Phishing & Lookalike Detection**: Catches visual homoglyphs (e.g. `micros0ft.com`), CEO fraud / BEC spoofing, and raw IP URLs.
5. **Incident Case Tracking**: Allows analysts to group related email investigations into cases and record timestamped notes.

---

## 🚀 Quickstart

### 1. Windows One-Click Start
Double-click **`run.bat`** in the project root.

### 2. Manual Start:
```bash
# Terminal 1 (Backend):
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2 (Frontend):
cd frontend
npm run dev
```

### 3. Run Tests:
```bash
python -m pytest backend/tests/test_scanner.py -v
```

- **Web UI**: [http://localhost:5173](http://localhost:5173)
- **API Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
