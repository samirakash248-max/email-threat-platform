@echo off
title ThreatSentinel Launcher
echo ========================================================
echo Launching ThreatSentinel Platform (Backend + Frontend)
echo SIH 2026 PS 26106 - AI-Powered Email Threat Platform
echo ========================================================
echo.

start "ThreatSentinel Backend (FastAPI)" cmd /k "cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
start "ThreatSentinel Frontend (Vite React)" cmd /k "cd frontend && npm run dev"

echo.
echo Both servers are launching in background windows:
echo - Backend API Docs: http://127.0.0.1:8000/docs
echo - Frontend Web UI:  http://localhost:5173
echo.
pause
