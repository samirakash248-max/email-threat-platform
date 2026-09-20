# ThreatSentinel
**Forensic Email Analysis & SOC Case Management Platform**

ThreatSentinel is a deterministic email parsing, forensic analysis, and SOC case management platform. It uses strict rule-based scoring combined with MITRE ATT&CK mapping, Threat Intelligence Graphs, and Campaign Correlation to empower analysts to identify, triage, and remediate advanced email threats.

## ?? Key Features

* **Forensic Analysis Pipeline**: Deterministic evaluation of RFC 5322 structures, SPF/DKIM/DMARC alignment, and deep headers.
* **URL Intelligence Engine**: On-device extraction and risk-scoring of URLs (detecting typosquatting, obfuscation, and suspicious top-level domains) without external API reliance.
* **MITRE ATT&CK Mapping**: Maps threat heuristics directly to the ATT&CK framework (e.g., T1566.002 Spearphishing Link).
* **Threat Intelligence Graph**: A backend-driven ForceGraph visualization correlating overlapping indicators (IPs, domains, hashes) across investigations.
* **Campaign Correlation Engine**: Groups isolated phishing attempts into broader threat campaigns automatically based on shared infrastructure.
* **SOC Analyst Case Lifecycle**: Built-in state machine (`NEW` -> `TRIAGED` -> `INVESTIGATING` -> `RESOLVED`) with analyst assignment and immutable notes.
* **Chain of Custody & Blockchain Anchoring**: Cryptographically secures evidence via Merkle Trees and an Ethereum smart contract to mathematically prevent evidence tampering.
* **Detection Analytics**: Native performance scoring (Accuracy, Precision, Recall, F1) running live against synthetic datasets to validate rule efficacy without fabricated metrics.

## ?? Architecture
- **Backend**: FastAPI (Python 3) handling APIs, SQLite via SQLAlchemy for persistence, and `web3.py` for blockchain interactions.
- **Frontend**: React, Tailwind CSS, Vite, and Lucide Icons. Features an enterprise-grade tabbed SOC dashboard.
- **Data Persistence**: `email_threat_platform.db` (SQLite) stores immutable records, cases, correlations, and analytics.

## ?? Installation & Setup

1. **Install Backend Dependencies**:
```bash
cd backend
pip install -r requirements.txt
```

2. **Install Frontend Dependencies**:
```bash
cd frontend
npm install
```

3. **Environment Variables (`.env`)**:
```env
DEMO_MODE=true
MAX_UPLOAD_SIZE_BYTES=15728640
BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545
```

## ?? Running the Application

**Option A: Windows Batch Script**
```cmd
run.bat
```

**Option B: Manual Startup**
*Backend*:
```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
*Frontend*:
```bash
cd frontend
npm run dev
```

## ?? Security & Privacy Model
- **Zero PII on Blockchain**: Only canonical, non-sensitive forensic metadata (scores, severity) are hashed and anchored to the Ethereum ledger. Raw email bodies, personal signatures, and PII are explicitly stripped.
- **No Path Traversal**: All uploaded emails are processed in-memory.
- **Graceful Failures**: If the blockchain RPC is unreachable, the system gracefully falls back to off-chain cryptography without crashing.

## ?? Testing
The project maintains a rigorous suite of 76 tests covering the entire pipeline.
```bash
pytest backend/tests/ -v
```

## ?? Demo Workflow
Run `python scripts/demo_walkthrough.py` to watch a synthetic email pass through ingestion, scoring, graphing, blockchain anchoring, and case closure.

## ?? Known Limitations

- **Domain Intelligence**: Domain WHOIS/RDAP and DNS heuristics highlight infrastructure configuration (e.g. shared MX, privacy protection) and cannot attribute actual ownership to a specific human actor. PII from WHOIS is intentionally minimized.
- **Offline Fallback for DNS/RDAP**: Domain intelligence relies on local mocked data sets when `USE_LIVE_DNS_API=true` and `USE_LIVE_WHOIS_API=true` are not enabled, allowing the application to function entirely offline without external resolution delays or third-party dependencies.


- **Infrastructure Intelligence**: IP intelligence establishes *observed infrastructure* (e.g., Tor exit nodes, VPNs, cloud providers). It does not, and cannot, establish the physical location or true identity of the attacker.
- **Geolocation**: Any geographic location derived from IPs reflects the datacenter or ISP location, not the sender.
- **Offline Fallback**: The IP intelligence component works offline via local deterministic lists (for major clouds and Tor). A live external provider is optional and configurable via `USE_LIVE_IP_API=true`.

- The provided metrics in the Detection Analytics dashboard represent performance against a synthetic dataset of 10 samples. **This does not reflect production-grade real-world accuracy.**
- The system currently uses SQLite. A migration to PostgreSQL is recommended for large-scale enterprise deployments.


## Real-Time Ingestion

ThreatSentinel exposes an authenticated, idempotent HTTP ingestion boundary designed for integration with enterprise mail gateways and webhook-based MTA workflows.

* `/api/analyze-email` is the primary machine-ingestion boundary.
* It natively accepts RFC 5322 raw email payloads.
* It supports authenticated integration via the `INGESTION_API_KEY` (using `Authorization: Bearer <key>`).
* **Idempotency**: Submissions are deterministic. Duplicate deliveries of the same email (identified by `Message-ID` or raw hash) return the existing analysis without re-anchoring to the blockchain or creating duplicate alerts.
* **Automatic Escalation**: Highly suspicious emails automatically escalate and create new Case Records based on a configurable threshold (`AUTO_CASE_THRESHOLD`, default 80).

*Note: ThreatSentinel itself does not run an SMTP server, IMAP poller, Microsoft Graph listener, or a native mail gateway. It relies on the modern API-webhook delivery pattern.*

## Bulk Analysis

For analyst workflows and initial triage, ThreatSentinel provides a bulk import API and UI.

* Analysts can select multiple `.eml` files or upload a `.zip` archive containing emails.
* **Configurable Limits**: Limits on batch size, individual email size, and total uncompressed archive size protect the infrastructure from Zip Bombs or resource exhaustion.
* **Per-Email Analysis**: Each extracted `.eml` passes independently through the complete intelligence stack.
* **Duplicate Detection**: Safely skips expensive processing and blockchain anchoring for previously seen files.
* **Automatic Escalation**: Validates each payload against the `AUTO_CASE_THRESHOLD`.
* **Batch Summary**: Returns a comprehensive statistical summary of the batch (analyzed, duplicates, failed, and risk breakdowns).
* **Safe Archive Handling**: The pipeline strictly rejects path traversal (Zip Slip), nested ZIP files, and unsupported file extensions.

## Security

* **Authentication**: Machine-to-machine ingestion can be secured with a constant-time verified `INGESTION_API_KEY`.
* **Resource Limits**: Strict memory bounding on ZIP extraction and single-file sizes prevent Denial-of-Wallet and OOM attacks.
* **Duplicate Protection**: Halts the ingestion pipeline before executing expensive AI inferences or blockchain transactions if the payload is a recognized duplicate.
* **Archive Path Traversal**: Ensures zip extraction strictly ignores relative paths (`../`) and absolute path injection.
* **Zero-PII Blockchain Canonicalization**: The system strictly extracts forensics and strips unstructured bodies before issuing the final cryptographic anchor.
* *Note: ThreatSentinel implements best-in-class technical privacy controls, but does not claim legal or GDPR compliance automatically. Production deployment requires proper organizational access control.*
