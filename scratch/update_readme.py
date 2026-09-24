with open("README.md", "r", encoding="utf-8") as f:
    text = f.read()

new_docs = """
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
"""

text += "\n" + new_docs

with open("README.md", "w", encoding="utf-8") as f:
    f.write(text)
