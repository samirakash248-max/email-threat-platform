import os
from typing import Any, Dict, Optional

import httpx


ML_SERVICE_URL = os.getenv(
    "ML_SERVICE_URL",
    "http://127.0.0.1:8001",
)

ML_TIMEOUT_SECONDS = float(
    os.getenv("ML_SERVICE_TIMEOUT_SECONDS", "8")
)


def classify_email(
    sender: str = "",
    subject: str = "",
    body: str = "",
) -> Optional[Dict[str, Any]]:
    """
    Calls the local DistilBERT email threat classifier.

    Returns None if the ML service is unavailable or returns an
    invalid response. The forensic scanner must remain functional
    when ML is unavailable.
    """

    payload = {
        "sender": sender or "",
        "subject": subject or "",
        "body": body or "",
    }

    try:
        response = httpx.post(
            f"{ML_SERVICE_URL.rstrip('/')}/predict",
            json=payload,
            timeout=ML_TIMEOUT_SECONDS,
        )
        response.raise_for_status()

        data = response.json()

        prediction = data.get("prediction")
        confidence = data.get("confidence")
        threat_probability = data.get("threat_probability")
        benign_probability = data.get("benign_probability")

        if prediction not in {"BENIGN", "THREAT"}:
            return None

        if not all(
            isinstance(value, (int, float))
            for value in (
                confidence,
                threat_probability,
                benign_probability,
            )
        ):
            return None

        return {
            "prediction": prediction,
            "confidence": float(confidence),
            "threat_probability": float(threat_probability),
            "benign_probability": float(benign_probability),
            "model": "threatsentinel-distilbert",
            "source": "local_ml_service",
        }

    except Exception:
        # ML is enrichment, not a dependency of forensic analysis.
        return None
