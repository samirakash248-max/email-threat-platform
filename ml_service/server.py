from pathlib import Path

import torch
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForSequenceClassification


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "ml_model"


# ---------------------------------------------------------
# Application
# ---------------------------------------------------------

app = FastAPI(
    title="ThreatSentinel ML Service",
    version="1.0.0",
    description="Local DistilBERT email threat classification service"
)


# ---------------------------------------------------------
# Device
# ---------------------------------------------------------

DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)


# ---------------------------------------------------------
# Load trained model
# ---------------------------------------------------------

print(f"Loading ThreatSentinel model from: {MODEL_PATH}")
print(f"Using device: {DEVICE}")

tokenizer = AutoTokenizer.from_pretrained(
    str(MODEL_PATH)
)

model = AutoModelForSequenceClassification.from_pretrained(
    str(MODEL_PATH)
)

model.to(DEVICE)
model.eval()

print("ThreatSentinel model loaded successfully.")


# ---------------------------------------------------------
# Request schema
# ---------------------------------------------------------

class EmailPredictionRequest(BaseModel):
    sender: str = ""
    subject: str = ""
    body: str = ""


# ---------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model": "threatsentinel-distilbert",
        "device": str(DEVICE),
        "cuda_available": torch.cuda.is_available()
    }


# ---------------------------------------------------------
# Prediction endpoint
# ---------------------------------------------------------

@app.post("/predict")
def predict(request: EmailPredictionRequest):

    model_text = (
        "Sender: " + request.sender.strip() +
        "\nSubject: " + request.subject.strip() +
        "\n\nEmail Body:\n" + request.body.strip()
    )

    inputs = tokenizer(
        model_text,
        return_tensors="pt",
        truncation=True,
        max_length=256
    )

    inputs = {
        key: value.to(DEVICE)
        for key, value in inputs.items()
    }

    with torch.no_grad():
        outputs = model(**inputs)

    probabilities = torch.softmax(
        outputs.logits,
        dim=-1
    )[0]

    benign_probability = float(probabilities[0].item())
    threat_probability = float(probabilities[1].item())

    prediction = (
        "THREAT"
        if threat_probability >= 0.5
        else "BENIGN"
    )

    confidence = max(
        benign_probability,
        threat_probability
    )

    return {
        "prediction": prediction,
        "confidence": confidence,
        "threat_probability": threat_probability,
        "benign_probability": benign_probability
    }
