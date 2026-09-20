import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
import json

camps_res = client.get("/api/campaigns")
print(json.dumps(camps_res.json(), indent=2))
