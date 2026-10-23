from fastapi.testclient import TestClient
from app.main import app, connection
from app import main
import json

client = TestClient(app)
AUTH = {"Authorization": "Bearer test-admin"}

def test_token_usage_requires_admin():
    assert client.get("/api/v1/ai-token-usage").status_code == 401

def test_token_usage_aggregation_without_prices():
    with connection() as db:
        db.execute("""INSERT INTO ai_token_runs
            (source,model,profile,token_input,token_output,token_total,rounds,tools,result_chars,details)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            ("qa", "test-usage-model", "standard", 100, 25, 125, 2, 1, 300,
             json.dumps([{"kind":"round","round":1,"input":100,"output":25,"total":125},
                         {"kind":"tool","name":"host_get","chars":300,"raw_chars":500,"ms":50}])))
    response=client.get("/api/v1/ai-token-usage?model=test-usage-model&source=qa",headers=AUTH)
    assert response.status_code == 200
    payload=response.json()
    assert payload["total_tokens"] >= 125
    assert payload["total_input"] >= 100
    assert payload["records"][0]["details"][1]["name"] == "host_get"
    assert "price_input" not in payload and "total_cost" not in payload
