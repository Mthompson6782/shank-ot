import pytest
from fastapi.testclient import TestClient
from otbase.web.app import app

client = TestClient(app)

def test_api_status():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["total_assets"] > 0

def test_api_dashboard():
    res = client.get("/api/dashboard")
    assert res.status_code == 200
    data = res.json()
    assert "total_assets" in data
    assert "avg_ot_risk_score" in data
    assert "top_risky_assets" in data
    assert len(data["top_risky_assets"]) > 0

def test_api_scenarios_switching():
    res = client.post("/api/scenarios/substation")
    assert res.status_code == 200
    assert "substation" in res.json()["message"].lower()

    # Reset back to water treatment
    res2 = client.post("/api/scenarios/water_treatment")
    assert res2.status_code == 200

def test_api_assets_list_and_keyswitch():
    res = client.get("/api/assets")
    assert res.status_code == 200
    assets = res.json()
    assert len(assets) > 0

    first_plc = next(a for a in assets if a["tag_name"] == "PLC-01-MAIN")
    # Change key switch to RUN
    res_put = client.put(f"/api/assets/{first_plc['id']}/keyswitch?mode=RUN")
    assert res_put.status_code == 200
    data = res_put.json()
    assert "RUN" in data["message"]

def test_api_chassis_view():
    res = client.get("/api/chassis/wt-plc-01")
    assert res.status_code == 200
    data = res.json()
    assert data["asset_tag"] == "PLC-01-MAIN"
    assert data["chassis"]["total_slots"] == 10
    assert len(data["chassis"]["modules"]) > 0

def test_api_vulnerabilities_and_compensating_controls():
    res = client.get("/api/vulnerabilities")
    assert res.status_code == 200
    data = res.json()
    assert data["total_vulnerabilities"] > 0

    # Apply a compensating control to wt-plc-01
    payload = {
        "control_type": "Deep Packet Inspection (DPI) Firewall / Zone Conduit Filter",
        "name": "DPI Firewall Filter",
        "description": "Block unauthorized CIP memory writes",
        "risk_reduction_pct": 35.0,
        "justification": "Testing compensating control via API"
    }
    res_post = client.post("/api/vulnerabilities/wt-plc-01/compensate", json=payload)
    assert res_post.status_code == 200
    comp_data = res_post.json()
    assert comp_data["new_risk_score"] > 0

def test_api_hbom_and_compliance():
    res_hbom = client.get("/api/export/hbom/json")
    assert res_hbom.status_code == 200
    assert res_hbom.json()["bom_format"] == "OT-BASE Hardware Bill of Materials (HBOM)"

    res_comp = client.get("/api/export/compliance?format=json")
    assert res_comp.status_code == 200
    assert "overall_score" in res_comp.json()
