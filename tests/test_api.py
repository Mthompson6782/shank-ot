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

def test_api_network_context_and_enterprise_connectors():
    # 1. Kandinsky Perspectives
    for mode in ["connections", "locations", "purdue", "networks", "organic"]:
        res_persp = client.get(f"/api/topology/perspectives?mode={mode}")
        assert res_persp.status_code == 200
        data = res_persp.json()
        assert len(data["nodes"]) > 0

    # 2. Telemetry and Sankey
    res_sankey = client.get("/api/telemetry/sankey")
    assert res_sankey.status_code == 200
    assert "links" in res_sankey.json()

    res_profile = client.get("/api/telemetry/profile/192.168.10.10")
    assert res_profile.status_code == 200
    assert res_profile.json()["target_ip"] == "192.168.10.10"

    # 3. Locations and Systems
    res_loc = client.get("/api/locations")
    assert res_loc.status_code == 200
    assert len(res_loc.json()["location_tree"]) > 0

    res_sys = client.get("/api/systems")
    assert res_sys.status_code == 200
    assert len(res_sys.json()["systems"]) > 0

    # 4. Enterprise Connectors
    res_snow = client.get("/api/export/servicenow")
    assert res_snow.status_code == 200
    assert res_snow.json()["source"] == "SHANK Service Graph Connector"

    res_splunk = client.get("/api/export/splunk")
    assert res_splunk.status_code == 200
    assert "CEF:0|Thompson|SHANK" in res_splunk.text

    res_fw = client.get("/api/export/firewall-rules?vendor=fortinet")
    assert res_fw.status_code == 200
    assert "config firewall policy" in res_fw.text

    res_graphml = client.get("/api/export/topology-graphml?mode=connections")
    assert res_graphml.status_code == 200
    assert "<graphml" in res_graphml.text

    res_svg = client.get("/api/export/topology-svg?mode=connections")
    assert res_svg.status_code == 200
    assert "<svg" in res_svg.text

def test_api_walmart_cold_chain_scenario():
    # 1. Switch scenario to Walmart Cold Chain
    res_switch = client.post("/api/scenarios/walmart_cold_chain")
    assert res_switch.status_code == 200
    data_switch = res_switch.json()
    assert "walmart_cold_chain" in data_switch["message"].lower()
    assert "Walmart" in data_switch["facility"]

    # 2. Verify assets list
    res_assets = client.get("/api/assets")
    assert res_assets.status_code == 200
    assets = res_assets.json()
    assert len(assets) == 11

    tags = [a["tag_name"] for a in assets]
    assert "PLC-NH3-COMP-01" in tags
    assert "PLC-NH3-COMP-02" in tags
    assert "RACK-E3-GROCERY" in tags
    assert "NH3-GAS-SAFETY-01" in tags
    assert "HMI-COLD-DOCK" in tags
    assert "TAB-DOCK-TECH" in tags
    assert "SCADA-COLD-SRV01" in tags
    assert "SW-COLD-01" in tags
    assert "IOT-AZURE-COLDGW" in tags
    assert "PLC-BLAST-FREEZE-B" in tags
    assert "PUMP-NH3-PURGE-STBY" in tags

    # 3. Verify Frick Quantum HD Chassis
    res_chassis = client.get("/api/chassis/wm-plc-nh3-01")
    assert res_chassis.status_code == 200
    chassis_data = res_chassis.json()
    assert chassis_data["asset_tag"] == "PLC-NH3-COMP-01"
    assert chassis_data["chassis"]["total_slots"] == 6
    assert len(chassis_data["chassis"]["modules"]) == 6

    # 4. Verify Duplicate IP disambiguation (192.168.10.11 on Compressor 1 and Blast Freezer Skid)
    res_dup = client.get("/api/locations/duplicate-ips")
    assert res_dup.status_code == 200
    dup_data = res_dup.json()
    assert dup_data["total_duplicate_ips_tracked"] >= 1
    dup_cluster = next((c for c in dup_data["duplicate_subnets"] if c["ip_address"] == "192.168.10.11"), None)
    assert dup_cluster is not None
    assert dup_cluster["collision_count"] == 2

    # 5. Verify Topology & Violations (Dual-homed dock tablet + remote keyswitch)
    res_topo = client.get("/api/topology")
    assert res_topo.status_code == 200
    topo_data = res_topo.json()
    assert len(topo_data["zones"]) == 5
    assert len(topo_data["conduits"]) == 4
    assert len(topo_data["violations"]) >= 2

    # 6. Verify Key Switch Toggle on Compressor 2
    res_key = client.put("/api/assets/wm-plc-nh3-02/keyswitch?mode=RUN")
    assert res_key.status_code == 200
    assert "RUN" in res_key.json()["message"]

    # 7. Switch back to water treatment for test isolation
    res_reset = client.post("/api/scenarios/water_treatment")
    assert res_reset.status_code == 200

