import os
import json
from typing import List, Optional, Dict, Any
from pathlib import Path
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from otbase.config import settings
from otbase.db.repository import repo
from otbase.models.asset import Asset, KeySwitchMode
from otbase.models.vulnerability import CompensatingControl, CompensatingControlType
from otbase.engine.risk_engine import OTRiskEngine
from otbase.engine.cve_matcher import CVEMatcher
from otbase.engine.topology_analyzer import TopologyAnalyzer
from otbase.engine.lifecycle_analyzer import LifecycleAnalyzer
from otbase.discovery.parsers.rockwell_l5x import RockwellL5XParser
from otbase.discovery.parsers.siemens_aml import SiemensAMLParser
from otbase.discovery.parsers.generic_csv import GenericAssetParser
from otbase.discovery.parsers.ignition_parser import IgnitionParser
from otbase.discovery.probe_simulator import OTProbeSimulator
from otbase.exporter.hbom_sbom import HBOMExporter
from otbase.exporter.compliance_report import ComplianceReportGenerator
from otbase.models.pid_schema import PIDPayload, FlowTelemetryRecord
from otbase.models.topology import LayoutPerspective, TopologyPerspectiveData
from otbase.engine.flow_engine import FlowEngine
from otbase.engine.kandinsky_layout import KandinskyLayoutEngine
from otbase.engine.location_engine import LocationEngine
from otbase.exporter.enterprise_connectors import EnterpriseConnectors

app = FastAPI(
    title="SHANK: SCADA & Hardware Asset Network Knowledge",
    description="Blade Fleet Operational Technology Asset Management & Cybersecurity API",
    version=settings.app_version
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper function to refresh all calculations
def refresh_analytics():
    assets = repo.list_assets()
    advisories = repo.list_advisories()

    # Refresh CVE matches and risk
    for a in assets:
        controls = repo.get_compensating_controls(a.id)
        CVEMatcher.match_asset(a, advisories, controls)
        repo.save_asset(a)

# Initial refresh
refresh_analytics()

@app.get("/api/status")
def get_status():
    return {
        "status": "online",
        "app_name": settings.app_name,
        "version": settings.app_version,
        "active_facility": repo.current_facility,
        "total_assets": len(repo.assets)
    }

@app.get("/api/dashboard")
def get_dashboard_kpis():
    refresh_analytics()
    assets = repo.list_assets()
    violations = TopologyAnalyzer.audit(assets, repo.list_zones(), repo.list_conduits())
    lifecycle_risks = LifecycleAnalyzer.analyze_assets(assets, repo.lifecycle_milestones)

    # Calculate metrics
    purdue_counts: Dict[str, int] = {}
    criticality_counts: Dict[str, int] = {}
    vendor_counts: Dict[str, int] = {}
    cve_severity_counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    total_cves = 0

    all_matches = []
    for a in assets:
        # Purdue breakdown
        p_val = a.purdue_level.value.split(" - ")[0]
        purdue_counts[p_val] = purdue_counts.get(p_val, 0) + 1

        # Criticality breakdown
        c_val = a.criticality.value.split(" (")[0]
        criticality_counts[c_val] = criticality_counts.get(c_val, 0) + 1

        # Vendor breakdown
        vendor_counts[a.vendor] = vendor_counts.get(a.vendor, 0) + 1

        # Matches
        matches = CVEMatcher.match_asset(a, repo.list_advisories(), repo.get_compensating_controls(a.id))
        for m in matches:
            all_matches.append(m)
            cve_severity_counts[m.severity.value] = cve_severity_counts.get(m.severity.value, 0) + 1

    total_cves = len(all_matches)
    avg_risk = round(sum(a.ot_risk_score for a in assets) / max(1, len(assets)), 1)
    sorted_risky = sorted(assets, key=lambda x: x.ot_risk_score, reverse=True)[:5]

    scorecard = ComplianceReportGenerator.evaluate(repo.current_facility, assets, violations)

    return {
        "active_facility": repo.current_facility,
        "total_assets": len(assets),
        "avg_ot_risk_score": avg_risk,
        "total_cves": total_cves,
        "total_violations": len(violations),
        "eol_hardware_count": len(lifecycle_risks),
        "compliance_score": scorecard.overall_score,
        "iec_62443_score": scorecard.iec_62443_score,
        "purdue_distribution": purdue_counts,
        "criticality_distribution": criticality_counts,
        "vendor_distribution": vendor_counts,
        "cve_severity_distribution": cve_severity_counts,
        "top_risky_assets": [
            {
                "id": a.id,
                "tag": a.tag_name,
                "name": a.display_name,
                "vendor": a.vendor,
                "model": a.model,
                "level": a.purdue_level.value,
                "ot_risk_score": a.ot_risk_score,
                "active_cves": a.active_cves
            }
            for a in sorted_risky
        ]
    }

@app.get("/api/scenarios")
def get_scenarios():
    return [
        {
            "id": "water_treatment",
            "name": "Municipal Water Treatment Facility",
            "description": "Rockwell ControlLogix 5580, CompactLogix, PanelView HMI, FactoryTalk Historian, Level 3.5 IDMZ.",
            "device_count": 8
        },
        {
            "id": "substation",
            "name": "500kV Substation Alpha (Power Transmission)",
            "description": "SEL-3530 RTAC, SEL-421, Siemens SIPROTEC 5, NERC CIP Electronic Security Perimeter.",
            "device_count": 5
        },
        {
            "id": "refinery",
            "name": "Petrochemical Continuous Refinery (Crude Unit)",
            "description": "Yokogawa Centum VP DCS, Triconex SIS Safety Controller (SIL 3), legacy Siemens S7-400H.",
            "device_count": 5
        },
        {
            "id": "walmart_cold_chain",
            "name": "Walmart DC 6094 (Perishable Grocery & Cold Chain)",
            "description": "Johnson Controls Frick Quantum HD screw compressors, Emerson Copeland E3, Det-Tronics NH3 life safety, Inductive Automation Ignition SCADA.",
            "device_count": 11
        }
    ]

@app.post("/api/scenarios/{scenario_name}")
def switch_scenario(scenario_name: str):
    if scenario_name not in ("water_treatment", "substation", "refinery", "walmart_cold_chain", "walmart", "cold_chain"):
        raise HTTPException(status_code=400, detail="Unknown scenario.")
    repo.load_scenario(scenario_name)
    refresh_analytics()
    return {"message": f"Successfully loaded scenario {scenario_name}", "facility": repo.current_facility}

@app.get("/api/assets")
def list_assets(
    facility: Optional[str] = None,
    purdue_level: Optional[str] = None,
    vendor: Optional[str] = None,
    query: Optional[str] = None
):
    refresh_analytics()
    return repo.list_assets(facility, purdue_level, vendor, query)

@app.get("/api/assets/{asset_id}")
def get_asset_detail(asset_id: str):
    asset = repo.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    controls = repo.get_compensating_controls(asset_id)
    matches = CVEMatcher.match_asset(asset, repo.list_advisories(), controls)
    return {
        "asset": asset,
        "vulnerability_matches": matches,
        "compensating_controls": controls
    }

@app.put("/api/assets/{asset_id}/keyswitch")
def update_keyswitch(asset_id: str, mode: str = Query(...)):
    asset = repo.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Match mode
    matched_mode = KeySwitchMode.NOT_APPLICABLE
    for km in KeySwitchMode:
        if km.name.lower() == mode.lower() or km.value.lower().startswith(mode.lower()):
            matched_mode = km
            break
    
    asset.key_switch = matched_mode
    controls = repo.get_compensating_controls(asset_id)
    matches = CVEMatcher.match_asset(asset, repo.list_advisories(), controls)
    repo.save_asset(asset)
    return {
        "message": f"Updated key switch to {matched_mode.value}",
        "new_risk_score": asset.ot_risk_score
    }

@app.delete("/api/assets/{asset_id}")
def delete_asset(asset_id: str):
    deleted = repo.delete_asset(asset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"message": "Asset successfully deleted"}

@app.get("/api/chassis/{asset_id}")
def get_chassis_view(asset_id: str):
    asset = repo.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not asset.chassis:
        raise HTTPException(status_code=404, detail="Asset does not have a modular chassis")
    return {
        "asset_tag": asset.tag_name,
        "asset_name": asset.display_name,
        "chassis": asset.chassis
    }

@app.get("/api/topology")
def get_topology():
    assets = repo.list_assets()
    zones = repo.list_zones()
    conduits = repo.list_conduits()
    violations = TopologyAnalyzer.audit(assets, zones, conduits)
    return {
        "facility": repo.current_facility,
        "zones": zones,
        "conduits": conduits,
        "violations": violations,
        "assets": [
            {
                "id": a.id,
                "tag_name": a.tag_name,
                "display_name": a.display_name,
                "purdue_level": a.purdue_level.value,
                "device_type": a.device_type.value,
                "ip_address": a.network_interfaces[0].ip_address if a.network_interfaces else None,
                "ot_risk_score": a.ot_risk_score
            }
            for a in assets
        ]
    }

@app.get("/api/vulnerabilities")
def get_vulnerabilities():
    assets = repo.list_assets()
    advisories = repo.list_advisories()
    all_matches = []
    for a in assets:
        controls = repo.get_compensating_controls(a.id)
        matches = CVEMatcher.match_asset(a, advisories, controls)
        all_matches.extend(matches)
    
    # Sort by contextual risk descending
    all_matches.sort(key=lambda m: m.ot_contextual_risk, reverse=True)
    return {
        "total_vulnerabilities": len(all_matches),
        "vulnerabilities": all_matches
    }

class CompensateRequest(BaseModel):
    control_type: CompensatingControlType
    name: str
    description: str
    risk_reduction_pct: float = 35.0
    justification: str

@app.post("/api/vulnerabilities/{asset_id}/compensate")
def apply_compensating_control(asset_id: str, req: CompensateRequest):
    asset = repo.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    import uuid
    ctrl = CompensatingControl(
        id=f"ctrl-{uuid.uuid4().hex[:6]}",
        control_type=req.control_type,
        name=req.name,
        description=req.description,
        risk_reduction_pct=req.risk_reduction_pct,
        is_active=True,
        justification=req.justification
    )
    repo.add_compensating_control(asset_id, ctrl)
    refresh_analytics()
    updated = repo.get_asset(asset_id)
    return {
        "message": "Compensating control successfully applied",
        "new_risk_score": updated.ot_risk_score,
        "control": ctrl
    }

@app.delete("/api/vulnerabilities/{asset_id}/compensate/{control_id}")
def remove_compensating_control(asset_id: str, control_id: str):
    repo.remove_compensating_control(asset_id, control_id)
    refresh_analytics()
    updated = repo.get_asset(asset_id)
    return {
        "message": "Compensating control removed",
        "new_risk_score": updated.ot_risk_score if updated else 0.0
    }

@app.get("/api/lifecycle")
def get_lifecycle_overview():
    assets = repo.list_assets()
    risks = LifecycleAnalyzer.analyze_assets(assets, repo.lifecycle_milestones)
    return {
        "milestones": repo.lifecycle_milestones,
        "obsolescence_risks": risks
    }

@app.post("/api/discovery/probe")
def trigger_passive_probe():
    new_assets = OTProbeSimulator.run_safe_discovery_sweep(repo.current_facility)
    added = []
    for a in new_assets:
        repo.save_asset(a)
        added.append(a.tag_name)
    refresh_analytics()
    return {
        "message": f"Non-intrusive probe completed. Discovered {len(added)} new asset(s).",
        "discovered_assets": added
    }

@app.post("/api/ingest/upload")
async def upload_file(
    file: UploadFile = File(...),
    file_type: str = Form("auto")
):
    content = await file.read()
    filename = file.filename or "unknown_file"
    text_content = content.decode("utf-8", errors="replace")

    inferred_type = file_type
    if inferred_type == "auto":
        if filename.lower().endswith(".gwbk"):
            inferred_type = "gwbk"
        elif filename.endswith(".L5X") or filename.endswith(".l5x") or "RSLogix5000Content" in text_content:
            inferred_type = "l5x"
        elif filename.endswith(".aml") or "CAEXFile" in text_content or "AutomationML" in text_content:
            inferred_type = "aml"
        elif filename.endswith(".csv"):
            inferred_type = "csv"
        elif filename.endswith(".json"):
            if "pid_version" in text_content or "backplane_crawls" in text_content or "probed_subnets" in text_content:
                inferred_type = "pid"
            elif "opcItemPath" in text_content or "tagType" in text_content or "opcServer" in text_content:
                inferred_type = "ignition_tags"
            else:
                inferred_type = "json"
        elif filename.endswith(".pid"):
            inferred_type = "pid"

    added_assets = []
    try:
        if inferred_type == "pid":
            data = json.loads(text_content)
            payload = PIDPayload.model_validate(data)
            res = repo.ingest_pid(payload)
            added_assets = res.get("assets", [])
        elif inferred_type == "gwbk":
            assets, conduits = IgnitionParser.parse_gwbk_bytes(content, facility=repo.current_facility)
            for a in assets:
                repo.save_asset(a)
                added_assets.append(a.tag_name)
            for c in conduits:
                repo.conduits[c.id] = c
            repo.save_to_disk()
        elif inferred_type == "ignition_tags":
            assets, conduits = IgnitionParser.parse_tag_json(text_content, facility=repo.current_facility)
            for a in assets:
                repo.save_asset(a)
                added_assets.append(a.tag_name)
            for c in conduits:
                repo.conduits[c.id] = c
            repo.save_to_disk()
        elif inferred_type == "l5x":
            asset = RockwellL5XParser.parse_string(text_content, facility=repo.current_facility)
            repo.save_asset(asset)
            added_assets.append(asset.tag_name)
        elif inferred_type == "aml":
            asset = SiemensAMLParser.parse_string(text_content, facility=repo.current_facility)
            repo.save_asset(asset)
            added_assets.append(asset.tag_name)
        elif inferred_type == "csv":
            assets = GenericAssetParser.parse_csv(text_content, facility=repo.current_facility)
            for a in assets:
                repo.save_asset(a)
                added_assets.append(a.tag_name)
        elif inferred_type == "json":
            assets = GenericAssetParser.parse_json(text_content, facility=repo.current_facility)
            for a in assets:
                repo.save_asset(a)
                added_assets.append(a.tag_name)
        else:
            raise HTTPException(status_code=400, detail=f"Unrecognized file format for '{filename}'")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse file: {str(e)}")

    refresh_analytics()
    return {
        "message": f"Successfully ingested '{filename}'. Imported {len(added_assets)} asset(s).",
        "imported_tags": added_assets
    }

@app.get("/api/export/hbom/json")
def export_hbom_json():
    assets = repo.list_assets()
    data = HBOMExporter.generate_hbom_json(assets)
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f"attachment; filename=HBOM_{repo.current_facility.replace(' ', '_')}.json"}
    )

@app.get("/api/export/hbom/csv")
def export_hbom_csv():
    assets = repo.list_assets()
    csv_str = HBOMExporter.generate_hbom_csv(assets)
    return Response(
        content=csv_str,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=HBOM_{repo.current_facility.replace(' ', '_')}.csv"}
    )

@app.get("/api/export/compliance")
def get_compliance_scorecard(format: str = "json"):
    assets = repo.list_assets()
    violations = TopologyAnalyzer.audit(assets, repo.list_zones(), repo.list_conduits())
    scorecard = ComplianceReportGenerator.evaluate(repo.current_facility, assets, violations)

    if format == "markdown":
        md = ComplianceReportGenerator.generate_markdown_report(scorecard)
        return PlainTextResponse(md)

    return scorecard

@app.post("/api/ingest/pid")
def ingest_pid_payload(payload: PIDPayload):
    result = repo.ingest_pid(payload)
    refresh_analytics()
    return result

@app.get("/api/topology/perspectives")
def get_topology_perspective(mode: str = Query("connections")):
    mode_map = {
        "connections": LayoutPerspective.CONNECTIONS,
        "locations": LayoutPerspective.LOCATIONS,
        "purdue": LayoutPerspective.PURDUE_HIERARCHY,
        "networks": LayoutPerspective.NETWORKS,
        "organic": LayoutPerspective.ORGANIC
    }
    persp = mode_map.get(mode.lower(), LayoutPerspective.CONNECTIONS)
    return repo.get_topology_perspective(persp)

@app.post("/api/topology/unmanaged-switch")
def add_unmanaged_switch(switch_data: Dict[str, Any]):
    return repo.add_unmanaged_switch(switch_data)

@app.get("/api/telemetry/flows")
def get_flow_telemetry():
    return {
        "total_flows": len(repo.flows),
        "flows": repo.flows
    }

@app.get("/api/telemetry/sankey")
def get_sankey_data():
    return repo.get_sankey_data()

@app.get("/api/telemetry/profile/{ip_address}")
def profile_traffic(ip_address: str):
    return FlowEngine.profile_asset_traffic(ip_address, repo.flows, repo.list_assets())

@app.get("/api/locations")
def get_locations_and_duplicate_ips():
    return {
        "facility": repo.current_facility,
        "location_tree": repo.location_tree,
        "duplicate_ip_report": repo.get_duplicate_ips()
    }

@app.get("/api/locations/duplicate-ips")
def get_duplicate_ips():
    return repo.get_duplicate_ips()

@app.get("/api/systems")
def get_systems():
    return {
        "facility": repo.current_facility,
        "systems": repo.systems,
        "shared_trunk_switches": LocationEngine.find_shared_trunk_switches(repo.systems)
    }

@app.get("/api/export/servicenow")
def export_servicenow_cmdb():
    payload = EnterpriseConnectors.generate_servicenow_cmdb_payload(repo.list_assets(), repo.current_facility)
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f"attachment; filename=ServiceNow_CMDB_{repo.current_facility.replace(' ', '_')}.json"}
    )

@app.get("/api/export/splunk")
def export_splunk_ta():
    events = EnterpriseConnectors.generate_splunk_ta_events(repo.list_assets(), repo.list_violations(), repo.flows)
    return PlainTextResponse(events)

@app.get("/api/export/firewall-rules")
def export_firewall_rules(vendor: str = Query("fortinet")):
    rules = EnterpriseConnectors.generate_firewall_rules(repo.list_conduits(), repo.list_assets(), vendor)
    return PlainTextResponse(rules)

@app.get("/api/export/topology-graphml")
def export_topology_graphml(mode: str = Query("connections")):
    mode_map = {
        "connections": LayoutPerspective.CONNECTIONS,
        "locations": LayoutPerspective.LOCATIONS,
        "purdue": LayoutPerspective.PURDUE_HIERARCHY,
        "networks": LayoutPerspective.NETWORKS,
        "organic": LayoutPerspective.ORGANIC
    }
    data = repo.get_topology_perspective(mode_map.get(mode.lower(), LayoutPerspective.CONNECTIONS))
    graphml = KandinskyLayoutEngine.export_graphml(data)
    return Response(
        content=graphml,
        media_type="application/xml",
        headers={"Content-Disposition": f"attachment; filename=Topology_{mode}.graphml"}
    )

@app.get("/api/export/topology-svg")
def export_topology_svg(mode: str = Query("connections")):
    mode_map = {
        "connections": LayoutPerspective.CONNECTIONS,
        "locations": LayoutPerspective.LOCATIONS,
        "purdue": LayoutPerspective.PURDUE_HIERARCHY,
        "networks": LayoutPerspective.NETWORKS,
        "organic": LayoutPerspective.ORGANIC
    }
    data = repo.get_topology_perspective(mode_map.get(mode.lower(), LayoutPerspective.CONNECTIONS))
    svg = KandinskyLayoutEngine.export_svg(data)
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Content-Disposition": f"attachment; filename=Topology_{mode}.svg"}
    )

# Armis Integration Endpoints
class ArmisSyncRequest(BaseModel):
    tenant_url: Optional[str] = None
    api_secret_key: Optional[str] = None
    simulate: bool = True
    aql: str = "in:devices"

@app.post("/api/armis/sync")
def sync_armis(payload: Optional[ArmisSyncRequest] = None):
    p = payload or ArmisSyncRequest()
    res = repo.sync_armis(
        tenant_url=p.tenant_url,
        api_secret_key=p.api_secret_key,
        simulate=p.simulate,
        aql=p.aql
    )
    return res

@app.get("/api/armis/devices")
def get_armis_devices():
    if not repo.armis_devices:
        repo.sync_armis(simulate=True)
    return {
        "count": len(repo.armis_devices),
        "devices": repo.armis_devices
    }

@app.get("/api/armis/reconciliation")
def get_armis_reconciliation():
    report = repo.get_reconciliation_report()
    return report

@app.post("/api/armis/connections/ingest-to-flows")
def ingest_armis_flows():
    new_flows = repo.ingest_armis_connections_to_flows()
    return {
        "status": "success",
        "new_flows_ingested": new_flows,
        "total_flows": len(repo.flows)
    }

# Mount static files
static_path = settings.static_dir
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_file = settings.static_dir / "index.html"
    if index_file.exists():
        return index_file.read_text(encoding="utf-8")
    return HTMLResponse("<h1>OT-BASE Asset Center</h1><p>Static files loading...</p>")
