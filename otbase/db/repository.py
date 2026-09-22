import json
import os
from typing import List, Optional, Dict, Any
from pathlib import Path
from otbase.config import settings
from otbase.models.asset import Asset, Chassis, RackModule, PurdueLevel, Criticality, SwitchPortBinding
from otbase.models.topology import PurdueZone, Conduit, SecurityViolation, LayoutPerspective, TopologyPerspectiveData
from otbase.models.location_tree import LocationNode, OTSystem
from otbase.models.pid_schema import (
    PIDPayload, FlowTelemetryRecord, SwitchPortDiscovery
)
from otbase.models.vulnerability import (
    ICSAdvisory, VulnerabilityMatch, CompensatingControl, CompensatingControlType
)
from otbase.models.lifecycle import LifecycleMilestone, ObsolescenceRisk
from otbase.db.seed_data import (
    get_water_treatment_assets, get_substation_assets, get_refinery_assets,
    get_walmart_cold_chain_assets,
    get_purdue_zones, get_conduits, get_security_violations,
    get_ics_advisories, get_lifecycle_milestones
)
from otbase.discovery.switch_interrogator import SwitchInterrogator
from otbase.engine.flow_engine import FlowEngine
from otbase.engine.kandinsky_layout import KandinskyLayoutEngine
from otbase.engine.location_engine import LocationEngine
from otbase.models.armis_schema import (
    ArmisDeviceRecord, ArmisConnectionRecord, ReconciliationReport
)
from otbase.discovery.armis_connector import ArmisConnector, ReconciliationEngine

class OTBaseRepository:
    """Central repository managing OT assets, chassis slots, network topology, and CVE correlations."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or settings.data_dir
        self.db_file = self.data_dir / "otbase_db.json"
        
        self.current_facility = "Municipal Water Treatment Facility"
        self.assets: Dict[str, Asset] = {}
        self.zones: Dict[str, PurdueZone] = {}
        self.conduits: Dict[str, Conduit] = {}
        self.violations: Dict[str, SecurityViolation] = {}
        self.advisories: Dict[str, ICSAdvisory] = {}
        self.applied_compensating_controls: Dict[str, List[CompensatingControl]] = {}
        self.lifecycle_milestones: List[LifecycleMilestone] = []
        self.location_tree: List[LocationNode] = []
        self.systems: List[OTSystem] = []
        self.flows: List[FlowTelemetryRecord] = []
        self.switch_ports: List[SwitchPortDiscovery] = []
        self.unmanaged_switches: List[Dict[str, Any]] = []
        self.armis_devices: List[ArmisDeviceRecord] = []
        self.armis_connections: List[ArmisConnectionRecord] = []
        self.latest_reconciliation: Optional[ReconciliationReport] = None

        self._initialize()

    def _initialize(self):
        """Loads from disk if present, else populates from seed data."""
        if self.db_file.exists():
            try:
                self.load_from_disk()
                return
            except Exception as e:
                print(f"[WARN] Failed to load from disk ({e}), re-seeding default scenario.")
        self.load_scenario("water_treatment")

    def load_scenario(self, scenario: str = "water_treatment"):
        """Switches the active plant scenario."""
        self.assets.clear()
        self.zones.clear()
        self.conduits.clear()
        self.violations.clear()
        self.advisories.clear()
        self.applied_compensating_controls.clear()

        # Load global advisories & milestones
        for adv in get_ics_advisories():
            self.advisories[adv.advisory_id] = adv
        self.lifecycle_milestones = get_lifecycle_milestones()

        if scenario == "substation":
            self.current_facility = "500kV Substation Alpha"
            asset_list = get_substation_assets()
        elif scenario == "refinery":
            self.current_facility = "Petrochemical Continuous Refinery"
            asset_list = get_refinery_assets()
        elif scenario in ("walmart_cold_chain", "walmart", "cold_chain"):
            self.current_facility = "Walmart Distribution Center 6094 (Perishable Grocery & Cold Chain)"
            asset_list = get_walmart_cold_chain_assets()
        else:
            self.current_facility = "Municipal Water Treatment Facility"
            asset_list = get_water_treatment_assets()

        for a in asset_list:
            self.assets[a.id] = a

        for z in get_purdue_zones(self.current_facility):
            self.zones[z.id] = z

        for c in get_conduits(self.current_facility):
            self.conduits[c.id] = c

        for v in get_security_violations(self.current_facility):
            self.violations[v.id] = v

        # Seed Location Tree, Systems, Flows, Switch Ports
        self.location_tree = LocationEngine.get_seed_location_tree(self.current_facility)
        self.systems = LocationEngine.get_seed_systems(self.current_facility, list(self.assets.values()))
        self.flows = FlowEngine.get_seed_telemetry(self.current_facility)
        self.switch_ports = SwitchInterrogator.generate_switch_port_telemetry(self.current_facility)
        self.unmanaged_switches = []

        # Resolve Layer 1 physical links deterministically
        switches = [a for a in self.assets.values() if "Switch" in a.device_type.value]
        endpoints = [a for a in self.assets.values() if "Switch" not in a.device_type.value]
        SwitchInterrogator.resolve_physical_links(switches, endpoints, self.switch_ports)

        self.save_to_disk()

    # Asset Operations
    def list_assets(
        self,
        facility: Optional[str] = None,
        purdue_level: Optional[str] = None,
        vendor: Optional[str] = None,
        query: Optional[str] = None
    ) -> List[Asset]:
        results = list(self.assets.values())
        if facility:
            results = [a for a in results if a.facility.lower() == facility.lower()]
        if purdue_level:
            results = [a for a in results if a.purdue_level.value == purdue_level or purdue_level in a.purdue_level.value]
        if vendor:
            results = [a for a in results if vendor.lower() in a.vendor.lower()]
        if query:
            q = query.lower()
            results = [
                a for a in results if
                q in a.tag_name.lower() or
                q in a.display_name.lower() or
                q in a.model.lower() or
                q in a.vendor.lower() or
                (a.catalog_number and q in a.catalog_number.lower())
            ]
        return results

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        return self.assets.get(asset_id)

    def save_asset(self, asset: Asset) -> Asset:
        self.assets[asset.id] = asset
        self.save_to_disk()
        return asset

    def delete_asset(self, asset_id: str) -> bool:
        if asset_id in self.assets:
            del self.assets[asset_id]
            # Remove from zones
            for z in self.zones.values():
                if asset_id in z.asset_ids:
                    z.asset_ids.remove(asset_id)
            self.save_to_disk()
            return True
        return False

    # Zones & Conduits
    def list_zones(self) -> List[PurdueZone]:
        return list(self.zones.values())

    def get_zone(self, zone_id: str) -> Optional[PurdueZone]:
        return self.zones.get(zone_id)

    def list_conduits(self) -> List[Conduit]:
        return list(self.conduits.values())

    def list_violations(self) -> List[SecurityViolation]:
        return list(self.violations.values())

    # Advisories & Vulnerabilities
    def list_advisories(self) -> List[ICSAdvisory]:
        return list(self.advisories.values())

    def get_advisory(self, advisory_id: str) -> Optional[ICSAdvisory]:
        return self.advisories.get(advisory_id)

    def get_compensating_controls(self, asset_id: str) -> List[CompensatingControl]:
        return self.applied_compensating_controls.get(asset_id, [])

    def add_compensating_control(self, asset_id: str, control: CompensatingControl):
        if asset_id not in self.applied_compensating_controls:
            self.applied_compensating_controls[asset_id] = []
        # Check if already exists
        existing = [c for c in self.applied_compensating_controls[asset_id] if c.id == control.id]
        if not existing:
            self.applied_compensating_controls[asset_id].append(control)
        self.save_to_disk()

    def remove_compensating_control(self, asset_id: str, control_id: str):
        if asset_id in self.applied_compensating_controls:
            self.applied_compensating_controls[asset_id] = [
                c for c in self.applied_compensating_controls[asset_id] if c.id != control_id
            ]
            self.save_to_disk()

    # Network Context Operations
    def get_topology_perspective(self, perspective: LayoutPerspective) -> TopologyPerspectiveData:
        return KandinskyLayoutEngine.generate_perspective(
            perspective=perspective,
            assets=list(self.assets.values()),
            zones=list(self.zones.values()),
            conduits=list(self.conduits.values()),
            locations=self.location_tree,
            unmanaged_switches=self.unmanaged_switches
        )

    def add_unmanaged_switch(self, switch_data: Dict[str, Any]) -> Dict[str, Any]:
        self.unmanaged_switches.append(switch_data)
        self.save_to_disk()
        return switch_data

    def get_sankey_data(self) -> Dict[str, Any]:
        return FlowEngine.generate_sankey_data(self.flows, list(self.assets.values()))

    def get_duplicate_ips(self) -> Dict[str, Any]:
        return LocationEngine.disambiguate_duplicate_ips(list(self.assets.values()))

    def ingest_pid(self, payload: PIDPayload) -> Dict[str, Any]:
        imported_assets = []
        for arp in payload.arp_entries:
            matched = None
            for a in self.assets.values():
                for iface in a.network_interfaces:
                    if iface.mac_address.upper() == arp.mac_address.upper():
                        matched = a
                        iface.ip_address = arp.ip_address
                        break
            if not matched:
                import uuid
                from otbase.models.asset import DeviceType, PurdueLevel, Criticality, NetworkInterface
                new_a = Asset(
                    id=f"AST-PID-{uuid.uuid4().hex[:6].upper()}",
                    tag_name=arp.hostname or f"LIVE-DEV-{arp.ip_address.split('.')[-1]}",
                    display_name=f"Discovered {arp.oui_vendor or 'Industrial'} Device",
                    vendor=arp.oui_vendor or "Industrial Equipment",
                    model="Ethernet Field Device",
                    device_type=DeviceType.FIELD_DEVICE,
                    purdue_level=PurdueLevel.LEVEL_1,
                    facility=self.current_facility,
                    location_id=payload.metadata.location_id,
                    location_path=payload.metadata.location_path,
                    criticality=Criticality.HIGH,
                    network_interfaces=[
                        NetworkInterface(
                            mac_address=arp.mac_address,
                            ip_address=arp.ip_address
                        )
                    ]
                )
                self.save_asset(new_a)
                imported_assets.append(new_a.tag_name)

        for sp in payload.switch_ports:
            self.switch_ports.append(sp)

        for f in payload.flow_telemetry:
            self.flows.append(f)

        # Re-resolve physical links
        switches = [a for a in self.assets.values() if "Switch" in a.device_type.value]
        endpoints = [a for a in self.assets.values() if "Switch" not in a.device_type.value]
        SwitchInterrogator.resolve_physical_links(switches, endpoints, self.switch_ports)

        self.save_to_disk()
        return {
            "status": "success",
            "probe_id": payload.metadata.probe_id,
            "new_assets_created": len(imported_assets),
            "assets": imported_assets,
            "flows_ingested": len(payload.flow_telemetry),
            "switch_ports_ingested": len(payload.switch_ports)
        }

    # Armis Ingestion & Reconciliation
    def sync_armis(
        self,
        tenant_url: Optional[str] = None,
        api_secret_key: Optional[str] = None,
        simulate: bool = True,
        aql: str = "in:devices",
    ) -> Dict[str, Any]:
        """Runs Armis device & connection extraction and performs reconciliation."""
        connector = ArmisConnector(
            tenant_url=tenant_url,
            api_secret_key=api_secret_key,
            simulate=simulate,
        )
        self.armis_devices = connector.get_devices(aql=aql)
        self.armis_connections = connector.get_connections()

        # Execute reconciliation against active assets
        engine = ReconciliationEngine()
        self.latest_reconciliation = engine.reconcile(self.armis_devices, list(self.assets.values()))

        self.save_to_disk()
        return {
            "status": "success",
            "devices_discovered": len(self.armis_devices),
            "connections_discovered": len(self.armis_connections),
            "correlated_assets": self.latest_reconciliation.correlated_assets_count,
            "rogue_assets": self.latest_reconciliation.rogue_assets_count,
            "dormant_assets": self.latest_reconciliation.dormant_assets_count,
            "discrepancies_count": len(self.latest_reconciliation.discrepancies),
        }

    def get_reconciliation_report(self) -> ReconciliationReport:
        """Retrieves or executes the latest Armis ground-truth reconciliation report."""
        if self.latest_reconciliation is None:
            if not self.armis_devices:
                self.sync_armis(simulate=True)
            else:
                engine = ReconciliationEngine()
                self.latest_reconciliation = engine.reconcile(self.armis_devices, list(self.assets.values()))
        return self.latest_reconciliation

    def ingest_armis_connections_to_flows(self) -> int:
        """Ingests Armis network connection records into FlowEngine telemetry."""
        if not self.armis_connections:
            connector = ArmisConnector(simulate=True)
            self.armis_connections = connector.get_connections()

        new_flows_count = 0
        for conn in self.armis_connections:
            existing = any(
                f.src_ip == conn.source_ip
                and f.dst_ip == conn.destination_ip
                and f.dst_port == conn.destination_port
                for f in self.flows
            )
            if not existing:
                flow_rec = FlowTelemetryRecord(
                    src_ip=conn.source_ip,
                    dst_ip=conn.destination_ip,
                    src_port=conn.source_port,
                    dst_port=conn.destination_port,
                    protocol=conn.protocol,
                    byte_count=conn.byte_count,
                    packet_count=conn.packet_count,
                    sampling_ratio=128,
                    first_switched=conn.start_time,
                    last_switched=conn.last_activity,
                )
                self.flows.append(flow_rec)
                new_flows_count += 1

        self.save_to_disk()
        return new_flows_count

    # Serialization
    def save_to_disk(self):
        data = {
            "current_facility": self.current_facility,
            "assets": [a.model_dump(mode="json") for a in self.assets.values()],
            "zones": [z.model_dump(mode="json") for z in self.zones.values()],
            "conduits": [c.model_dump(mode="json") for c in self.conduits.values()],
            "violations": [v.model_dump(mode="json") for v in self.violations.values()],
            "advisories": [adv.model_dump(mode="json") for adv in self.advisories.values()],
            "applied_compensating_controls": {
                k: [c.model_dump(mode="json") for c in v] for k, v in self.applied_compensating_controls.items()
            },
            "location_tree": [l.model_dump(mode="json") for l in self.location_tree],
            "systems": [s.model_dump(mode="json") for s in self.systems],
            "flows": [f.model_dump(mode="json") for f in self.flows],
            "switch_ports": [sp.model_dump(mode="json") for sp in self.switch_ports],
            "unmanaged_switches": self.unmanaged_switches,
            "armis_devices": [d.model_dump(mode="json") for d in self.armis_devices],
            "armis_connections": [c.model_dump(mode="json") for c in self.armis_connections],
            "latest_reconciliation": self.latest_reconciliation.model_dump(mode="json") if self.latest_reconciliation else None,
        }
        with open(self.db_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def load_from_disk(self):
        with open(self.db_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.current_facility = data.get("current_facility", "Municipal Water Treatment Facility")
        self.assets = {item["id"]: Asset.model_validate(item) for item in data.get("assets", [])}
        self.zones = {item["id"]: PurdueZone.model_validate(item) for item in data.get("zones", [])}
        self.conduits = {item["id"]: Conduit.model_validate(item) for item in data.get("conduits", [])}
        self.violations = {item["id"]: SecurityViolation.model_validate(item) for item in data.get("violations", [])}
        self.advisories = {item["advisory_id"]: ICSAdvisory.model_validate(item) for item in data.get("advisories", [])}
        self.applied_compensating_controls = {
            k: [CompensatingControl.model_validate(c) for c in v]
            for k, v in data.get("applied_compensating_controls", {}).items()
        }
        self.lifecycle_milestones = get_lifecycle_milestones()
        self.location_tree = [LocationNode.model_validate(item) for item in data.get("location_tree", [])] or LocationEngine.get_seed_location_tree(self.current_facility)
        self.systems = [OTSystem.model_validate(item) for item in data.get("systems", [])] or LocationEngine.get_seed_systems(self.current_facility, list(self.assets.values()))
        self.flows = [FlowTelemetryRecord.model_validate(item) for item in data.get("flows", [])] or FlowEngine.get_seed_telemetry(self.current_facility)
        self.switch_ports = [SwitchPortDiscovery.model_validate(item) for item in data.get("switch_ports", [])] or SwitchInterrogator.generate_switch_port_telemetry(self.current_facility)
        self.unmanaged_switches = data.get("unmanaged_switches", [])
        self.armis_devices = [ArmisDeviceRecord.model_validate(item) for item in data.get("armis_devices", [])]
        self.armis_connections = [ArmisConnectionRecord.model_validate(item) for item in data.get("armis_connections", [])]
        recon_data = data.get("latest_reconciliation")
        self.latest_reconciliation = ReconciliationReport.model_validate(recon_data) if recon_data else None

# Singleton repo instance
repo = OTBaseRepository()

