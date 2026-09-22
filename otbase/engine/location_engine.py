from typing import List, Dict, Any, Optional, Tuple
from otbase.models.asset import Asset
from otbase.models.location_tree import LocationNode, LocationTier, OTSystem
from otbase.models.pid_schema import FlowTelemetryRecord

class LocationEngine:
    """
    Manages Location Trees, enforces strict Location ID data bindings,
    disambiguates duplicate IP spaces, and manages functional OT Systems profiles.
    
    Location Tree Hierarchy:
    Enterprise -> Site -> Building -> Control Room -> Cabinet / Skid
    """

    @classmethod
    def get_seed_location_tree(cls, facility: str) -> List[LocationNode]:
        """Generates default 5-tier location tree for the active facility."""
        nodes: List[LocationNode] = [
            LocationNode(
                id="loc-ent-01",
                name="Global Water Utilities Corp",
                tier=LocationTier.ENTERPRISE,
                facility=facility,
                description="Enterprise Corporate Level"
            ),
            LocationNode(
                id="loc-site-01",
                name=facility,
                tier=LocationTier.SITE,
                parent_id="loc-ent-01",
                facility=facility,
                description="Regional Production Facility"
            ),
            LocationNode(
                id="loc-bld-01",
                name="Filtration & Chemical Treatment Building",
                tier=LocationTier.BUILDING,
                parent_id="loc-site-01",
                facility=facility
            ),
            LocationNode(
                id="loc-room-01",
                name="Main Supervisory Control Room",
                tier=LocationTier.CONTROL_ROOM,
                parent_id="loc-bld-01",
                facility=facility
            ),
            LocationNode(
                id="loc-skid-01",
                name="Skid 1 - Coagulation & Chemical Dosing",
                tier=LocationTier.CABINET_SKID,
                parent_id="loc-room-01",
                facility=facility,
                metadata={"duplicate_subnet_enabled": True, "subnet": "192.168.1.0/24"}
            ),
            LocationNode(
                id="loc-skid-02",
                name="Skid 2 - Flocculation & Polymer Dosing (OEM Duplicate)",
                tier=LocationTier.CABINET_SKID,
                parent_id="loc-room-01",
                facility=facility,
                metadata={"duplicate_subnet_enabled": True, "subnet": "192.168.1.0/24"}
            )
        ]
        return nodes

    @classmethod
    def disambiguate_duplicate_ips(cls, assets: List[Asset]) -> Dict[str, Any]:
        """
        Disambiguates duplicate IPv4 address spaces across modular skids.
        Groups assets by IP address. If an IP appears under multiple Location IDs,
        treats them as distinct assets within isolated location namespaces.
        """
        ip_map: Dict[str, List[Asset]] = {}
        for a in assets:
            for iface in a.network_interfaces:
                if iface.ip_address:
                    if iface.ip_address not in ip_map:
                        ip_map[iface.ip_address] = []
                    ip_map[iface.ip_address].append(a)

        duplicate_clusters = []
        for ip, asset_list in ip_map.items():
            if len(asset_list) > 1:
                duplicate_clusters.append({
                    "ip_address": ip,
                    "collision_count": len(asset_list),
                    "assets": [
                        {
                            "id": a.id,
                            "tag": a.tag_name,
                            "location_id": a.location_id or "Unassigned",
                            "location_path": a.location_path or a.area,
                            "facility": a.facility,
                            "is_distinct_skid": True
                        }
                        for a in asset_list
                    ],
                    "status": "Isolated by Location ID Binding (No Data Overwrite)"
                })

        return {
            "total_duplicate_ips_tracked": len(duplicate_clusters),
            "duplicate_subnets": duplicate_clusters
        }

    @classmethod
    def get_seed_systems(cls, facility: str, assets: List[Asset]) -> List[OTSystem]:
        """
        Defines functional OT Systems grouping controllers, HMIs, drives, and network switches.
        """
        systems = [
            OTSystem(
                id="sys-coag-01",
                name="Primary Coagulation & Filtration System",
                description="Controls intake mixing and chemical coagulant addition.",
                facility=facility,
                primary_controller_id="PLC-01-MAIN",
                asset_ids=["PLC-01-MAIN", "HMI-OPERATOR-01", "SW-CORE-01"],
                shared_switch_ids=["SW-CORE-01"],
                process_criticality="High",
                total_bandwidth_kbps=18400.0
            ),
            OTSystem(
                id="sys-chem-02",
                name="Secondary Chemical Disinfection Skid",
                description="Modular OEM skid dosing sodium hypochlorite.",
                facility=facility,
                primary_controller_id="PLC-02-CHEM",
                asset_ids=["PLC-02-CHEM", "SW-CORE-01"],
                shared_switch_ids=["SW-CORE-01"],
                process_criticality="High",
                total_bandwidth_kbps=9200.0
            )
        ]
        return systems

    @classmethod
    def find_shared_trunk_switches(cls, systems: List[OTSystem]) -> List[Dict[str, Any]]:
        """
        Identifies managed switches that serve multiple distinct functional systems.
        Shared switching infrastructure introduces shared operational risk.
        """
        switch_usage: Dict[str, List[str]] = {}
        for sys in systems:
            for sw_id in sys.shared_switch_ids:
                if sw_id not in switch_usage:
                    switch_usage[sw_id] = []
                switch_usage[sw_id].append(sys.name)

        shared_switches = []
        for sw_id, sys_names in switch_usage.items():
            if len(sys_names) > 1:
                shared_switches.append({
                    "switch_id": sw_id,
                    "serving_systems": sys_names,
                    "shared_risk_warning": (
                        f"Switch '{sw_id}' serves multiple independent operational systems: "
                        f"{', '.join(sys_names)}. A switch outage or firmware reboot will compromise multiple control loops."
                    )
                })

        return shared_switches
