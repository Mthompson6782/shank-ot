import json
import os
from typing import List, Optional, Dict, Any
from pathlib import Path
from otbase.config import settings
from otbase.models.asset import Asset, Chassis, RackModule, PurdueLevel, Criticality
from otbase.models.topology import PurdueZone, Conduit, SecurityViolation
from otbase.models.vulnerability import (
    ICSAdvisory, VulnerabilityMatch, CompensatingControl, CompensatingControlType
)
from otbase.models.lifecycle import LifecycleMilestone, ObsolescenceRisk
from otbase.db.seed_data import (
    get_water_treatment_assets, get_substation_assets, get_refinery_assets,
    get_purdue_zones, get_conduits, get_security_violations,
    get_ics_advisories, get_lifecycle_milestones
)

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
            }
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

# Singleton repo instance
repo = OTBaseRepository()
