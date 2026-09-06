import csv
import io
import json
from typing import List, Dict, Any
from otbase.models.asset import Asset

class HBOMExporter:
    """Exports Hardware Bill of Materials (HBOM) and Software Bill of Materials (SBOM)."""

    @classmethod
    def generate_hbom_json(cls, assets: List[Asset]) -> Dict[str, Any]:
        items = []
        for a in assets:
            entry = {
                "asset_tag": a.tag_name,
                "display_name": a.display_name,
                "vendor": a.vendor,
                "model": a.model,
                "catalog_number": a.catalog_number,
                "serial_number": a.serial_number,
                "hardware_revision": a.hardware_revision,
                "firmware_version": a.firmware_version,
                "purdue_level": a.purdue_level.value,
                "facility": a.facility,
                "area": a.area,
                "criticality": a.criticality.value,
                "key_switch": a.key_switch.value,
                "rack_slots": []
            }
            if a.chassis:
                for mod in a.chassis.modules:
                    entry["rack_slots"].append({
                        "slot": mod.slot,
                        "name": mod.name,
                        "catalog_number": mod.catalog_number,
                        "serial_number": mod.serial_number,
                        "hardware_revision": mod.hardware_revision,
                        "firmware_version": mod.firmware_version,
                        "module_type": mod.module_type.value,
                        "cves": mod.cves
                    })
            items.append(entry)

        return {
            "bom_format": "OT-BASE Hardware Bill of Materials (HBOM)",
            "version": "1.0",
            "total_parent_assets": len(assets),
            "items": items
        }

    @classmethod
    def generate_hbom_csv(cls, assets: List[Asset]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Asset Tag", "Asset Name", "Purdue Level", "Slot", "Component / Module",
            "Vendor", "Catalog Number", "Serial Number", "HW Rev", "FW Version", "Criticality", "CVEs"
        ])

        for a in assets:
            # Write parent device
            writer.writerow([
                a.tag_name, a.display_name, a.purdue_level.value, "Chassis / Main", a.model,
                a.vendor, a.catalog_number or "N/A", a.serial_number or "N/A",
                a.hardware_revision or "N/A", a.firmware_version or "N/A",
                a.criticality.value, "; ".join(a.active_cves)
            ])
            # Write sub-modules if modular rack
            if a.chassis:
                for mod in a.chassis.modules:
                    writer.writerow([
                        a.tag_name, a.display_name, a.purdue_level.value, f"Slot {mod.slot}", mod.name,
                        mod.vendor, mod.catalog_number, mod.serial_number or "N/A",
                        mod.hardware_revision or "N/A", mod.firmware_version or "N/A",
                        a.criticality.value, "; ".join(mod.cves)
                    ])

        return output.getvalue()
