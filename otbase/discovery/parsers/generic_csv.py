import csv
import io
import json
import uuid
from typing import List, Dict, Any, Optional
from otbase.models.asset import (
    Asset, NetworkInterface, DeviceType, PurdueLevel, Criticality, KeySwitchMode
)

class GenericAssetParser:
    """Parses bulk CSV or JSON asset inventory spreadsheets."""

    @classmethod
    def parse_csv(cls, csv_content: str, facility: str = "Imported Plant") -> List[Asset]:
        reader = csv.DictReader(io.StringIO(csv_content))
        assets: List[Asset] = []

        for row in reader:
            normalized = {k.strip().lower(): v.strip() for k, v in row.items() if k and v}
            tag = normalized.get("tag_name") or normalized.get("tag") or normalized.get("name") or f"ASSET-{uuid.uuid4().hex[:6].upper()}"
            vendor = normalized.get("vendor") or normalized.get("manufacturer") or "Generic OT Vendor"
            model = normalized.get("model") or normalized.get("part_number") or "Unknown Model"
            firmware = normalized.get("firmware_version") or normalized.get("firmware") or normalized.get("version") or "1.0.0"
            ip = normalized.get("ip_address") or normalized.get("ip") or "192.168.10.100"
            mac = normalized.get("mac_address") or normalized.get("mac") or f"00:11:22:{uuid.uuid4().hex[:2].upper()}:{uuid.uuid4().hex[:2].upper()}:{uuid.uuid4().hex[:2].upper()}"
            
            # Match Purdue Level
            plevel_str = normalized.get("purdue_level") or normalized.get("level") or "1"
            purdue = PurdueLevel.LEVEL_1
            if "0" in plevel_str:
                purdue = PurdueLevel.LEVEL_0
            elif "2" in plevel_str:
                purdue = PurdueLevel.LEVEL_2
            elif "3.5" in plevel_str:
                purdue = PurdueLevel.LEVEL_3_5
            elif "3" in plevel_str:
                purdue = PurdueLevel.LEVEL_3
            elif "4" in plevel_str:
                purdue = PurdueLevel.LEVEL_4

            # Match Device Type
            dtype_str = normalized.get("device_type") or normalized.get("type") or "PLC"
            dtype = DeviceType.PLC
            for dt in DeviceType:
                if dt.name.lower() in dtype_str.lower() or dtype_str.lower() in dt.value.lower():
                    dtype = dt
                    break

            asset = Asset(
                id=f"csv-{uuid.uuid4().hex[:8]}",
                tag_name=tag,
                display_name=f"{tag} ({vendor} {model})",
                vendor=vendor,
                model=model,
                firmware_version=firmware,
                device_type=dtype,
                purdue_level=purdue,
                facility=facility,
                area=normalized.get("area", "General Plant"),
                criticality=Criticality.HIGH,
                key_switch=KeySwitchMode.RUN,
                network_interfaces=[
                    NetworkInterface(
                        name="eth0",
                        mac_address=mac,
                        ip_address=ip,
                        subnet_mask="255.255.255.0",
                        gateway="192.168.10.1"
                    )
                ],
                notes="Imported via bulk CSV inventory table."
            )
            assets.append(asset)

        return assets

    @classmethod
    def parse_json(cls, json_content: str, facility: str = "Imported Plant") -> List[Asset]:
        data = json.loads(json_content)
        if isinstance(data, dict):
            data = data.get("assets", [data])

        assets = []
        for item in data:
            if "id" not in item:
                item["id"] = f"json-{uuid.uuid4().hex[:8]}"
            if "facility" not in item:
                item["facility"] = facility
            assets.append(Asset.model_validate(item))
        return assets
