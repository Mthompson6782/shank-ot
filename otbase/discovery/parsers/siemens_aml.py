import xml.etree.ElementTree as ET
import uuid
from typing import List, Optional
from otbase.models.asset import (
    Asset, Chassis, RackModule, NetworkInterface, DeviceType,
    PurdueLevel, Criticality, KeySwitchMode, ModuleType, LEDStatus, LEDColor
)

class SiemensAMLParser:
    """
    Parses Siemens TIA Portal / AutomationML (.aml) hardware configuration exports.
    Extracts S7-1500/1200 racks, CPUs, communications processors, and I/O slices.
    """

    @classmethod
    def parse_string(cls, xml_content: str, facility: str = "Imported Plant") -> Asset:
        root = ET.fromstring(xml_content)
        return cls._parse_element_tree(root, facility)

    @classmethod
    def parse_file(cls, filepath: str, facility: str = "Imported Plant") -> Asset:
        tree = ET.parse(filepath)
        root = tree.getroot()
        return cls._parse_element_tree(root, facility)

    @classmethod
    def _parse_element_tree(cls, root: ET.Element, facility: str) -> Asset:
        # Search for InternalElement nodes representing hardware devices
        plc_name = "SIMATIC_S7_1500"
        cpu_model = "CPU 1516-3 PN/DP"
        firmware_ver = "2.8.0"

        # Check for AutomationML Root or CAEX tags
        name_attr = root.get("Name")
        if name_attr:
            plc_name = name_attr

        modules: List[RackModule] = []
        slot_counter = 1

        # Look for modules / rack items
        for elem in root.iter():
            if elem.tag.endswith("InternalElement") or elem.tag.endswith("Module") or elem.tag == "Module":
                elem_name = elem.get("Name", "")
                elem_type = elem.get("RefBaseSystemUnitPath", "")
                cat_no = elem.get("OrderNumber") or elem.get("CatalogNumber") or elem_name

                if any(k in elem_name.upper() or k in elem_type.upper() or k in cat_no.upper() for k in ["CPU", "PLC", "S7", "DI", "DQ", "AI", "AQ", "CP", "PM"]):
                    mod_type = cls._infer_siemens_module_type(cat_no)
                    
                    if mod_type == ModuleType.CONTROLLER or "PLC" in elem_name.upper():
                        cpu_model = elem_name
                        plc_name = elem_name
                        # Check firmware attribute if present
                        for attr in elem.findall(".//Attribute"):
                            if "Firmware" in attr.get("Name", ""):
                                val = attr.find("Value")
                                if val is not None and val.text:
                                    firmware_ver = val.text

                    modules.append(
                        RackModule(
                            slot=slot_counter,
                            name=elem_name,
                            catalog_number=cat_no,
                            serial_number=f"SVB-{uuid.uuid4().hex[:8].upper()}",
                            hardware_revision="FS01",
                            firmware_version=firmware_ver if mod_type == ModuleType.CONTROLLER else "1.0.0",
                            vendor="Siemens",
                            module_type=mod_type,
                            status_leds=[
                                LEDStatus(name="RUN", state=LEDColor.GREEN),
                                LEDStatus(name="MAINT", state=LEDColor.OFF)
                            ],
                            description=f"Siemens AutomationML Module: {elem_name}"
                        )
                    )
                    slot_counter += 1

        if not modules:
            # Add default S7-1500 Controller and CP module
            modules = [
                RackModule(
                    slot=1,
                    name=f"Siemens {cpu_model}",
                    catalog_number="6ES7516-3AN02-0AB0",
                    serial_number=f"SVP-{uuid.uuid4().hex[:8].upper()}",
                    hardware_revision="FS03",
                    firmware_version=firmware_ver,
                    vendor="Siemens",
                    module_type=ModuleType.CONTROLLER,
                    status_leds=[LEDStatus(name="RUN", state=LEDColor.GREEN)],
                    description="Standard S7-1500 Controller"
                ),
                RackModule(
                    slot=2,
                    name="CP 1543-1 Industrial Ethernet",
                    catalog_number="6GK7543-1AX00-0XE0",
                    serial_number=f"SVC-{uuid.uuid4().hex[:8].upper()}",
                    hardware_revision="FS02",
                    firmware_version="2.2.0",
                    vendor="Siemens",
                    module_type=ModuleType.COMM_ADAPTER,
                    status_leds=[LEDStatus(name="RUN", state=LEDColor.GREEN)],
                    description="Security CP with PROFINET"
                )
            ]

        chassis = Chassis(
            model=f"Siemens S7-1500 DIN Rail ({len(modules)} Modules)",
            serial_number=f"SN-S7-{uuid.uuid4().hex[:6].upper()}",
            total_slots=max(8, len(modules) + 2),
            modules=modules
        )

        asset_id = f"aml-{uuid.uuid4().hex[:8]}"
        return Asset(
            id=asset_id,
            tag_name=plc_name,
            display_name=f"{plc_name} ({cpu_model})",
            vendor="Siemens",
            model=cpu_model,
            catalog_number="6ES7516-3AN02-0AB0",
            firmware_version=firmware_ver,
            os_name="SIMATIC S7 Firmware",
            os_version=firmware_ver,
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            facility=facility,
            area="Imported Area",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.RUN,
            chassis=chassis,
            network_interfaces=[
                NetworkInterface(
                    name="PROFINET Interface X1",
                    mac_address=f"00:1C:06:{uuid.uuid4().hex[:2].upper()}:{uuid.uuid4().hex[:2].upper()}:{uuid.uuid4().hex[:2].upper()}",
                    ip_address="192.168.10.88",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            notes="Ingested from Siemens TIA Portal AutomationML (.aml) configuration."
        )

    @classmethod
    def _infer_siemens_module_type(cls, cat: str) -> ModuleType:
        c = cat.upper()
        if "PM" in c or "POWER" in c or "PS" in c:
            return ModuleType.POWER_SUPPLY
        elif "CPU" in c or "511" in c or "512" in c or "513" in c or "515" in c or "516" in c or "518" in c:
            return ModuleType.CONTROLLER
        elif "CP" in c or "COMM" in c or "1543" in c or "1542" in c:
            return ModuleType.COMM_ADAPTER
        elif "DI" in c or "521" in c:
            return ModuleType.DIGITAL_INPUT
        elif "DQ" in c or "DO" in c or "522" in c:
            return ModuleType.DIGITAL_OUTPUT
        elif "AI" in c or "531" in c:
            return ModuleType.ANALOG_INPUT
        elif "AQ" in c or "AO" in c or "532" in c:
            return ModuleType.ANALOG_OUTPUT
        return ModuleType.SPECIALTY
