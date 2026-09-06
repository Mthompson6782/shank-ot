import xml.etree.ElementTree as ET
import uuid
from typing import Optional, Dict, Any, List
from otbase.models.asset import (
    Asset, Chassis, RackModule, NetworkInterface, DeviceType,
    PurdueLevel, Criticality, KeySwitchMode, ModuleType, LEDStatus, LEDColor
)

class RockwellL5XParser:
    """
    Parses Rockwell Automation Studio 5000 / RSLogix 5000 .L5X XML configuration exports.
    Extracts Controller metadata, backplane chassis, modules in each slot, and firmware revisions.
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
        # Controller node
        controller_node = root.find(".//Controller")
        if controller_node is None:
            controller_node = root if root.tag == "Controller" else None

        controller_name = controller_node.get("Name", "ControlLogix_PLC") if controller_node is not None else "Rockwell_PLC"
        processor_type = controller_node.get("ProcessorType", "1756-L83E") if controller_node is not None else "1756-L83E"
        major_rev = controller_node.get("MajorRev", "33") if controller_node is not None else "33"
        minor_rev = controller_node.get("MinorRev", "011") if controller_node is not None else "011"
        firmware_ver = f"{major_rev}.{minor_rev}"

        # Parse Modules in the backplane
        modules: List[RackModule] = []
        modules_node = root.find(".//Modules")
        max_slot = 7

        if modules_node is not None:
            for mod_elem in modules_node.findall("Module"):
                mod_name = mod_elem.get("Name", "Module")
                cat_num = mod_elem.get("CatalogNumber", "Unknown")
                slot_str = mod_elem.get("Slot", "0")
                try:
                    slot = int(slot_str)
                except ValueError:
                    slot = len(modules)

                if slot > max_slot:
                    max_slot = slot

                rev_maj = mod_elem.get("Major", "1")
                rev_min = mod_elem.get("Minor", "0")
                mod_firmware = f"{rev_maj}.{rev_min}"

                # Infer module type from catalog number
                mod_type = cls._infer_module_type(cat_num)

                modules.append(
                    RackModule(
                        slot=slot,
                        name=f"{cat_num} ({mod_name})",
                        catalog_number=cat_num,
                        serial_number=f"SN-{uuid.uuid4().hex[:8].upper()}",
                        hardware_revision="B",
                        firmware_version=mod_firmware,
                        vendor="Rockwell Automation",
                        module_type=mod_type,
                        status_leds=[
                            LEDStatus(name="OK", state=LEDColor.GREEN),
                            LEDStatus(name="RUN", state=LEDColor.GREEN if slot == 0 or slot == 1 else LEDColor.OFF)
                        ],
                        description=f"Parsed from L5X Project Module: {mod_name}"
                    )
                )

        # Sort modules by slot
        modules.sort(key=lambda m: m.slot)

        # If no modules explicitly parsed, add a default controller module
        if not modules:
            modules.append(
                RackModule(
                    slot=0,
                    name=f"{processor_type} Main Controller",
                    catalog_number=processor_type,
                    serial_number=f"SN-{uuid.uuid4().hex[:8].upper()}",
                    hardware_revision="A",
                    firmware_version=firmware_ver,
                    vendor="Rockwell Automation",
                    module_type=ModuleType.CONTROLLER,
                    status_leds=[LEDStatus(name="OK", state=LEDColor.GREEN)],
                    description="Primary ControlLogix CPU"
                )
            )

        chassis = Chassis(
            model=f"1756-A{max(10, max_slot + 1)} {max(10, max_slot + 1)}-Slot Chassis",
            serial_number=f"CH-L5X-{uuid.uuid4().hex[:6].upper()}",
            total_slots=max(10, max_slot + 1),
            modules=modules
        )

        asset_id = f"l5x-{uuid.uuid4().hex[:8]}"
        return Asset(
            id=asset_id,
            tag_name=controller_name,
            display_name=f"{controller_name} ({processor_type})",
            vendor="Rockwell Automation",
            model=processor_type,
            catalog_number=processor_type,
            firmware_version=firmware_ver,
            os_name="Logix Firmware RTOS",
            os_version=firmware_ver,
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            facility=facility,
            area="Imported Area",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.REMOTE_RUN,
            chassis=chassis,
            network_interfaces=[
                NetworkInterface(
                    name="EtherNet/IP Interface",
                    mac_address=f"00:1D:9C:{uuid.uuid4().hex[:2].upper()}:{uuid.uuid4().hex[:2].upper()}:{uuid.uuid4().hex[:2].upper()}",
                    ip_address="192.168.10.75",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            notes="Ingested from Rockwell Studio 5000 .L5X project file."
        )

    @classmethod
    def _infer_module_type(cls, cat_num: str) -> ModuleType:
        c = cat_num.upper()
        if "PA" in c or "PB" in c or "POWER" in c:
            return ModuleType.POWER_SUPPLY
        elif "L8" in c or "L7" in c or "L6" in c or "CPU" in c or "5580" in c or "5570" in c:
            return ModuleType.CONTROLLER
        elif "EN2" in c or "EN3" in c or "ENBT" in c or "COMM" in c or "CNBR" in c or "DNB" in c:
            return ModuleType.COMM_ADAPTER
        elif "IB" in c or "IA" in c or "DI" in c:
            return ModuleType.DIGITAL_INPUT
        elif "OB" in c or "OA" in c or "OW" in c or "DO" in c:
            return ModuleType.DIGITAL_OUTPUT
        elif "IF" in c or "IR" in c or "AI" in c:
            return ModuleType.ANALOG_INPUT
        elif "OF" in c or "AO" in c:
            return ModuleType.ANALOG_OUTPUT
        elif "GUARD" in c or "SAFETY" in c or "L8SP" in c:
            return ModuleType.SAFETY_PARTNER
        return ModuleType.SPECIALTY
