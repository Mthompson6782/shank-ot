import random
import uuid
from typing import List, Dict, Any
from otbase.models.asset import (
    Asset, Chassis, RackModule, NetworkInterface, SerialPort,
    DeviceType, PurdueLevel, Criticality, KeySwitchMode, ModuleType,
    LEDStatus, LEDColor
)

class OTProbeSimulator:
    """
    Simulates non-intrusive OT network discovery (Passive Sniffing & Safe CIP/S7comm/Modbus queries).
    Safely captures broadcast announcements (PROFINET DCP, CIP ListIdentity, ARP/LLDP)
    without sending dangerous IT TCP port scans that could trip legacy PLCs.
    """

    SAMPLE_DISCOVERIES = [
        {
            "tag": "PLC-BOOSTER-03",
            "name": "High-Lift Distribution Booster Pump Controller",
            "vendor": "Schneider Electric",
            "model": "Modicon M580 ePAC",
            "catalog": "BMEP584040",
            "firmware": "3.20",
            "protocol": "Modbus TCP / EtherNet/IP",
            "ip": "192.168.10.45",
            "mac": "00:80:F4:9A:31:02",
            "level": PurdueLevel.LEVEL_1,
            "type": DeviceType.PLC,
            "chassis_modules": [
                ("Power Supply 24V DC", "BMXCPS3020", ModuleType.POWER_SUPPLY, "1.00"),
                ("M580 Standalone CPU 4040", "BMEP584040", ModuleType.CONTROLLER, "3.20"),
                ("Ethernet Network Module", "BMENOC0301", ModuleType.COMM_ADAPTER, "2.14"),
                ("Discrete Input 32-ch 24VDC", "BMXDDI3202K", ModuleType.DIGITAL_INPUT, "1.01"),
                ("Discrete Output 32-ch 24VDC", "BMXDDO3202K", ModuleType.DIGITAL_OUTPUT, "1.01"),
            ]
        },
        {
            "tag": "VFD-PUMP-101",
            "name": "Intake Well 1 Variable Frequency Drive",
            "vendor": "ABB",
            "model": "ACS880 Industrial Drive",
            "catalog": "ACS880-01-105A-3",
            "firmware": "2.81",
            "protocol": "EtherNet/IP (FENA-21)",
            "ip": "192.168.10.160",
            "mac": "00:0C:02:11:88:99",
            "level": PurdueLevel.LEVEL_1,
            "type": DeviceType.FIELD_DEVICE,
            "chassis_modules": []
        },
        {
            "tag": "HMI-PANELVIEW-02",
            "name": "Chemical Dosing Local Touchscreen PanelView",
            "vendor": "Rockwell Automation",
            "model": "PanelView Plus 7 Performance",
            "catalog": "2711P-T15C22D9P",
            "firmware": "12.001",
            "protocol": "CIP / EtherNet/IP",
            "ip": "192.168.20.25",
            "mac": "00:1D:9C:33:90:55",
            "level": PurdueLevel.LEVEL_2,
            "type": DeviceType.HMI,
            "chassis_modules": []
        },
        {
            "tag": "SW-RING-02",
            "name": "Field Switch Turbo Ring Redundant Switch",
            "vendor": "Moxa",
            "model": "EDS-510E Managed Ethernet Switch",
            "catalog": "EDS-510E-3GTD",
            "firmware": "V5.2",
            "protocol": "PROFINET / Turbo Ring / SNMPv3",
            "ip": "192.168.20.8",
            "mac": "00:90:E8:4A:21:77",
            "level": PurdueLevel.LEVEL_2,
            "type": DeviceType.INDUSTRIAL_SWITCH,
            "chassis_modules": []
        }
    ]

    @classmethod
    def run_safe_discovery_sweep(cls, facility: str = "Municipal Water Treatment Facility") -> List[Asset]:
        """Runs a safe simulation sweep, discovering one or more previously uninventoried OT assets."""
        discovered: List[Asset] = []
        selected_samples = random.sample(cls.SAMPLE_DISCOVERIES, k=min(2, len(cls.SAMPLE_DISCOVERIES)))

        for s in selected_samples:
            chassis = None
            if s["chassis_modules"]:
                mods = []
                for slot_idx, (m_name, m_cat, m_type, m_fw) in enumerate(s["chassis_modules"]):
                    mods.append(
                        RackModule(
                            slot=slot_idx,
                            name=m_name,
                            catalog_number=m_cat,
                            serial_number=f"SN-{uuid.uuid4().hex[:8].upper()}",
                            hardware_revision="02",
                            firmware_version=m_fw,
                            vendor=s["vendor"],
                            module_type=m_type,
                            status_leds=[LEDStatus(name="RUN", state=LEDColor.GREEN)],
                            description=f"Discovered {m_name}"
                        )
                    )
                chassis = Chassis(
                    model=f"{s['vendor']} Backplane ({len(mods)} Slots)",
                    serial_number=f"CH-{uuid.uuid4().hex[:6].upper()}",
                    total_slots=len(mods) + 2,
                    modules=mods
                )

            asset = Asset(
                id=f"disc-{uuid.uuid4().hex[:8]}",
                tag_name=s["tag"],
                display_name=s["name"],
                vendor=s["vendor"],
                model=s["model"],
                catalog_number=s["catalog"],
                serial_number=f"SN-{uuid.uuid4().hex[:8].upper()}",
                firmware_version=s["firmware"],
                os_name=f"{s['vendor']} Embedded OS",
                os_version=s["firmware"],
                device_type=s["type"],
                purdue_level=s["level"],
                facility=facility,
                area="Active Plant Network",
                criticality=Criticality.HIGH,
                key_switch=KeySwitchMode.RUN if s["type"] == DeviceType.PLC else KeySwitchMode.NOT_APPLICABLE,
                chassis=chassis,
                network_interfaces=[
                    NetworkInterface(
                        name="eth0 (Discovered via PROFINET/CIP Broadcast)",
                        mac_address=s["mac"],
                        ip_address=s["ip"],
                        subnet_mask="255.255.255.0",
                        gateway="192.168.10.1"
                    )
                ],
                notes=f"Discovered passively via non-intrusive {s['protocol']} probe."
            )
            discovered.append(asset)

        return discovered
