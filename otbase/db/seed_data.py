import uuid
from typing import List, Dict, Any
from otbase.models.asset import (
    Asset, Chassis, RackModule, NetworkInterface, SerialPort,
    DeviceType, PurdueLevel, Criticality, KeySwitchMode, ModuleType,
    LEDStatus, LEDColor
)
from otbase.models.topology import (
    PurdueZone, Conduit, SecurityViolation, SecurityViolationType, ViolationSeverity
)
from otbase.models.vulnerability import (
    ICSAdvisory, VulnerabilityMatch, CompensatingControl, CompensatingControlType, CVSSSeverity
)
from otbase.models.lifecycle import (
    LifecycleState, LifecycleMilestone, ObsolescenceRisk
)

def get_rockwell_water_chassis() -> Chassis:
    """Standard 10-Slot ControlLogix 1756 Chassis with full module breakdown."""
    modules = [
        RackModule(
            slot=0,
            name="1756-PA72 Power Supply",
            catalog_number="1756-PA72",
            serial_number="0x28A14F90",
            hardware_revision="B",
            firmware_version="N/A",
            vendor="Rockwell Automation",
            module_type=ModuleType.POWER_SUPPLY,
            status_leds=[
                LEDStatus(name="POWER", state=LEDColor.GREEN),
                LEDStatus(name="OK", state=LEDColor.GREEN)
            ],
            description="ControlLogix 85-265V AC Power Supply (10 A @ 5V DC)",
            cve_count=0
        ),
        RackModule(
            slot=1,
            name="1756-L83E ControlLogix 5580 Controller",
            catalog_number="1756-L83E",
            serial_number="0x4B9E2101",
            hardware_revision="B",
            firmware_version="33.011",
            vendor="Rockwell Automation",
            module_type=ModuleType.CONTROLLER,
            status_leds=[
                LEDStatus(name="RUN", state=LEDColor.GREEN),
                LEDStatus(name="FORCE", state=LEDColor.OFF),
                LEDStatus(name="SD", state=LEDColor.GREEN),
                LEDStatus(name="OK", state=LEDColor.GREEN),
                LEDStatus(name="NET", state=LEDColor.FLASHING_GREEN)
            ],
            description="High-performance controller with 10MB user memory & Gigabit onboard Ethernet",
            cve_count=2,
            cves=["CVE-2022-1159", "CVE-2021-22681"]
        ),
        RackModule(
            slot=2,
            name="1756-EN2T EtherNet/IP Bridge",
            catalog_number="1756-EN2T",
            serial_number="0x118C55A4",
            hardware_revision="C",
            firmware_version="5.028",
            vendor="Rockwell Automation",
            module_type=ModuleType.COMM_ADAPTER,
            status_leds=[
                LEDStatus(name="LINK1", state=LEDColor.GREEN),
                LEDStatus(name="LINK2", state=LEDColor.OFF),
                LEDStatus(name="NET", state=LEDColor.GREEN),
                LEDStatus(name="OK", state=LEDColor.GREEN)
            ],
            description="Dual-port 10/100 Mbps EtherNet/IP communications interface module",
            cve_count=1,
            cves=["CVE-2020-6967"]
        ),
        RackModule(
            slot=3,
            name="1756-IB16 Digital Input Module",
            catalog_number="1756-IB16",
            serial_number="0x992B104A",
            hardware_revision="D",
            firmware_version="3.002",
            vendor="Rockwell Automation",
            module_type=ModuleType.DIGITAL_INPUT,
            status_leds=[
                LEDStatus(name="OK", state=LEDColor.GREEN),
                LEDStatus(name="I/O", state=LEDColor.GREEN)
            ],
            description="16-Point 24V DC Sink/Source Isolated Input Module",
            cve_count=0
        ),
        RackModule(
            slot=4,
            name="1756-OB16E Digital Output Module",
            catalog_number="1756-OB16E",
            serial_number="0x992B108B",
            hardware_revision="D",
            firmware_version="3.001",
            vendor="Rockwell Automation",
            module_type=ModuleType.DIGITAL_OUTPUT,
            status_leds=[
                LEDStatus(name="OK", state=LEDColor.GREEN),
                LEDStatus(name="FUSE", state=LEDColor.OFF)
            ],
            description="16-Point 24V DC Electronically Protected Output Module",
            cve_count=0
        ),
        RackModule(
            slot=5,
            name="1756-IF8 Analog Input Module",
            catalog_number="1756-IF8",
            serial_number="0x884D2001",
            hardware_revision="B",
            firmware_version="2.001",
            vendor="Rockwell Automation",
            module_type=ModuleType.ANALOG_INPUT,
            status_leds=[
                LEDStatus(name="OK", state=LEDColor.GREEN),
                LEDStatus(name="CAL", state=LEDColor.OFF)
            ],
            description="8-Point Voltage/Current Analog Input Module (4-20mA / 0-10V)",
            cve_count=0
        ),
        RackModule(
            slot=6,
            name="1756-OF4 Analog Output Module",
            catalog_number="1756-OF4",
            serial_number="0x884D209F",
            hardware_revision="A",
            firmware_version="1.005",
            vendor="Rockwell Automation",
            module_type=ModuleType.ANALOG_OUTPUT,
            status_leds=[
                LEDStatus(name="OK", state=LEDColor.GREEN)
            ],
            description="4-Point Isolated Voltage/Current Analog Output Module",
            cve_count=0
        ),
        RackModule(
            slot=7,
            name="1756-SYNCH SynchLink Module",
            catalog_number="1756-SYNCH",
            serial_number="0x771A9002",
            hardware_revision="B",
            firmware_version="2.010",
            vendor="Rockwell Automation",
            module_type=ModuleType.SPECIALTY,
            status_leds=[
                LEDStatus(name="RUN", state=LEDColor.GREEN),
                LEDStatus(name="SYNC", state=LEDColor.GREEN)
            ],
            description="Fiber-optic time synchronization and high-speed peer-to-peer data broadcast",
            cve_count=0
        )
    ]
    return Chassis(
        model="1756-A10 10-Slot ControlLogix Chassis",
        serial_number="CH-NA-902188",
        total_slots=10,
        modules=modules
    )

def get_siemens_s71500_chassis() -> Chassis:
    """Siemens S7-1500 Modular Rack Chassis."""
    modules = [
        RackModule(
            slot=1,
            name="PM 190W 120/230VAC Power Supply",
            catalog_number="6EP1333-4BA00",
            serial_number="SVB8102938",
            hardware_revision="FS01",
            firmware_version="N/A",
            vendor="Siemens",
            module_type=ModuleType.POWER_SUPPLY,
            status_leds=[LEDStatus(name="24V DC", state=LEDColor.GREEN)],
            description="Load power supply PM 190W for S7-1500 backplane",
            cve_count=0
        ),
        RackModule(
            slot=2,
            name="CPU 1518-4 PN/DP Controller",
            catalog_number="6ES7518-4AP00-0AB0",
            serial_number="SVP9281741",
            hardware_revision="FS04",
            firmware_version="2.8.3",
            vendor="Siemens",
            module_type=ModuleType.CONTROLLER,
            status_leds=[
                LEDStatus(name="RUN", state=LEDColor.GREEN),
                LEDStatus(name="STOP", state=LEDColor.OFF),
                LEDStatus(name="ERROR", state=LEDColor.OFF),
                LEDStatus(name="MAINT", state=LEDColor.OFF)
            ],
            description="High-end CPU with 4MB code / 20MB data, 3 PROFINET interfaces, 1 PROFIBUS",
            cve_count=2,
            cves=["CVE-2020-15782", "CVE-2022-38465"]
        ),
        RackModule(
            slot=3,
            name="CP 1543-1 Security Communications Processor",
            catalog_number="6GK7543-1AX00-0XE0",
            serial_number="SVC1029482",
            hardware_revision="FS02",
            firmware_version="2.2.14",
            vendor="Siemens",
            module_type=ModuleType.COMM_ADAPTER,
            status_leds=[
                LEDStatus(name="RUN", state=LEDColor.GREEN),
                LEDStatus(name="DIAG", state=LEDColor.GREEN)
            ],
            description="Industrial Ethernet Security CP with integrated SPI firewall & VPN",
            cve_count=0
        ),
        RackModule(
            slot=4,
            name="DI 32x24VDC HF Digital Input",
            catalog_number="6ES7521-1BL00-0AB0",
            serial_number="SVD3918204",
            hardware_revision="FS03",
            firmware_version="1.1.0",
            vendor="Siemens",
            module_type=ModuleType.DIGITAL_INPUT,
            status_leds=[LEDStatus(name="RUN", state=LEDColor.GREEN)],
            description="32 Channels 24V DC High Feature with hardware interrupt support",
            cve_count=0
        ),
        RackModule(
            slot=5,
            name="DQ 32x24VDC/0.5A HF Digital Output",
            catalog_number="6ES7522-1BL01-0AB0",
            serial_number="SVD3918299",
            hardware_revision="FS03",
            firmware_version="1.1.0",
            vendor="Siemens",
            module_type=ModuleType.DIGITAL_OUTPUT,
            status_leds=[LEDStatus(name="RUN", state=LEDColor.GREEN)],
            description="32 Channels 24V DC Transistor High Feature",
            cve_count=0
        ),
        RackModule(
            slot=6,
            name="AI 8xU/I/RTD/TC ST Analog Input",
            catalog_number="6ES7531-7KF00-0AB0",
            serial_number="SVA8192031",
            hardware_revision="FS02",
            firmware_version="1.0.0",
            vendor="Siemens",
            module_type=ModuleType.ANALOG_INPUT,
            status_leds=[LEDStatus(name="RUN", state=LEDColor.GREEN)],
            description="8 Channels differential voltage, current, thermocouple or RTD input",
            cve_count=0
        )
    ]
    return Chassis(
        model="Siemens S7-1500 Standard Tier-1 32-Module Rail",
        serial_number="SN-S7-1500-GER-841",
        total_slots=8,
        modules=modules
    )

def get_frick_quantum_chassis() -> Chassis:
    """Johnson Controls / Frick Quantum HD Industrial Refrigeration Controller Chassis."""
    modules = [
        RackModule(
            slot=0,
            name="Frick 24VDC Industrial Power Module",
            catalog_number="QHD-PWR-24V",
            serial_number="JCI-PWR-88219",
            hardware_revision="C",
            firmware_version="N/A",
            vendor="Johnson Controls / Frick",
            module_type=ModuleType.POWER_SUPPLY,
            status_leds=[
                LEDStatus(name="DC_OK", state=LEDColor.GREEN),
                LEDStatus(name="FAULT", state=LEDColor.OFF)
            ],
            description="Isolated 24VDC heavy-duty compressor panel power supply",
            cve_count=0
        ),
        RackModule(
            slot=1,
            name="Quantum HD Master Processor & Touch Display",
            catalog_number="QHD-CPU-V10",
            serial_number="FRICK-QHD-4410",
            hardware_revision="E",
            firmware_version="10.42.01",
            vendor="Johnson Controls / Frick",
            module_type=ModuleType.CONTROLLER,
            status_leds=[
                LEDStatus(name="RUN", state=LEDColor.GREEN),
                LEDStatus(name="COMM", state=LEDColor.GREEN),
                LEDStatus(name="ALARM", state=LEDColor.OFF)
            ],
            description="Quantum HD Screw Compressor Controller with real-time suction/discharge pressure calculations",
            cve_count=1,
            cves=["CVE-2022-30512"]
        ),
        RackModule(
            slot=2,
            name="Dual-Port EtherNet/IP & Modbus/TCP Comm Module",
            catalog_number="QHD-COM-ETH",
            serial_number="FRICK-ETH-9921",
            hardware_revision="B",
            firmware_version="4.012",
            vendor="Johnson Controls / Frick",
            module_type=ModuleType.COMM_ADAPTER,
            status_leds=[
                LEDStatus(name="LINK1", state=LEDColor.GREEN),
                LEDStatus(name="NET", state=LEDColor.GREEN)
            ],
            description="Industrial dual-port Ethernet bridge communicating with SCADA and Ammonia Safety Network",
            cve_count=0
        ),
        RackModule(
            slot=3,
            name="Precision RTD Temperature Input Module (Ammonia Suction/Discharge)",
            catalog_number="QHD-RTD-8",
            serial_number="FRICK-RTD-3301",
            hardware_revision="A",
            firmware_version="1.004",
            vendor="Johnson Controls / Frick",
            module_type=ModuleType.ANALOG_INPUT,
            status_leds=[LEDStatus(name="SCAN", state=LEDColor.GREEN)],
            description="8-Channel 4-wire RTD input measuring oil temp, suction temp, and condenser return",
            cve_count=0
        ),
        RackModule(
            slot=4,
            name="Compressor Slide Valve & Motor VFD Digital Control Module",
            catalog_number="QHD-OUT-RELAY",
            serial_number="FRICK-RLY-7712",
            hardware_revision="B",
            firmware_version="2.001",
            vendor="Johnson Controls / Frick",
            module_type=ModuleType.DIGITAL_OUTPUT,
            status_leds=[LEDStatus(name="OUT_EN", state=LEDColor.GREEN)],
            description="High-voltage relay outputs commanding 500HP compressor motor starter and capacity slide valves",
            cve_count=0
        ),
        RackModule(
            slot=5,
            name="VFD Speed Reference & Economizer Analog Output Module",
            catalog_number="QHD-AO-4",
            serial_number="FRICK-AO-9182",
            hardware_revision="A",
            firmware_version="1.002",
            vendor="Johnson Controls / Frick",
            module_type=ModuleType.ANALOG_OUTPUT,
            status_leds=[LEDStatus(name="OK", state=LEDColor.GREEN)],
            description="4-channel 4-20mA output commanding variable frequency drive motor speed and economizer backpressure",
            cve_count=0
        )
    ]
    return Chassis(
        model="Frick Quantum HD 6-Slot Refrigeration Chassis",
        serial_number="FRICK-CHAS-6094",
        total_slots=6,
        modules=modules
    )

def get_water_treatment_assets() -> List[Asset]:
    """Municipal Water Treatment Facility Asset Baseline."""
    return [
        Asset(
            id="wt-plc-01",
            tag_name="PLC-01-MAIN",
            display_name="Water Treatment Main Intake & Filtration PLC",
            vendor="Rockwell Automation",
            model="ControlLogix 5580",
            catalog_number="1756-L83E",
            serial_number="SN-CLX-L83E-9018",
            hardware_revision="B",
            firmware_version="33.011",
            os_name="Rockwell Firmware OS",
            os_version="33.011",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            facility="Municipal Water Treatment Facility",
            area="Raw Water Intake & Filtration",
            production_line="Intake Train A",
            workcell="Filter Bed Control",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.REMOTE_RUN,  # Remote Run leaves it open to network program upload/download
            chassis=get_rockwell_water_chassis(),
            network_interfaces=[
                NetworkInterface(
                    name="1756-EN2T Port A",
                    mac_address="00:1D:9C:C4:55:01",
                    ip_address="192.168.10.10",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                ),
                NetworkInterface(
                    name="1756-L83E Onboard GigE",
                    mac_address="00:1D:9C:F1:83:02",
                    ip_address="192.168.10.11",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            serial_ports=[],
            active_cves=["CVE-2022-1159", "CVE-2021-22681", "CVE-2020-6967"],
            ot_risk_score=8.4,
            lifecycle_state="Active",
            notes="Controls primary flocculation and rapid sand filter backwash cycles."
        ),
        Asset(
            id="wt-plc-02",
            tag_name="PLC-02-CHEM",
            display_name="Chemical Dosing & Chlorination Controller",
            vendor="Rockwell Automation",
            model="CompactLogix 5380",
            catalog_number="5069-L320ERM",
            serial_number="SN-CMPX-5069-781",
            hardware_revision="A",
            firmware_version="32.012",
            os_name="CompactLogix Embedded RTOS",
            os_version="32.012",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            facility="Municipal Water Treatment Facility",
            area="Chemical Feed Building",
            production_line="Chlorine Gas & Alum Feed",
            workcell="Disinfection Header",
            criticality=Criticality.SAFETY_CRITICAL,
            key_switch=KeySwitchMode.RUN,  # Hardware locked
            chassis=None,
            network_interfaces=[
                NetworkInterface(
                    name="EtherNet/IP Dual-Port",
                    mac_address="00:1D:9C:88:22:19",
                    ip_address="192.168.10.20",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            serial_ports=[
                SerialPort(
                    name="RS-485 Modbus Link",
                    interface_type="RS-485",
                    protocol="Modbus RTU",
                    baud_rate=9600
                )
            ],
            active_cves=["CVE-2021-22681"],
            ot_risk_score=5.1,  # Lower risk because key switch is locked to RUN!
            lifecycle_state="Active",
            notes="Regulates sodium hypochlorite and coagulant pumps. Physical key locked in cabinet."
        ),
        Asset(
            id="wt-hmi-01",
            tag_name="HMI-01-OP",
            display_name="Main Control Room Operator Station",
            vendor="AVEVA / Wonderware",
            model="InTouch 2020 R2",
            catalog_number="WND-IT-2020",
            serial_number="LIC-WW-89201-US",
            hardware_revision="N/A",
            firmware_version="N/A",
            os_name="Windows 10 Enterprise LTSC 2019",
            os_version="1809 (Build 17763)",
            device_type=DeviceType.HMI,
            purdue_level=PurdueLevel.LEVEL_2,
            facility="Municipal Water Treatment Facility",
            area="Central Control Room",
            production_line="All Trains",
            workcell="Operator Desk A",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="Intel I219-LM NIC",
                    mac_address="00:50:56:A2:3B:11",
                    ip_address="192.168.20.15",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.20.1",
                    vlan=20
                )
            ],
            serial_ports=[],
            active_cves=["CVE-2021-44228"],
            ot_risk_score=6.8,
            lifecycle_state="Active",
            notes="Primary operational HMI graphic display and alarm annunciator."
        ),
        Asset(
            id="wt-ews-01",
            tag_name="EWS-01-ENG",
            display_name="Lead Automation Engineering Workstation",
            vendor="Rockwell Automation",
            model="Studio 5000 Professional v33",
            catalog_number="EWS-RACK-DELL",
            serial_number="SN-DELL-PREC-3640",
            hardware_revision="N/A",
            firmware_version="v33.00",
            os_name="Windows 10 Pro 64-bit",
            os_version="21H2",
            device_type=DeviceType.ENGINEERING_WORKSTATION,
            purdue_level=PurdueLevel.LEVEL_3,
            facility="Municipal Water Treatment Facility",
            area="Engineering Office",
            production_line="Automation Maintenance",
            workcell="Programmer Bench",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="OT Plant NIC",
                    mac_address="00:50:56:88:C1:22",
                    ip_address="192.168.30.50",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.30.1",
                    vlan=30
                ),
                NetworkInterface(
                    name="Direct Control NIC (DUAL HOMED BREACH)",
                    mac_address="00:50:56:88:C1:23",
                    ip_address="192.168.10.99",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            serial_ports=[],
            active_cves=["CVE-2022-29845"],
            ot_risk_score=9.1,  # Critical risk due to dual-homed bridge and engineering privileges
            lifecycle_state="Active",
            notes="Engineering workstation used for PLC logic changes, Studio 5000, and firmware flash tools."
        ),
        Asset(
            id="wt-hist-01",
            tag_name="HIST-01-SRV",
            display_name="Site Operations Data Historian Server",
            vendor="Rockwell Automation",
            model="FactoryTalk Historian SE",
            catalog_number="9701-VWSTPR01",
            serial_number="SN-FT-HIST-9011",
            hardware_revision="N/A",
            firmware_version="7.00.00",
            os_name="Windows Server 2019 Standard",
            os_version="1809 (Build 17763)",
            device_type=DeviceType.HISTORIAN,
            purdue_level=PurdueLevel.LEVEL_3,
            facility="Municipal Water Treatment Facility",
            area="Server Room Rack 1",
            production_line="Plant-Wide Telemetry",
            workcell="Historian Node",
            criticality=Criticality.MEDIUM,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="Historian Internal NIC",
                    mac_address="00:50:56:11:44:AA",
                    ip_address="192.168.30.100",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.30.1",
                    vlan=30
                )
            ],
            serial_ports=[],
            active_cves=[],
            ot_risk_score=3.2,
            lifecycle_state="Active",
            notes="Aggregates 1-second process telemetry for water quality regulatory compliance reporting."
        ),
        Asset(
            id="wt-idmz-gw",
            tag_name="IDMZ-SEC-GW01",
            display_name="Industrial DMZ Security Firewall & Jump Host Gateway",
            vendor="Phoenix Contact",
            model="FL mGuard RS4000 TX/TX",
            catalog_number="2989983",
            serial_number="SN-PHX-MG-8812",
            hardware_revision="Rev 3",
            firmware_version="8.8.1",
            os_name="mGuard Secure OS",
            os_version="8.8.1",
            device_type=DeviceType.INDUSTRIAL_FIREWALL,
            purdue_level=PurdueLevel.LEVEL_3_5,
            facility="Municipal Water Treatment Facility",
            area="DMZ Border Enclosure",
            production_line="Perimeter",
            workcell="IDMZ Security Cluster",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="External IT Port (Level 4)",
                    mac_address="00:A0:45:11:22:33",
                    ip_address="10.100.5.1",
                    subnet_mask="255.255.255.0",
                    gateway="10.100.5.254",
                    vlan=100
                ),
                NetworkInterface(
                    name="Internal OT Port (Level 3)",
                    mac_address="00:A0:45:11:22:34",
                    ip_address="192.168.30.1",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.30.1",
                    vlan=30
                )
            ],
            serial_ports=[],
            active_cves=[],
            ot_risk_score=2.5,
            lifecycle_state="Active",
            notes="Stateful packet inspection firewall enforcing strict ISA/IEC 62443 zone boundaries."
        ),
        Asset(
            id="wt-sw-01",
            tag_name="SW-01-IND",
            display_name="Plant Floor Core Managed Industrial Switch",
            vendor="Cisco Systems",
            model="Catalyst IE-3400 Heavy Duty",
            catalog_number="IE-3400-8T2S-E",
            serial_number="FOC2419U091",
            hardware_revision="V02",
            firmware_version="17.9.2a",
            os_name="Cisco IOS-XE",
            os_version="17.9.2a",
            device_type=DeviceType.INDUSTRIAL_SWITCH,
            purdue_level=PurdueLevel.LEVEL_2,
            facility="Municipal Water Treatment Facility",
            area="Control Room Network Rack",
            production_line="Plant Backbone",
            workcell="Switching Core",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="Vlan1 Management",
                    mac_address="00:2A:6A:99:88:10",
                    ip_address="192.168.20.2",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.20.1",
                    vlan=20,
                    is_management=True
                )
            ],
            serial_ports=[
                SerialPort(
                    name="Console RJ45",
                    interface_type="RS-232",
                    protocol="CLI",
                    baud_rate=9600
                )
            ],
            active_cves=["CVE-2023-20076"],
            ot_risk_score=4.6,
            lifecycle_state="Active",
            notes="Industrial Ethernet switch handling PROFINET, EtherNet/IP, and SCADA VLAN traffic."
        ),
        Asset(
            id="wt-field-01",
            tag_name="FIT-101-RAW",
            display_name="Raw Water Influent Magnetic Flowmeter",
            vendor="Endress+Hauser",
            model="Proline Promag W 400",
            catalog_number="5W4B80-AA",
            serial_number="SN-EH-991204-CH",
            hardware_revision="1.02",
            firmware_version="02.01.00",
            os_name="Embedded Microcontroller",
            os_version="2.1",
            device_type=DeviceType.FIELD_DEVICE,
            purdue_level=PurdueLevel.LEVEL_0,
            facility="Municipal Water Treatment Facility",
            area="Intake Vault 1",
            production_line="Influent Header",
            workcell="Pipeline Measurement",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="EtherNet/IP Interface",
                    mac_address="00:07:60:55:12:89",
                    ip_address="192.168.10.150",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            serial_ports=[
                SerialPort(
                    name="HART FSK Port",
                    interface_type="Current Loop",
                    protocol="HART 7.0",
                    baud_rate=1200
                )
            ],
            active_cves=[],
            ot_risk_score=1.8,
            lifecycle_state="Active",
            notes="Transmits real-time mega-gallons/day (MGD) influent flow to PLC-01-MAIN."
        )
    ]

def get_substation_assets() -> List[Asset]:
    """Electrical Power Transmission Substation Alpha Asset Baseline."""
    return [
        Asset(
            id="sub-rtu-01",
            tag_name="RTU-500KV-01",
            display_name="500kV Substation Substation Automation Controller",
            vendor="Schweitzer Engineering Laboratories",
            model="SEL-3530 Real-Time Automation Controller (RTAC)",
            catalog_number="353001221",
            serial_number="1150490188",
            hardware_revision="C",
            firmware_version="R149-V0",
            os_name="Embedded RTOS / SEL RTAC OS",
            os_version="R149",
            device_type=DeviceType.RTU,
            purdue_level=PurdueLevel.LEVEL_1,
            facility="500kV Substation Alpha",
            area="Substation Control House",
            production_line="500kV Bus 1",
            workcell="RTAC Automation Cabinet",
            criticality=Criticality.SAFETY_CRITICAL,
            key_switch=KeySwitchMode.RUN,
            network_interfaces=[
                NetworkInterface(
                    name="ETH1 Substation LAN (DNP3/IEC 61850)",
                    mac_address="00:30:A7:11:45:90",
                    ip_address="10.20.10.10",
                    subnet_mask="255.255.255.0",
                    gateway="10.20.10.1",
                    vlan=10
                ),
                NetworkInterface(
                    name="ETH2 Control Center SCADA Link",
                    mac_address="00:30:A7:11:45:91",
                    ip_address="10.20.50.10",
                    subnet_mask="255.255.255.0",
                    gateway="10.20.50.1",
                    vlan=50
                )
            ],
            serial_ports=[
                SerialPort(
                    name="Port 1 (SEL Relay Intertie)",
                    interface_type="RS-232 / EIA-485",
                    protocol="SEL Fast Message / DNP3",
                    baud_rate=38400
                )
            ],
            active_cves=["CVE-2020-11896"],  # Treck Ripple20 stack vulnerability in older firmware
            ot_risk_score=7.6,
            lifecycle_state="Active",
            notes="Concentrates breaker status and synchrophasor PMU measurements across 12 feeder bays."
        ),
        Asset(
            id="sub-ied-01",
            tag_name="RELAY-501-L1",
            display_name="Line 1 Distance Protection and Breaker Control Relay",
            vendor="Schweitzer Engineering Laboratories",
            model="SEL-421 Protection Relay",
            catalog_number="042156154XC4X85",
            serial_number="1169820041",
            hardware_revision="B",
            firmware_version="R314",
            os_name="SEL Relay Microcode",
            os_version="R314",
            device_type=DeviceType.IED,
            purdue_level=PurdueLevel.LEVEL_1,
            facility="500kV Substation Alpha",
            area="Bay 1 Yard Relay Rack",
            production_line="500kV Feeder Line 1",
            workcell="Transmission Relay Panel",
            criticality=Criticality.SAFETY_CRITICAL,
            key_switch=KeySwitchMode.RUN,
            network_interfaces=[
                NetworkInterface(
                    name="Fiber Port 1 (IEC 61850 GOOSE/MMS)",
                    mac_address="00:30:A7:88:99:01",
                    ip_address="10.20.10.21",
                    subnet_mask="255.255.255.0",
                    gateway="10.20.10.1",
                    vlan=10
                )
            ],
            serial_ports=[],
            active_cves=[],
            ot_risk_score=2.1,
            lifecycle_state="Active",
            notes="Primary high-speed distance protection for 500kV overhead transmission conductor."
        ),
        Asset(
            id="sub-ied-02",
            tag_name="RELAY-502-T1",
            display_name="Transformer 1 Differential Protection Relay",
            vendor="Siemens",
            model="SIPROTEC 5 7UT85",
            catalog_number="7UT85-AA0-0AA0",
            serial_number="BF190820491",
            hardware_revision="04.01",
            firmware_version="V08.83",
            os_name="Siemens DIGSI RTOS",
            os_version="V08.83",
            device_type=DeviceType.IED,
            purdue_level=PurdueLevel.LEVEL_1,
            facility="500kV Substation Alpha",
            area="Transformer 1 Yard",
            production_line="500kV/230kV Auto-Transformer",
            workcell="Transformer Protection Panel",
            criticality=Criticality.SAFETY_CRITICAL,
            key_switch=KeySwitchMode.RUN,
            network_interfaces=[
                NetworkInterface(
                    name="Optical Ethernet BD",
                    mac_address="00:1C:06:54:19:80",
                    ip_address="10.20.10.22",
                    subnet_mask="255.255.255.0",
                    gateway="10.20.10.1",
                    vlan=10
                )
            ],
            serial_ports=[],
            active_cves=["CVE-2022-38465"],
            ot_risk_score=4.8,
            lifecycle_state="Active",
            notes="Restricted earth fault and phase differential protection for 750 MVA transformer bank."
        ),
        Asset(
            id="sub-hmi-01",
            tag_name="HMI-SUB-TOUCH",
            display_name="Substation Local Operator Touchscreen Workstation",
            vendor="Schweitzer Engineering Laboratories",
            model="SEL-3355 Tough Server / HMI",
            catalog_number="33550212",
            serial_number="1178294101",
            hardware_revision="A",
            firmware_version="N/A",
            os_name="Windows 10 IoT Enterprise 2021 LTSC",
            os_version="21H2",
            device_type=DeviceType.HMI,
            purdue_level=PurdueLevel.LEVEL_2,
            facility="500kV Substation Alpha",
            area="Substation Control House",
            production_line="Station Overview",
            workcell="Front Desk",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="Intel Dual GbE",
                    mac_address="00:30:A7:DA:11:40",
                    ip_address="10.20.20.5",
                    subnet_mask="255.255.255.0",
                    gateway="10.20.20.1",
                    vlan=20
                )
            ],
            serial_ports=[],
            active_cves=[],
            ot_risk_score=2.2,
            lifecycle_state="Active",
            notes="Local single-line diagram (SLD) display for switching operations and lockout resets."
        ),
        Asset(
            id="sub-sec-gw",
            tag_name="GW-RUGGED-01",
            display_name="NERC CIP Security Perimeter Gateway / VPN Router",
            vendor="Siemens Ruggedcom",
            model="Ruggedcom RX1500 Multi-Service Platform",
            catalog_number="6GK6015-0AL20-0AA0",
            serial_number="WAP0849201",
            hardware_revision="B2",
            firmware_version="ROX 2.15.1",
            os_name="Rugged Operating System (ROX)",
            os_version="ROX 2.15.1",
            device_type=DeviceType.INDUSTRIAL_FIREWALL,
            purdue_level=PurdueLevel.LEVEL_3_5,
            facility="500kV Substation Alpha",
            area="Communications Room",
            production_line="NERC CIP Electronic Security Perimeter (ESP)",
            workcell="WAN Demarcation",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="WAN IPsec Tunnel to Transmission Grid Ops",
                    mac_address="00:0A:DC:77:22:11",
                    ip_address="172.16.8.50",
                    subnet_mask="255.255.255.252",
                    gateway="172.16.8.49",
                    vlan=800
                ),
                NetworkInterface(
                    name="Local ESP Trunk",
                    mac_address="00:0A:DC:77:22:12",
                    ip_address="10.20.1.1",
                    subnet_mask="255.255.255.0",
                    gateway="10.20.1.1",
                    vlan=1
                )
            ],
            serial_ports=[],
            active_cves=[],
            ot_risk_score=2.0,
            lifecycle_state="Active",
            notes="Enforces NERC CIP-005 Electronic Security Perimeter and encrypted DNP3-Secure tunnels."
        )
    ]

def get_refinery_assets() -> List[Asset]:
    """Continuous Petrochemical Refinery (Crude Distillation Unit) Baseline."""
    return [
        Asset(
            id="ref-dcs-01",
            tag_name="FCS-01-CRUDE",
            display_name="Crude Distillation Field Control Station (FCS)",
            vendor="Yokogawa Electric",
            model="CENTUM VP AFV30D Duplexed Field Control Unit",
            catalog_number="AFV30D-S41201",
            serial_number="YOK-JP-9948201",
            hardware_revision="Rev 4",
            firmware_version="R6.08.00",
            os_name="Yokogawa Vnet/IP Controller OS",
            os_version="R6.08",
            device_type=DeviceType.DCS_CONTROLLER,
            purdue_level=PurdueLevel.LEVEL_1,
            facility="Petrochemical Continuous Refinery",
            area="Crude Distillation Unit (CDU)",
            production_line="Atmospheric Tower",
            workcell="FCS Rack 01",
            criticality=Criticality.SAFETY_CRITICAL,
            key_switch=KeySwitchMode.RUN,
            network_interfaces=[
                NetworkInterface(
                    name="Vnet/IP Bus 1",
                    mac_address="00:00:E2:81:49:01",
                    ip_address="172.24.10.11",
                    subnet_mask="255.255.255.0",
                    gateway="172.24.10.1",
                    vlan=10
                ),
                NetworkInterface(
                    name="Vnet/IP Bus 2 (Redundant)",
                    mac_address="00:00:E2:81:49:02",
                    ip_address="172.24.11.11",
                    subnet_mask="255.255.255.0",
                    gateway="172.24.11.1",
                    vlan=11
                )
            ],
            serial_ports=[],
            active_cves=["CVE-2022-4413"],
            ot_risk_score=6.2,
            lifecycle_state="Active",
            notes="Controls 42 furnace valves, tower reflux pumps, and crude preheat train."
        ),
        Asset(
            id="ref-sis-01",
            tag_name="SIS-TRICON-01",
            display_name="Safety Instrumented System (SIS) Emergency Shutdown (ESD)",
            vendor="Schneider Electric / Triconex",
            model="Tricon v11.4 Triple Modular Redundant (TMR) Controller",
            catalog_number="3008N",
            serial_number="TRIC-US-88194",
            hardware_revision="Rev G",
            firmware_version="11.4.1",
            os_name="Tricon Enhanced Diagnostic OS (TSAA)",
            os_version="11.4",
            device_type=DeviceType.SIS_CONTROLLER,
            purdue_level=PurdueLevel.LEVEL_1,
            facility="Petrochemical Continuous Refinery",
            area="Safety Enclosure Building",
            production_line="Refinery-Wide Emergency Depressurization",
            workcell="SIS Cabinet 01",
            criticality=Criticality.SAFETY_CRITICAL,
            key_switch=KeySwitchMode.RUN,  # Locked key switch prevents TRITON/HatMan style firmware reprogramming
            network_interfaces=[
                NetworkInterface(
                    name="Network Communication Module (NCM)",
                    mac_address="00:80:F4:71:04:19",
                    ip_address="172.24.15.5",
                    subnet_mask="255.255.255.0",
                    gateway="172.24.15.1",
                    vlan=15
                )
            ],
            serial_ports=[],
            active_cves=["CVE-2017-6016"],
            ot_risk_score=3.5,  # Key switch locked, isolated SIS network
            lifecycle_state="Active",
            notes="SIL 3 Safety Instrumented System executing automatic flare trip and hydrocarbon isolation."
        ),
        Asset(
            id="ref-plc-01",
            tag_name="PLC-BOILER-400",
            display_name="High-Pressure Steam Boiler 4 Controller",
            vendor="Siemens",
            model="SIMATIC S7-400H Redundant System",
            catalog_number="6ES7414-5HM06-0AB0",
            serial_number="SVB-S7400-9948",
            hardware_revision="05.00",
            firmware_version="4.5.7",  # Legacy firmware version - END OF SUPPORT!
            os_name="Siemens S7 Firmware",
            os_version="4.5.7",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            facility="Petrochemical Continuous Refinery",
            area="Utilities & Steam Generation",
            production_line="Boiler 4",
            workcell="Burner Management System",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.REMOTE_RUN,
            network_interfaces=[
                NetworkInterface(
                    name="CP 443-1 Industrial Ethernet",
                    mac_address="00:1B:1B:90:34:55",
                    ip_address="172.24.10.80",
                    subnet_mask="255.255.255.0",
                    gateway="172.24.10.1",
                    vlan=10
                )
            ],
            serial_ports=[],
            active_cves=["CVE-2019-19294", "CVE-2015-5374"],
            ot_risk_score=9.4,  # Very high risk: legacy EOS firmware, remote run, cleartext S7comm
            lifecycle_state="End of Support (EOS - No Security Patches)",
            notes="Legacy S7-400H system installed in 2008. Vendor support has ended; planned for migration to S7-1500."
        ),
        Asset(
            id="ref-his-01",
            tag_name="HIS-01-DESK",
            display_name="Crude Unit Human Interface Station (HIS)",
            vendor="Yokogawa Electric",
            model="CENTUM VP HIS Client",
            catalog_number="LHS1100",
            serial_number="YOK-HIS-7741",
            hardware_revision="N/A",
            firmware_version="R6.08",
            os_name="Windows 10 Enterprise LTSC",
            os_version="21H2",
            device_type=DeviceType.HMI,
            purdue_level=PurdueLevel.LEVEL_2,
            facility="Petrochemical Continuous Refinery",
            area="Refinery Central Control Building",
            production_line="Distillation Operations",
            workcell="Console 1",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="Dual Vnet/IP NIC",
                    mac_address="00:00:E2:AA:BB:CC",
                    ip_address="172.24.20.10",
                    subnet_mask="255.255.255.0",
                    gateway="172.24.20.1",
                    vlan=20
                )
            ],
            serial_ports=[],
            active_cves=[],
            ot_risk_score=2.8,
            lifecycle_state="Active",
            notes="Displays process alarms, PID tuning faceplates, and trending graphics."
        ),
        Asset(
            id="ref-pi-01",
            tag_name="PI-CORP-HIST",
            display_name="Enterprise Operations PI System Historian",
            vendor="OSIsoft / AVEVA",
            model="PI Server 2022",
            catalog_number="PI-SRV-ENT",
            serial_number="LIC-PI-849201",
            hardware_revision="N/A",
            firmware_version="3.4.445",
            os_name="Windows Server 2022 Datacenter",
            os_version="21H2",
            device_type=DeviceType.HISTORIAN,
            purdue_level=PurdueLevel.LEVEL_3,
            facility="Petrochemical Continuous Refinery",
            area="Plant IT Datacenter",
            production_line="Enterprise Integration",
            workcell="Rack 4",
            criticality=Criticality.MEDIUM,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="Plant Operations Interface",
                    mac_address="00:50:56:FE:DC:BA",
                    ip_address="172.24.30.25",
                    subnet_mask="255.255.255.0",
                    gateway="172.24.30.1",
                    vlan=30
                )
            ],
            serial_ports=[],
            active_cves=[],
            ot_risk_score=2.4,
            lifecycle_state="Active",
            notes="Stores high-frequency process variables for predictive maintenance and yields."
        )
    ]

def get_walmart_cold_chain_assets() -> List[Asset]:
    """Walmart Distribution Center 6094 (Perishable Food & Cold Chain) Asset Baseline."""
    facility = "Walmart Distribution Center 6094 (Perishable Grocery & Cold Chain)"
    return [
        Asset(
            id="wm-plc-nh3-01",
            tag_name="PLC-NH3-COMP-01",
            display_name="Ammonia Compressor Skid #1 - Frick Screw Compressor Controller",
            vendor="Johnson Controls / Frick",
            model="Quantum HD",
            catalog_number="QHD-CPU-V10",
            serial_number="SN-FRICK-COMP1-6094",
            hardware_revision="E",
            firmware_version="10.42.01",
            os_name="Frick Real-Time OS",
            os_version="10.42",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            facility=facility,
            area="Compressor Engine Room",
            production_line="High-Stage Ammonia Loop",
            workcell="Compressor Bay 1",
            criticality=Criticality.SAFETY_CRITICAL,
            key_switch=KeySwitchMode.RUN,  # Hardware write-protected
            chassis=get_frick_quantum_chassis(),
            network_interfaces=[
                NetworkInterface(
                    name="eth0",
                    mac_address="00:0E:8C:11:22:01",
                    ip_address="192.168.10.11",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            serial_ports=[],
            location_id="loc-wm-skid-nh3-01",
            location_path="Walmart Supply Chain / DC-6094 Perishable / Engine Room / CP-NH3-01",
            cpe_string="cpe:2.3:h:johnsoncontrols:frick_quantum_hd:10.42:*:*:*:*:*:*:*",
            active_cves=["CVE-2022-30512"],
            ot_risk_score=6.8,
            lifecycle_state="Active",
            notes="Controls 500HP screw compressor maintaining -20°F blast freezer refrigerant loop."
        ),
        Asset(
            id="wm-plc-nh3-02",
            tag_name="PLC-NH3-COMP-02",
            display_name="Ammonia Compressor Skid #2 - Frick Screw Compressor Controller",
            vendor="Johnson Controls / Frick",
            model="Quantum HD",
            catalog_number="QHD-CPU-V10",
            serial_number="SN-FRICK-COMP2-6094",
            hardware_revision="E",
            firmware_version="10.42.01",
            os_name="Frick Real-Time OS",
            os_version="10.42",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            facility=facility,
            area="Compressor Engine Room",
            production_line="Low-Stage Ammonia Loop",
            workcell="Compressor Bay 2",
            criticality=Criticality.SAFETY_CRITICAL,
            key_switch=KeySwitchMode.REMOTE_RUN,  # Remote Run leaves it open to network modification
            chassis=get_frick_quantum_chassis(),
            network_interfaces=[
                NetworkInterface(
                    name="eth0",
                    mac_address="00:0E:8C:11:22:02",
                    ip_address="192.168.10.12",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            serial_ports=[],
            location_id="loc-wm-skid-nh3-02",
            location_path="Walmart Supply Chain / DC-6094 Perishable / Engine Room / CP-NH3-02",
            cpe_string="cpe:2.3:h:johnsoncontrols:frick_quantum_hd:10.42:*:*:*:*:*:*:*",
            active_cves=["CVE-2022-30512"],
            ot_risk_score=9.8,
            lifecycle_state="Active",
            notes="Secondary lead/lag ammonia compressor for perishable meat & dairy cooling."
        ),
        Asset(
            id="wm-rack-copeland",
            tag_name="RACK-E3-GROCERY",
            display_name="Emerson Copeland E3 Refrigeration Controller (Meat/Dairy Vaults 34°F)",
            vendor="Emerson Climate Technologies",
            model="Copeland E3",
            catalog_number="E3-SUPERMARKET-RACK",
            serial_number="SN-EMERSON-E3-10499",
            hardware_revision="Rev 3",
            firmware_version="3.10.2",
            os_name="Emerson E3 Linux",
            os_version="3.10",
            device_type=DeviceType.RTU,
            purdue_level=PurdueLevel.LEVEL_1,
            facility=facility,
            area="Perishable Storage Vaults",
            production_line="Medium-Temp Refrigeration",
            workcell="Meat & Produce Storage",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.RUN,
            network_interfaces=[
                NetworkInterface(
                    name="eth0",
                    mac_address="00:08:E1:44:55:12",
                    ip_address="192.168.10.25",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            serial_ports=[
                SerialPort(port_name="RS485-COM1", protocol="Modbus RTU", baud_rate=19200, parity="None", data_bits=8, stop_bits=1)
            ],
            location_id="loc-wm-vault-dairy",
            location_path="Walmart Supply Chain / DC-6094 Perishable / Dairy Vaults / CP-E3-01",
            cpe_string="cpe:2.3:h:emerson:copeland_e3:3.10:*:*:*:*:*:*:*",
            active_cves=[],
            ot_risk_score=2.2,
            lifecycle_state="Active",
            notes="Controls 32 electronic expansion valves (EEVs) regulating constant 34°F cold chain holding."
        ),
        Asset(
            id="wm-safety-nh3",
            tag_name="NH3-GAS-SAFETY-01",
            display_name="Det-Tronics Eagle Quantum Premier Ammonia (NH3) Gas Safety System (SIL 2)",
            vendor="Detector Electronics Corp (Det-Tronics)",
            model="Eagle Quantum Premier (EQP)",
            catalog_number="EQP-24VDC-SAFETY",
            serial_number="SN-DETTRONICS-9082A",
            hardware_revision="D",
            firmware_version="5.04.1",
            os_name="Det-Tronics Safety Kernel",
            os_version="5.04",
            device_type=DeviceType.SIS_CONTROLLER,
            purdue_level=PurdueLevel.LEVEL_1,
            facility=facility,
            area="Engine Room Life Safety",
            production_line="Toxic Vapor Containment",
            workcell="Ammonia Sensor Grid",
            criticality=Criticality.SAFETY_CRITICAL,
            key_switch=KeySwitchMode.RUN,
            network_interfaces=[
                NetworkInterface(
                    name="eqp-net",
                    mac_address="00:1B:4F:99:88:01",
                    ip_address="192.168.10.50",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            serial_ports=[],
            location_id="loc-wm-life-safety",
            location_path="Walmart Supply Chain / DC-6094 Perishable / Life Safety / CP-GAS-01",
            cpe_string="cpe:2.3:h:det-tronics:eagle_quantum_premier:5.04:*:*:*:*:*:*:*",
            active_cves=[],
            ot_risk_score=1.4,
            lifecycle_state="Active",
            notes="Life safety instrumented system (SIS). Automatically activates roof louvers and 50,000 CFM exhaust fans if NH3 > 25 PPM."
        ),
        Asset(
            id="wm-hmi-dock",
            tag_name="HMI-COLD-DOCK",
            display_name="Refrigerated Loading Dock Operator Panel & Inbound Pallet Inspector",
            vendor="Rockwell Automation",
            model="PanelView Plus 7 Performance",
            catalog_number="2711P-T15C22D9P",
            serial_number="SN-PV7-DOCK-1928",
            hardware_revision="C",
            firmware_version="12.001",
            os_name="Windows 10 IoT Enterprise",
            os_version="1809 LTSC",
            device_type=DeviceType.HMI,
            purdue_level=PurdueLevel.LEVEL_2,
            facility=facility,
            area="Refrigerated Shipping/Receiving Dock (38°F)",
            production_line="Outbound Cross-Dock",
            workcell="Dock Door 1-20",
            criticality=Criticality.MEDIUM,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="eth0",
                    mac_address="00:50:56:B2:3C:44",
                    ip_address="192.168.20.15",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.20.1",
                    vlan=20
                )
            ],
            serial_ports=[],
            location_id="loc-wm-dock-room",
            location_path="Walmart Supply Chain / DC-6094 Perishable / Shipping Dock / PNL-DOCK-01",
            cpe_string="cpe:2.3:h:rockwellautomation:panelview_plus_7:12.001:*:*:*:*:*:*:*",
            active_cves=["CVE-2020-6967"],
            ot_risk_score=3.8,
            lifecycle_state="Active",
            notes="Operator touch terminal displaying trailer core temps, door seals, and blast freezer staging status."
        ),
        Asset(
            id="wm-tablet-dock",
            tag_name="TAB-DOCK-TECH",
            display_name="Inbound Receiving Dock Field Maintenance Tablet (Dual-Homed Wi-Fi/OT)",
            vendor="Getac / Zebra",
            model="Getac F110 Fully Rugged Tablet",
            catalog_number="F110-G6",
            serial_number="SN-GETAC-DOCK-6094",
            hardware_revision="G6",
            firmware_version="N/A",
            os_name="Windows 11 Pro",
            os_version="22H2",
            device_type=DeviceType.ENGINEERING_WORKSTATION,
            purdue_level=PurdueLevel.LEVEL_3,
            facility=facility,
            area="Dock Maintenance Office",
            production_line="Mobile Workstation",
            workcell="Dock Tech Bench",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="Wi-Fi 6E (Corporate)",
                    mac_address="00:15:5D:88:12:01",
                    ip_address="10.240.50.88",
                    subnet_mask="255.255.255.0",
                    gateway="10.240.50.1",
                    vlan=50
                ),
                NetworkInterface(
                    name="USB-C Ethernet (Ammonia Skid Pivot)",
                    mac_address="00:E0:4C:68:01:23",
                    ip_address="192.168.10.77",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            serial_ports=[],
            location_id="loc-wm-dock-room",
            location_path="Walmart Supply Chain / DC-6094 Perishable / Shipping Dock / TECH-BENCH",
            cpe_string="cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:*:*",
            active_cves=["CVE-2023-38146"],
            ot_risk_score=9.6,  # Dual-homed cross-zone pivot into Level 1
            lifecycle_state="Active",
            notes="Maintenance tablet bridging corporate dock Wi-Fi directly into Ammonia Engine Room Subnet without firewall inspection."
        ),
        Asset(
            id="wm-scada-ignition",
            tag_name="SCADA-COLD-SRV01",
            display_name="Inductive Automation Ignition SCADA & FDA FSMA Cold Chain Compliance Server",
            vendor="Inductive Automation",
            model="Ignition Enterprise Gateway",
            catalog_number="IGN-GW-ENTERPRISE",
            serial_number="SN-IGNITION-WM-6094",
            hardware_revision="Rack 2U",
            firmware_version="8.1.28",
            os_name="Ubuntu Linux Server",
            os_version="22.04 LTS",
            device_type=DeviceType.SCADA_SERVER,
            purdue_level=PurdueLevel.LEVEL_3,
            facility=facility,
            area="Data Center & Operations Control",
            production_line="Cold Chain Telemetry",
            workcell="Central SCADA",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="eth0",
                    mac_address="00:50:56:99:11:A3",
                    ip_address="192.168.30.20",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.30.1",
                    vlan=30
                )
            ],
            serial_ports=[],
            location_id="loc-wm-server-room",
            location_path="Walmart Supply Chain / DC-6094 Perishable / Data Center / RACK-SRV-02",
            cpe_string="cpe:2.3:a:inductiveautomation:ignition:8.1.28:*:*:*:*:*:*:*",
            active_cves=[],
            ot_risk_score=1.8,
            lifecycle_state="Active",
            notes="Logs unalterable historical temperature records for FDA Food Safety Modernization Act (FSMA) compliance."
        ),
        Asset(
            id="wm-switch-cold",
            tag_name="SW-COLD-01",
            display_name="Cisco Catalyst IE-3300 Rugged Industrial Ethernet Switch",
            vendor="Cisco Systems",
            model="Catalyst IE-3300-8T2S-E",
            catalog_number="IE-3300-8T2S-E",
            serial_number="FOC241998A1",
            hardware_revision="V02",
            firmware_version="17.09.04",
            os_name="Cisco IOS-XE",
            os_version="17.9.4",
            device_type=DeviceType.INDUSTRIAL_SWITCH,
            purdue_level=PurdueLevel.LEVEL_2,
            facility=facility,
            area="Compressor Engine Room MCC",
            production_line="Refrigeration Network Core",
            workcell="Motor Control Center",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="Vlan1",
                    mac_address="00:2A:6A:12:34:56",
                    ip_address="192.168.20.2",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.20.1",
                    vlan=20
                )
            ],
            serial_ports=[],
            location_id="loc-wm-skid-nh3-01",
            location_path="Walmart Supply Chain / DC-6094 Perishable / Engine Room / MCC-01",
            cpe_string="cpe:2.3:o:cisco:ios_xe:17.9.4:*:*:*:*:*:*:*",
            active_cves=[],
            ot_risk_score=1.9,
            lifecycle_state="Active",
            notes="Harsh-environment switch rated for -40°C to +75°C engine room operation."
        ),
        Asset(
            id="wm-gw-telemetry",
            tag_name="IOT-AZURE-COLDGW",
            display_name="Walmart Enterprise Cold Chain Azure IoT Edge Telemetry Gateway",
            vendor="Advantech",
            model="UNO-2271G Industrial IoT Edge Computer",
            catalog_number="UNO-2271G-E21AE",
            serial_number="SN-ADVAN-AZURE-6094",
            hardware_revision="A1",
            firmware_version="3.2.0",
            os_name="Yocto Linux / Azure IoT Edge Runtime",
            os_version="2.4",
            device_type=DeviceType.INDUSTRIAL_FIREWALL,
            purdue_level=PurdueLevel.LEVEL_3_5,
            facility=facility,
            area="Industrial DMZ (IDMZ)",
            production_line="Enterprise Cloud Reporting",
            workcell="IDMZ Security Cabinet",
            criticality=Criticality.MEDIUM,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="eth0 (IDMZ)",
                    mac_address="00:D0:C9:AA:BB:01",
                    ip_address="10.240.12.5",
                    subnet_mask="255.255.255.0",
                    gateway="10.240.12.1",
                    vlan=35
                )
            ],
            serial_ports=[],
            location_id="loc-wm-idmz-room",
            location_path="Walmart Supply Chain / DC-6094 Perishable / IDMZ / SEC-RACK-01",
            cpe_string="cpe:2.3:h:advantech:uno-2271g:*:*:*:*:*:*:*:*",
            active_cves=[],
            ot_risk_score=2.0,
            lifecycle_state="Active",
            notes="Secure MQTT publisher transmitting cold-chain pallet temps and ammonia safety telemetry to Walmart Azure Cloud."
        ),
        Asset(
            id="wm-skid-duplicate",
            tag_name="PLC-BLAST-FREEZE-B",
            display_name="Modular Blast Freezer Skid B Controller (OEM Reused Subnet)",
            vendor="Rockwell Automation",
            model="CompactLogix 5380",
            catalog_number="5069-L320ER",
            serial_number="SN-CMPX-FREEZER-881",
            hardware_revision="B",
            firmware_version="33.011",
            os_name="Rockwell Firmware OS",
            os_version="33.011",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            facility=facility,
            area="Blast Freezer Bay 4 (-20°F)",
            production_line="Blast Freezer Line B",
            workcell="Bay 4 Evaporators",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.RUN,
            network_interfaces=[
                NetworkInterface(
                    name="5069-ENET",
                    mac_address="00:1D:9C:FE:DC:01",
                    ip_address="192.168.10.11",  # Reused IP demonstrating duplicate IP disambiguation
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            serial_ports=[],
            location_id="loc-wm-skid-freezer-b",
            location_path="Walmart Supply Chain / DC-6094 Perishable / Blast Freezers / SKID-BAY-04",
            cpe_string="cpe:2.3:h:rockwellautomation:compactlogix_5380:33.011:*:*:*:*:*:*:*",
            active_cves=["CVE-2021-22681"],
            ot_risk_score=7.1,
            lifecycle_state="Active",
            notes="Demonstrates SHANK duplicate IP disambiguation. Reused 192.168.10.11 subnet coexists cleanly via unique Location ID."
        ),
        Asset(
            id="wm-pump-standby",
            tag_name="PUMP-NH3-PURGE-STBY",
            display_name="Emergency Cold-Standby Ammonia Roof Vent Purge Fan (Dormant Asset)",
            vendor="Greenheck / Square D",
            model="Altivar 630 Ammonia Vent VFD",
            catalog_number="ATV630D37N4",
            serial_number="SN-SQD-VENT-7719",
            hardware_revision="A",
            firmware_version="2.1.0",
            os_name="Schneider Embedded Firmware",
            os_version="2.1",
            device_type=DeviceType.FIELD_DEVICE,
            purdue_level=PurdueLevel.LEVEL_0,
            facility=facility,
            area="Engine Room Roof Deck",
            production_line="Emergency Exhaust",
            workcell="Roof Fan 4",
            criticality=Criticality.HIGH,
            key_switch=KeySwitchMode.NOT_APPLICABLE,
            network_interfaces=[
                NetworkInterface(
                    name="eth0",
                    mac_address="00:80:F4:55:10:99",
                    ip_address="192.168.10.188",
                    subnet_mask="255.255.255.0",
                    gateway="192.168.10.1",
                    vlan=10
                )
            ],
            serial_ports=[],
            location_id="loc-wm-roof-deck",
            location_path="Walmart Supply Chain / DC-6094 Perishable / Roof Deck / FAN-PUMP-04",
            cpe_string="cpe:2.3:h:schneider-electric:altivar_process_atv630:*:*:*:*:*:*:*:*",
            active_cves=[],
            ot_risk_score=1.5,
            lifecycle_state="Active",
            notes="Cold-standby safety asset. Unseen by passive network TAPs (0 packets transmitted) until emergency test run."
        )
    ]

def get_purdue_zones(facility: str) -> List[PurdueZone]:
    """Returns ISA/IEC 62443 security zones based on the selected facility."""
    if "Water" in facility:
        return [
            PurdueZone(
                id="zone-wt-l0",
                name="Zone 0: Raw Water Physical Sensors & Actuators",
                purdue_level="Level 0 - Process / Field",
                facility=facility,
                description="Physical flowmeters, pressure transmitters, dosing pump drives",
                color="#64748b",
                asset_ids=["wt-field-01"]
            ),
            PurdueZone(
                id="zone-wt-l1",
                name="Zone 1: Basic Process Control System (BPCS)",
                purdue_level="Level 1 - Basic Control (PLCs/RTUs)",
                facility=facility,
                description="Deterministic PLC controllers executing realtime ladder logic",
                color="#0284c7",
                asset_ids=["wt-plc-01", "wt-plc-02"]
            ),
            PurdueZone(
                id="zone-wt-l2",
                name="Zone 2: Supervisory & Operator Control",
                purdue_level="Level 2 - Supervisory / HMIs",
                facility=facility,
                description="Operator stations, industrial core switches, and alarm consoles",
                color="#059669",
                asset_ids=["wt-hmi-01", "wt-sw-01"]
            ),
            PurdueZone(
                id="zone-wt-l3",
                name="Zone 3: Site Operations & Engineering",
                purdue_level="Level 3 - Operations & Historians",
                facility=facility,
                description="Engineering workstations, plant historians, domain controllers",
                color="#d97706",
                asset_ids=["wt-ews-01", "wt-hist-01"]
            ),
            PurdueZone(
                id="zone-wt-l35",
                name="Zone 3.5: Industrial DMZ (IDMZ)",
                purdue_level="Level 3.5 - Industrial DMZ (IDMZ)",
                facility=facility,
                description="Perimeter security firewalls, jump hosts, and proxied conduits",
                color="#dc2626",
                asset_ids=["wt-idmz-gw"]
            )
        ]
    elif "Substation" in facility:
        return [
            PurdueZone(
                id="zone-sub-l1",
                name="Zone 1: Station Relay & RTAC Automation Zone",
                purdue_level="Level 1 - Basic Control (PLCs/RTUs)",
                facility=facility,
                description="SEL-3530 RTAC, SEL-421 and Siemens SIPROTEC protection relays",
                color="#0284c7",
                asset_ids=["sub-rtu-01", "sub-ied-01", "sub-ied-02"]
            ),
            PurdueZone(
                id="zone-sub-l2",
                name="Zone 2: Substation Local HMI",
                purdue_level="Level 2 - Supervisory / HMIs",
                facility=facility,
                description="SEL-3355 Tough Server local display console",
                color="#059669",
                asset_ids=["sub-hmi-01"]
            ),
            PurdueZone(
                id="zone-sub-l35",
                name="Zone 3.5: Electronic Security Perimeter (ESP / IDMZ)",
                purdue_level="Level 3.5 - Industrial DMZ (IDMZ)",
                facility=facility,
                description="Ruggedcom RX1500 NERC CIP boundary gateway",
                color="#dc2626",
                asset_ids=["sub-sec-gw"]
            )
        ]
    elif "Walmart" in facility or "Cold Chain" in facility:
        return [
            PurdueZone(
                id="zone-wm-l0",
                name="Zone 0: Ammonia Field Actuators & Cold-Standby Fans",
                purdue_level="Level 0 - Process / Field",
                facility=facility,
                description="Cold-standby purge fan VFDs, solenoid valves, suction pressure sensors",
                color="#64748b",
                asset_ids=["wm-pump-standby"]
            ),
            PurdueZone(
                id="zone-wm-l1",
                name="Zone 1: Refrigeration & Life Safety Control Loop",
                purdue_level="Level 1 - Basic Control (PLCs/RTUs)",
                facility=facility,
                description="Frick Quantum HD ammonia controllers, Copeland E3 rack controllers, Det-Tronics NH3 gas safety",
                color="#0284c7",
                asset_ids=["wm-plc-nh3-01", "wm-plc-nh3-02", "wm-rack-copeland", "wm-safety-nh3", "wm-skid-duplicate"]
            ),
            PurdueZone(
                id="zone-wm-l2",
                name="Zone 2: Cold Storage Supervisory & Engine Room HMI",
                purdue_level="Level 2 - Supervisory / HMIs",
                facility=facility,
                description="Engine room PanelView Plus 7 display and Cisco IE-3300 industrial core switch",
                color="#059669",
                asset_ids=["wm-hmi-dock", "wm-switch-cold"]
            ),
            PurdueZone(
                id="zone-wm-l3",
                name="Zone 3: Distribution Center Operations & FSMA Compliance",
                purdue_level="Level 3 - Operations & Historians",
                facility=facility,
                description="Inductive Automation Ignition SCADA/Historian server logging FDA food safety compliance",
                color="#d97706",
                asset_ids=["wm-scada-ignition", "wm-tablet-dock"]
            ),
            PurdueZone(
                id="zone-wm-l35",
                name="Zone 3.5: Cold Chain Telemetry IDMZ",
                purdue_level="Level 3.5 - Industrial DMZ (IDMZ)",
                facility=facility,
                description="Advantech Azure IoT Edge computer transmitting pallet telemetry to cloud analytics",
                color="#dc2626",
                asset_ids=["wm-gw-telemetry"]
            )
        ]
    else:  # Refinery
        return [
            PurdueZone(
                id="zone-ref-l1-bpcs",
                name="Zone 1A: Basic Process Control (DCS)",
                purdue_level="Level 1 - Basic Control (PLCs/RTUs)",
                facility=facility,
                description="Yokogawa Centum VP Field Control Station and Siemens S7-400H",
                color="#0284c7",
                asset_ids=["ref-dcs-01", "ref-plc-01"]
            ),
            PurdueZone(
                id="zone-ref-l1-sis",
                name="Zone 1B: Safety Instrumented System (SIS)",
                purdue_level="Level 1 - Basic Control (PLCs/RTUs)",
                facility=facility,
                description="Independent SIL 3 Triconex Tricon emergency shutdown system",
                color="#9333ea",
                asset_ids=["ref-sis-01"]
            ),
            PurdueZone(
                id="zone-ref-l2",
                name="Zone 2: Refinery Operator Consoles",
                purdue_level="Level 2 - Supervisory / HMIs",
                facility=facility,
                description="Centum VP Human Interface Stations (HIS)",
                color="#059669",
                asset_ids=["ref-his-01"]
            ),
            PurdueZone(
                id="zone-ref-l3",
                name="Zone 3: Refinery Operations & Historian",
                purdue_level="Level 3 - Operations & Historians",
                facility=facility,
                description="OSIsoft PI System Data Historian Server",
                color="#d97706",
                asset_ids=["ref-pi-01"]
            )
        ]

def get_conduits(facility: str) -> List[Conduit]:
    """Defined conduits connecting zones with protocols and inspection status."""
    if "Water" in facility:
        return [
            Conduit(
                id="cnd-wt-01",
                name="Conduit C1: Supervisory Polling (Level 2 -> Level 1)",
                from_zone_id="zone-wt-l2",
                to_zone_id="zone-wt-l1",
                allowed_protocols=["EtherNet/IP (CIP)", "Modbus TCP"],
                ports=[44818, 502],
                is_inspected=True,
                inspection_device="FL mGuard DPI Firewall",
                is_encrypted=False,
                status="Active"
            ),
            Conduit(
                id="cnd-wt-02",
                name="Conduit C2: Historian Ingestion (Level 3 -> Level 2)",
                from_zone_id="zone-wt-l3",
                to_zone_id="zone-wt-l2",
                allowed_protocols=["OPC UA", "HTTPS"],
                ports=[4840, 443],
                is_inspected=True,
                inspection_device="Internal Zone Gateway",
                is_encrypted=True,
                status="Active"
            ),
            Conduit(
                id="cnd-wt-03",
                name="Conduit C3: Direct EWS to Field Conduit (UNINSPECTED VIOLATION)",
                from_zone_id="zone-wt-l3",
                to_zone_id="zone-wt-l1",
                allowed_protocols=["CIP Studio 5000 Programming", "SNMP", "HTTP"],
                ports=[44818, 161, 80],
                is_inspected=False,  # Security violation! Direct bypass around Level 2
                inspection_device=None,
                is_encrypted=False,
                status="Active"
            ),
            Conduit(
                id="cnd-wt-04",
                name="Conduit C4: IDMZ Jump Box Access (Level 3.5 -> Level 3)",
                from_zone_id="zone-wt-l35",
                to_zone_id="zone-wt-l3",
                allowed_protocols=["RDP over TLS", "SSH"],
                ports=[3389, 22],
                is_inspected=True,
                inspection_device="FL mGuard Jump Host Proxy",
                is_encrypted=True,
                status="Active"
            )
        ]
    elif "Substation" in facility:
        return [
            Conduit(
                id="cnd-sub-01",
                name="Substation Relay GOOSE / MMS Bus (Level 1 Intertie)",
                from_zone_id="zone-sub-l1",
                to_zone_id="zone-sub-l1",
                allowed_protocols=["IEC 61850 GOOSE", "IEC 61850 MMS", "DNP3"],
                ports=[102, 20000],
                is_inspected=True,
                inspection_device="SEL-2730M Managed Switch Port ACLs",
                is_encrypted=False,
                status="Active"
            ),
            Conduit(
                id="cnd-sub-02",
                name="Local HMI RTAC Polling (Level 2 -> Level 1)",
                from_zone_id="zone-sub-l2",
                to_zone_id="zone-sub-l1",
                allowed_protocols=["DNP3 over TCP"],
                ports=[20000],
                is_inspected=True,
                inspection_device="Substation Control House Firewall",
                is_encrypted=False,
                status="Active"
            ),
            Conduit(
                id="cnd-sub-03",
                name="NERC CIP Electronic Security Perimeter Conduit (Level 3.5 -> Level 1)",
                from_zone_id="zone-sub-l35",
                to_zone_id="zone-sub-l1",
                allowed_protocols=["DNP3-Secure", "IPsec Tunnel"],
                ports=[20000, 500],
                is_inspected=True,
                inspection_device="Ruggedcom ROX Firewall",
                is_encrypted=True,
                status="Active"
            )
        ]
    elif "Walmart" in facility or "Cold Chain" in facility:
        return [
            Conduit(
                id="cnd-wm-01",
                name="Conduit W1: Supervisory CIP & Gas Status (Level 2 -> Level 1)",
                from_zone_id="zone-wm-l2",
                to_zone_id="zone-wm-l1",
                allowed_protocols=["EtherNet/IP (CIP)", "Modbus TCP"],
                ports=[44818, 502],
                is_inspected=True,
                inspection_device="Cisco IE-3300 Port Security & Hardware ACLs",
                is_encrypted=False,
                status="Active"
            ),
            Conduit(
                id="cnd-wm-02",
                name="Conduit W2: SCADA Ingestion & FSMA Temperature Logging (Level 3 -> Level 1)",
                from_zone_id="zone-wm-l3",
                to_zone_id="zone-wm-l1",
                allowed_protocols=["Modbus TCP", "OPC UA"],
                ports=[502, 4840],
                is_inspected=True,
                inspection_device="Engine Room Distribution Switch ACL",
                is_encrypted=False,
                status="Active"
            ),
            Conduit(
                id="cnd-wm-03",
                name="Conduit W3: Cloud Edge Telemetry Feed (Level 3 -> Level 3.5)",
                from_zone_id="zone-wm-l3",
                to_zone_id="zone-wm-l35",
                allowed_protocols=["MQTT over TLS", "HTTPS"],
                ports=[8883, 443],
                is_inspected=True,
                inspection_device="IDMZ Edge Firewall",
                is_encrypted=True,
                status="Active"
            ),
            Conduit(
                id="cnd-wm-04",
                name="Conduit W4: Technician Tablet Wireless Maintenance (UNINSPECTED DUAL-HOMED VIOLATION)",
                from_zone_id="zone-wm-l3",
                to_zone_id="zone-wm-l1",
                allowed_protocols=["Rockwell FactoryTalk View", "VNC", "HTTP"],
                ports=[44818, 5900, 80],
                is_inspected=False,
                inspection_device=None,
                is_encrypted=False,
                status="Active"
            )
        ]
    else:  # Refinery
        return [
            Conduit(
                id="cnd-ref-01",
                name="DCS Vnet/IP Control Bus (Level 2 -> Level 1A)",
                from_zone_id="zone-ref-l2",
                to_zone_id="zone-ref-l1-bpcs",
                allowed_protocols=["Vnet/IP Proprietary", "Modbus TCP"],
                ports=[12345, 502],
                is_inspected=True,
                inspection_device="Yokogawa Vnet/IP Router",
                is_encrypted=False,
                status="Active"
            ),
            Conduit(
                id="cnd-ref-02",
                name="Read-Only SIS Safety Status Link (Level 1B -> Level 2)",
                from_zone_id="zone-ref-l1-sis",
                to_zone_id="zone-ref-l2",
                allowed_protocols=["Modbus TCP (Read-Only)"],
                ports=[502],
                is_inspected=True,
                inspection_device="Hardware Data Diode / Read-Only Gateway",
                is_encrypted=False,
                status="Active"
            ),
            Conduit(
                id="cnd-ref-03",
                name="Historian Data Collection (Level 3 -> Level 2)",
                from_zone_id="zone-ref-l3",
                to_zone_id="zone-ref-l2",
                allowed_protocols=["OPC UA Binary"],
                ports=[4840],
                is_inspected=True,
                inspection_device="Plant DMZ Firewall",
                is_encrypted=True,
                status="Active"
            )
        ]

def get_security_violations(facility: str) -> List[SecurityViolation]:
    """Automated security violations detected based on asset configurations and conduits."""
    if "Water" in facility:
        return [
            SecurityViolation(
                id="viol-wt-01",
                violation_type=SecurityViolationType.DUAL_HOMED_BRIDGE,
                severity=ViolationSeverity.CRITICAL,
                title="Dual-Homed Host Bridging Level 3 and Level 1 Directly",
                description="Engineering Workstation EWS-01-ENG has two network interfaces: one on the Level 3 engineering network (192.168.30.50) and a second physical adapter connected directly into the Level 1 PLC subnet (192.168.10.99), completely bypassing Level 2 supervisory firewalls.",
                affected_asset_ids=["wt-ews-01", "wt-plc-01"],
                affected_conduit_id="cnd-wt-03",
                standard_reference="ISA/IEC 62443-3-3 SR 5.2 / NIST SP 800-82r3 Section 5.3",
                remediation="Remove the secondary physical Ethernet interface from EWS-01-ENG. Require all engineering programming sessions to traverse a strictly brokered and authenticated jump host in Level 3.5."
            ),
            SecurityViolation(
                id="viol-wt-02",
                violation_type=SecurityViolationType.WEAK_KEYSWITCH_REMOTE,
                severity=ViolationSeverity.HIGH,
                title="Critical Intake PLC Key Switch Left in REMOTE Position",
                description="Primary controller PLC-01-MAIN has its physical hardware key switch positioned in 'REMOTE RUN' (REM). This allows unauthenticated network users with CIP access to upload modified ladder logic, download program changes, or force I/O without physical plant access.",
                affected_asset_ids=["wt-plc-01"],
                standard_reference="CISA Cross-Sector CPG 2.I / IEC 62443-4-2 CR 1.1",
                remediation="Instruct control room shift technician to rotate the physical chassis key switch to 'RUN' (hardware memory write protect). Store the physical key in a locked master lockbox."
            ),
            SecurityViolation(
                id="viol-wt-03",
                violation_type=SecurityViolationType.UNINSPECTED_CROSS_ZONE,
                severity=ViolationSeverity.MEDIUM,
                title="Uninspected Cleartext HTTP Admin Enabled on Core Industrial Switch",
                description="Core switch SW-01-IND has an active HTTP server on TCP port 80 enabled for web management across the supervisory zone without TLS encryption.",
                affected_asset_ids=["wt-sw-01"],
                standard_reference="ISA/IEC 62443-4-2 CR 4.3 (Data Confidentiality)",
                remediation="Disable HTTP web administration via switch CLI: `no ip http server` and enforce SSHv2 / HTTPS-only management with strong ciphers."
            )
        ]
    elif "Substation" in facility:
        return [
            SecurityViolation(
                id="viol-sub-01",
                violation_type=SecurityViolationType.DEFAULT_CREDENTIALS,
                severity=ViolationSeverity.HIGH,
                title="Unpatched Treck IP Stack Ripple20 on Substation RTAC",
                description="SEL-3530 RTAC is running firmware revision R149-V0 which contains vulnerable embedded Treck TCP/IP stack components subject to remote heap buffer overflow.",
                affected_asset_ids=["sub-rtu-01"],
                standard_reference="NERC CIP-007-6 R2 (Cyber Security - Systems Security Management)",
                remediation="Schedule maintenance outage to upgrade RTAC firmware to R151 or newer; apply compensating control by restricting port 20000 access exclusively to authenticated control center IP addresses."
            )
        ]
    elif "Walmart" in facility or "Cold Chain" in facility:
        return [
            SecurityViolation(
                id="viol-wm-01",
                violation_type=SecurityViolationType.DUAL_HOMED_BRIDGE,
                severity=ViolationSeverity.CRITICAL,
                title="Dual-Homed Maintenance Tablet Bridging Dock Wi-Fi to Ammonia PLC Subnet",
                description="Dock Technician Maintenance Tablet (TAB-DOCK-TECH) is connected simultaneously to the facility corporate Wi-Fi (10.240.50.88) and physically tethered via USB-Ethernet adapter directly into Ammonia Engine Room Subnet (192.168.10.77), establishing an uninspected pivot route into life-critical refrigeration controllers.",
                affected_asset_ids=["wm-tablet-dock", "wm-plc-nh3-01"],
                affected_conduit_id="cnd-wm-04",
                standard_reference="ISA/IEC 62443-3-3 SR 5.2 / NIST SP 800-82r3 Section 5.3",
                remediation="Disable multi-homed network adapter bridging on technician field tablets. Restrict dock tablets to dedicated management VLAN with 802.1X enterprise authentication."
            ),
            SecurityViolation(
                id="viol-wm-02",
                violation_type=SecurityViolationType.WEAK_KEYSWITCH_REMOTE,
                severity=ViolationSeverity.HIGH,
                title="Ammonia Screw Compressor Controller Key Switch Left in REMOTE Mode",
                description="Frick Quantum HD Screw Compressor #2 (PLC-NH3-COMP-02) key switch is set to REMOTE RUN rather than RUN. This permits remote firmware modification and parameter overrides over network ports without physical verification.",
                affected_asset_ids=["wm-plc-nh3-02"],
                standard_reference="CISA Cross-Sector CPG 2.I / IEC 62443-4-2 CR 1.1",
                remediation="Rotate Frick controller key switch to RUN position (hardware write protection). Mandate physical lock-out/tag-out (LOTO) procedure during logic revisions."
            ),
            SecurityViolation(
                id="viol-wm-03",
                violation_type=SecurityViolationType.UNINSPECTED_CROSS_ZONE,
                severity=ViolationSeverity.HIGH,
                title="Uninspected Direct Wi-Fi Maintenance Conduit Bypassing Security Filtering",
                description="Conduit W4 connects Level 3 Maintenance Tablet directly to Level 1 Ammonia controllers without stateful inspection, DPI firewall, or MFA jump host.",
                affected_asset_ids=["wm-tablet-dock", "wm-plc-nh3-02"],
                affected_conduit_id="cnd-wm-04",
                standard_reference="ISA/IEC 62443-3-3 SR 3.1 & SR 5.1",
                remediation="Terminate wireless maintenance sessions at an IDMZ jump proxy with session recording and multi-factor authentication before granting OT access."
            )
        ]
    else:  # Refinery
        return [
            SecurityViolation(
                id="viol-ref-01",
                violation_type=SecurityViolationType.DIRECT_IT_TO_OT,
                severity=ViolationSeverity.CRITICAL,
                title="Legacy End-of-Support S7-400H Boiler Controller with Remote Key Switch",
                description="SIMATIC S7-400H boiler controller PLC-BOILER-400 is running legacy firmware v4.5.7 that reached End of Support in 2018. It lacks cryptographic session integrity and has its key switch set to REMOTE RUN, leaving high-pressure steam boilers vulnerable to cleartext S7comm stop commands.",
                affected_asset_ids=["ref-plc-01"],
                standard_reference="ISA/IEC 62443-3-3 SR 3.1 & SR 5.1 / CISA ICS Advisory ICSA-19-192-01",
                remediation="Deploy an inline industrial security appliance (e.g., Belden Tofino Xenon or FL mGuard) with deep packet inspection (DPI) to enforce read-only S7comm function codes; lock the physical key switch to RUN."
            )
        ]

def get_ics_advisories() -> List[ICSAdvisory]:
    """Real-world ICS-CERT advisories and CVEs affecting common OT hardware and firmware."""
    return [
        ICSAdvisory(
            advisory_id="ICSA-22-104-01",
            cve_id="CVE-2022-1159",
            title="Rockwell Automation Logix Controllers CIP User Program Modification",
            vendor="Rockwell Automation",
            affected_models=["ControlLogix 5580", "CompactLogix 5380", "1756-L83E", "1756-L85E"],
            affected_firmware_pattern=r"^(3[0-3]\..*)$",  # Versions 30.x through 33.x
            cvss_base_score=8.8,
            severity=CVSSSeverity.HIGH,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-284 (Improper Access Control)",
            description="A vulnerability exists in Logix 5580 controllers that allows an authenticated attacker to alter executable user ladder logic code without triggering an unauthorized program change alert.",
            remediation="Upgrade to firmware version 34.011 or later. If upgrading is delayed, rotate the physical controller key switch to RUN mode to physically disable program modifications.",
            recommended_compensating_controls=[
                CompensatingControlType.PHYSICAL_KEY_SWITCH,
                CompensatingControlType.DPI_INDUSTRIAL_FIREWALL
            ],
            published_date="2022-04-14"
        ),
        ICSAdvisory(
            advisory_id="ICSA-21-056-03",
            cve_id="CVE-2021-22681",
            title="Rockwell Automation Logix Controllers Unauthenticated CIP Authentication Bypass",
            vendor="Rockwell Automation",
            affected_models=["ControlLogix 5580", "CompactLogix 5380", "GuardLogix 5580"],
            affected_firmware_pattern=r"^(3[0-2]\..*|33\.01[0-2])$",
            cvss_base_score=10.0,
            severity=CVSSSeverity.CRITICAL,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            cwe_id="CWE-306 (Missing Authentication for Critical Function)",
            description="The secret cryptographic signing key used to authenticate CIP connections was extracted, allowing attackers to forge trusted communication and upload malicious controller code.",
            remediation="Deploy CIP Security (TLS/DTLS) with FactoryTalk Policy Manager, or restrict port 44818 at industrial firewall boundaries.",
            recommended_compensating_controls=[
                CompensatingControlType.DPI_INDUSTRIAL_FIREWALL,
                CompensatingControlType.NETWORK_MICROSEGMENTATION,
                CompensatingControlType.PHYSICAL_KEY_SWITCH
            ],
            published_date="2021-02-25"
        ),
        ICSAdvisory(
            advisory_id="ICSA-20-254-01",
            cve_id="CVE-2020-15782",
            title="Siemens SIMATIC S7-1200 / S7-1500 Memory Protection Bypass",
            vendor="Siemens",
            affected_models=["CPU 1518-4 PN/DP", "S7-1500", "S7-1200"],
            affected_firmware_pattern=r"^(2\.[0-8]\..*)$",  # Firmware < 2.9.2
            cvss_base_score=8.1,
            severity=CVSSSeverity.HIGH,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-119 (Memory Buffer Errors)",
            description="A memory protection bypass allows an attacker with write access to copy arbitrary code into protected CPU memory areas and execute native machine code on the PLC.",
            remediation="Update S7-1500 CPU firmware to V2.9.2 or later. Implement access protection passwords in TIA Portal.",
            recommended_compensating_controls=[
                CompensatingControlType.DPI_INDUSTRIAL_FIREWALL,
                CompensatingControlType.PHYSICAL_KEY_SWITCH
            ],
            published_date="2020-09-10"
        ),
        ICSAdvisory(
            advisory_id="ICSA-20-168-01",
            cve_id="CVE-2020-11896",
            title="Treck TCP/IP Stack Ripple20 Remote Code Execution in Embedded Devices",
            vendor="Schweitzer Engineering Laboratories",
            affected_models=["SEL-3530 Real-Time Automation Controller (RTAC)"],
            affected_firmware_pattern=r"^(R14[0-9].*)$",
            cvss_base_score=9.8,
            severity=CVSSSeverity.CRITICAL,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-122 (Heap-based Buffer Overflow)",
            description="Improper handling of incoming IPv4 packet fragments allows an unauthenticated network adversary to trigger remote code execution or fatal device reboot.",
            remediation="Upgrade SEL RTAC firmware to version R150 or later. Block malformed IP fragments at perimeter firewalls.",
            recommended_compensating_controls=[
                CompensatingControlType.DPI_INDUSTRIAL_FIREWALL,
                CompensatingControlType.DATA_DIODE
            ],
            published_date="2020-06-16"
        ),
        ICSAdvisory(
            advisory_id="ICSA-22-298-01",
            cve_id="CVE-2022-38465",
            title="Siemens SIMATIC S7-1500 & SIPROTEC Global Cryptographic Key Extraction",
            vendor="Siemens",
            affected_models=["SIPROTEC 5 7UT85", "CPU 1518-4 PN/DP"],
            affected_firmware_pattern=r"^(V08\.[0-8].*|2\.[0-8]\..*)$",
            cvss_base_score=9.3,
            severity=CVSSSeverity.CRITICAL,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-321 (Use of Hard-coded Cryptographic Key)",
            description="Researchers extracted the internal symmetric hardware key protecting Siemens communications, enabling decryption and spoofing of firmware packets.",
            remediation="Apply Siemens DIGSI V09 update which transitions to individual TLS device certificates.",
            recommended_compensating_controls=[
                CompensatingControlType.NETWORK_MICROSEGMENTATION,
                CompensatingControlType.DPI_INDUSTRIAL_FIREWALL
            ],
            published_date="2022-10-25"
        ),
        ICSAdvisory(
            advisory_id="ICSA-20-042-02",
            cve_id="CVE-2020-6967",
            title="Rockwell Automation 1756-EN2T Ethernet Communication Module Denial of Service",
            vendor="Rockwell Automation",
            affected_models=["1756-EN2T"],
            affected_firmware_pattern=r"^(5\.0[0-2][0-9])$",
            cvss_base_score=7.5,
            severity=CVSSSeverity.HIGH,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            cwe_id="CWE-400 (Uncontrolled Resource Consumption)",
            description="Specially crafted CIP requests to the 1756-EN2T bridge cause the communication stack to lock up, severing all HMI and SCADA polling to the PLC rack.",
            remediation="Update 1756-EN2T firmware to version 5.030 or later.",
            recommended_compensating_controls=[
                CompensatingControlType.DPI_INDUSTRIAL_FIREWALL
            ],
            published_date="2020-02-11"
        ),
        ICSAdvisory(
            advisory_id="ICSA-22-263-02",
            cve_id="CVE-2022-30512",
            title="Johnson Controls Frick Quantum HD Unity Memory Corruption & Denial of Service",
            vendor="Johnson Controls / Frick",
            affected_models=["Quantum HD", "Quantum HD Unity"],
            affected_firmware_pattern=r"^(10\.[0-4][0-9].*)$",
            cvss_base_score=7.8,
            severity=CVSSSeverity.HIGH,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
            cwe_id="CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer)",
            description="A buffer error vulnerability allows remote unauthenticated attackers to send crafted TCP packets to the Frick Quantum HD web and communications server, causing controller crash, loss of screw compressor regulation, or arbitrary memory corruption.",
            remediation="Upgrade Frick Quantum HD firmware to version 10.50.00 or higher. Place the physical key switch in RUN mode and restrict TCP port 80/44818 at the industrial firewall.",
            recommended_compensating_controls=[
                CompensatingControlType.PHYSICAL_KEY_SWITCH,
                CompensatingControlType.DPI_INDUSTRIAL_FIREWALL
            ],
            published_date="2022-09-20"
        )
    ]

def get_lifecycle_milestones() -> List[LifecycleMilestone]:
    """Lifecycle milestones for major industrial hardware lines."""
    return [
        LifecycleMilestone(
            model="ControlLogix 5580 (1756-L83E)",
            vendor="Rockwell Automation",
            release_year=2016,
            eol_year=2035,
            eos_year=2040,
            state=LifecycleState.ACTIVE,
            replacement_model="Current Flagship Controller",
            description="Active mainstream production platform for large process and safety applications."
        ),
        LifecycleMilestone(
            model="ControlLogix 5570 (1756-L73)",
            vendor="Rockwell Automation",
            release_year=2011,
            eol_year=2024,
            eos_year=2028,
            state=LifecycleState.MATURE,
            replacement_model="ControlLogix 5580 (1756-L83E)",
            description="Mature product status. Recommended for modernization on upcoming capital refresh."
        ),
        LifecycleMilestone(
            model="ControlLogix 5555 (1756-L55)",
            vendor="Rockwell Automation",
            release_year=1999,
            eol_year=2014,
            eos_year=2018,
            state=LifecycleState.DISCONTINUED,
            replacement_model="ControlLogix 5580",
            description="Obsolete hardware. No security patches or spare parts available from manufacturer."
        ),
        LifecycleMilestone(
            model="SIMATIC S7-1500 (CPU 1518)",
            vendor="Siemens",
            release_year=2013,
            eol_year=2035,
            eos_year=2040,
            state=LifecycleState.ACTIVE,
            replacement_model="Current Standard",
            description="Active standard controller platform for complex automation tasks."
        ),
        LifecycleMilestone(
            model="SIMATIC S7-400H (6ES7414)",
            vendor="Siemens",
            release_year=1998,
            eol_year=2023,
            eos_year=2025,
            state=LifecycleState.END_OF_SUPPORT,
            replacement_model="SIMATIC S7-1500R/H Redundant",
            description="Legacy S7-400 architecture. End of support reached; replacement required to maintain cyber posture."
        ),
        LifecycleMilestone(
            model="SEL-3530 RTAC",
            vendor="Schweitzer Engineering Laboratories",
            release_year=2010,
            eol_year=2030,
            eos_year=2035,
            state=LifecycleState.ACTIVE,
            replacement_model="SEL-3555 / SEL-3560",
            description="Supported automation controller with regular ROX/RTOS firmware security updates."
        ),
        LifecycleMilestone(
            model="Frick Quantum HD",
            vendor="Johnson Controls / Frick",
            release_year=2012,
            eol_year=2030,
            eos_year=2035,
            state=LifecycleState.ACTIVE,
            replacement_model="Quantum HD Gen 2",
            description="Mainstream refrigeration screw compressor automation platform widely deployed in cold storage and food processing facilities."
        ),
        LifecycleMilestone(
            model="Copeland E3 Supervisory Controller",
            vendor="Emerson / Copeland",
            release_year=2021,
            eol_year=2038,
            eos_year=2042,
            state=LifecycleState.ACTIVE,
            replacement_model="Current Standard",
            description="Modern rack and facility management controller for grocery and temperature-controlled logistics."
        )
    ]
