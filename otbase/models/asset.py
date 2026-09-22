from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class PurdueLevel(str, Enum):
    LEVEL_0 = "Level 0 - Process / Field"
    LEVEL_1 = "Level 1 - Basic Control (PLCs/RTUs)"
    LEVEL_2 = "Level 2 - Supervisory / HMIs"
    LEVEL_3 = "Level 3 - Operations & Historians"
    LEVEL_3_5 = "Level 3.5 - Industrial DMZ (IDMZ)"
    LEVEL_4 = "Level 4 - Enterprise IT / Business"

class DeviceType(str, Enum):
    PLC = "PLC (Programmable Logic Controller)"
    RTU = "RTU (Remote Terminal Unit)"
    IED = "IED (Intelligent Electronic Device / Relay)"
    DCS_CONTROLLER = "DCS Controller"
    SIS_CONTROLLER = "Safety Instrumented System (SIS)"
    HMI = "HMI (Human Machine Interface)"
    SCADA_SERVER = "SCADA / Supervisory Server"
    HISTORIAN = "Data Historian"
    ENGINEERING_WORKSTATION = "Engineering Workstation (EWS)"
    INDUSTRIAL_SWITCH = "Industrial Managed Switch"
    INDUSTRIAL_FIREWALL = "Industrial Security Appliance / Firewall"
    FIELD_DEVICE = "Field Sensor / Transmitter / Actuator"

class KeySwitchMode(str, Enum):
    RUN = "RUN (Hardware Memory Protected)"
    REMOTE_RUN = "REM (Remote Run - Network Modifiable)"
    REMOTE_PROG = "REM PROG (Remote Program)"
    PROG = "PROG (Program Mode - CPU Halted)"
    NOT_APPLICABLE = "N/A"

class Criticality(str, Enum):
    SAFETY_CRITICAL = "Safety Critical (SIL 2/3 / SIS)"
    HIGH = "High (Process Trip Risk)"
    MEDIUM = "Medium (Secondary Unit)"
    LOW = "Low (Non-Essential Telemetry)"

class ModuleType(str, Enum):
    POWER_SUPPLY = "Power Supply"
    CONTROLLER = "Controller / CPU"
    COMM_ADAPTER = "Communication Adapter"
    DIGITAL_INPUT = "Digital / Discrete Input"
    DIGITAL_OUTPUT = "Digital / Discrete Output"
    ANALOG_INPUT = "Analog Input"
    ANALOG_OUTPUT = "Analog Output"
    SAFETY_PARTNER = "Safety Partner / Guard Controller"
    SPECIALTY = "Motion / Specialty Module"

class LEDColor(str, Enum):
    GREEN = "green"
    FLASHING_GREEN = "flashing-green"
    RED = "red"
    FLASHING_RED = "flashing-red"
    AMBER = "amber"
    OFF = "off"

class LEDStatus(BaseModel):
    name: str
    state: LEDColor = LEDColor.GREEN

class SwitchPortBinding(BaseModel):
    switch_asset_id: str
    switch_name: Optional[str] = None
    port_name: str
    vlan_id: Optional[int] = 1
    is_uplink: bool = False
    resolution_method: str = "SNMP Bridge MIB dot1dTpFdbTable"

class NetworkInterface(BaseModel):
    name: str = "eth0"
    mac_address: str
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = "255.255.255.0"
    gateway: Optional[str] = None
    vlan: Optional[int] = None
    is_management: bool = False
    switch_port: Optional[SwitchPortBinding] = None

class SerialPort(BaseModel):
    name: str = "Channel 0"
    interface_type: str = "RS-232"
    protocol: str = "Modbus RTU"
    baud_rate: int = 19200
    parity: str = "None"
    stop_bits: int = 1

class RackModule(BaseModel):
    slot: int
    name: str
    catalog_number: str
    serial_number: Optional[str] = None
    hardware_revision: Optional[str] = "A"
    firmware_version: Optional[str] = "1.0.0"
    vendor: str
    module_type: ModuleType
    status_leds: List[LEDStatus] = Field(default_factory=list)
    description: Optional[str] = None
    cve_count: int = 0
    cves: List[str] = Field(default_factory=list)

class Chassis(BaseModel):
    model: str
    serial_number: Optional[str] = None
    total_slots: int = 10
    modules: List[RackModule] = Field(default_factory=list)

class Asset(BaseModel):
    id: str
    tag_name: str
    display_name: str
    vendor: str
    model: str
    catalog_number: Optional[str] = None
    serial_number: Optional[str] = None
    hardware_revision: Optional[str] = None
    firmware_version: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    device_type: DeviceType
    purdue_level: PurdueLevel
    facility: str = "Main Plant"
    area: str = "Process Area"
    production_line: Optional[str] = None
    workcell: Optional[str] = None
    location_id: Optional[str] = None
    location_path: Optional[str] = None
    system_id: Optional[str] = None
    system_name: Optional[str] = None
    criticality: Criticality = Criticality.HIGH
    key_switch: KeySwitchMode = KeySwitchMode.NOT_APPLICABLE
    chassis: Optional[Chassis] = None
    network_interfaces: List[NetworkInterface] = Field(default_factory=list)
    serial_ports: List[SerialPort] = Field(default_factory=list)
    first_discovered: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    configuration_hash: Optional[str] = None
    active_cves: List[str] = Field(default_factory=list)
    ot_risk_score: float = 0.0
    lifecycle_state: str = "Active"
    is_compromised_simulated: bool = False
    notes: Optional[str] = None
