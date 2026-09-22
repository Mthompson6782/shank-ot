"""
Armis Data Schema & Models
==========================
Defines models for Armis REST API payloads (devices, boundaries, connections),
Purdue level mapping, and reconciliation discrepancy reports.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime, timezone


class ArmisCategory(str, Enum):
    INDUSTRIAL = "Industrial"
    NETWORK = "Network Equipment"
    COMPUTERS = "Computers"
    IOT = "IoT"
    MOBILE = "Mobile"
    SECURITY = "Security"
    UNKNOWN = "Unknown"


class ArmisDeviceType(str, Enum):
    PLC = "PLC"
    HMI = "HMI"
    SCADA_SERVER = "SCADA Server"
    ENGINEERING_WORKSTATION = "Engineering Workstation"
    HISTORIAN = "Historian"
    INDUSTRIAL_SWITCH = "Industrial Switch"
    FIREWALL = "Firewall"
    RTU = "RTU"
    SENSOR = "Sensor"
    DRIVE = "Drive"
    CAMERA = "IP Camera"
    BARCODE_SCANNER = "Barcode Scanner"
    TABLET = "Tablet"
    WORKSTATION = "Workstation"
    UNKNOWN = "Unknown"


class ArmisDeviceRecord(BaseModel):
    """Raw or normalized representation of an asset returned by Armis API."""
    model_config = ConfigDict(populate_by_name=True)

    id: int = Field(..., description="Armis internal device ID")
    name: str = Field(..., description="Device hostname or asset label")
    ip_address: Optional[str] = Field(None, alias="ipAddress", description="Primary IPv4 address")
    mac_address: Optional[str] = Field(None, alias="macAddress", description="Hardware MAC address")
    manufacturer: Optional[str] = Field(None, description="Vendor / Manufacturer")
    model: Optional[str] = Field(None, description="Hardware model or product family")
    category: str = Field(default="Industrial", description="Armis device category")
    device_type: str = Field(default="PLC", alias="type", description="Armis device type")
    operating_system: Optional[str] = Field(None, alias="operatingSystem", description="OS or firmware family")
    operating_system_version: Optional[str] = Field(None, alias="operatingSystemVersion", description="Firmware version")
    risk_level: int = Field(default=0, alias="riskLevel", description="Armis 0-10 risk rating")
    site: Optional[str] = Field(default=None, description="Physical site or plant location")
    boundaries: List[str] = Field(default_factory=list, description="Network zones / perimeter boundaries")
    switch_ip: Optional[str] = Field(None, alias="switch", description="IP of the switch this device attaches to")
    switch_name: Optional[str] = Field(None, alias="switchName", description="Host/tag of the switch")
    switch_port: Optional[str] = Field(None, alias="switchPort", description="Switch port name (e.g. FastEthernet1/1)")
    vlan: Optional[int] = Field(None, description="VLAN ID observed by Armis")
    protocols: List[str] = Field(default_factory=list, description="Protocols observed by Armis DPI")
    vulnerabilities: List[str] = Field(default_factory=list, description="CVE IDs identified on this device")
    first_seen: Optional[str] = Field(None, alias="firstSeen", description="Timestamp first seen")
    last_seen: Optional[str] = Field(None, alias="lastSeen", description="Timestamp last seen")
    tags: List[str] = Field(default_factory=list, description="Custom tags assigned in Armis")


class ArmisConnectionRecord(BaseModel):
    """Observed communication flow between devices captured by Armis."""
    connection_id: str = Field(..., description="Unique connection session ID")
    source_ip: str = Field(..., description="Source IPv4 address")
    source_port: int = Field(..., description="Source TCP/UDP port")
    destination_ip: str = Field(..., description="Destination IPv4 address")
    destination_port: int = Field(..., description="Destination TCP/UDP port")
    protocol: str = Field(..., description="Protocol (e.g. CIP, Modbus, S7, HTTPS, SSH)")
    byte_count: int = Field(default=0, description="Total bytes exchanged")
    packet_count: int = Field(default=0, description="Total packets exchanged")
    start_time: Optional[str] = Field(None, description="Session start ISO timestamp")
    last_activity: Optional[str] = Field(None, description="Last activity ISO timestamp")
    boundary_crossed: Optional[str] = Field(None, description="Identified zone boundary crossed")


class DiscrepancyType(str, Enum):
    FIRMWARE_MISMATCH = "FIRMWARE_MISMATCH"
    PORT_MISMATCH = "PORT_MISMATCH"
    ROGUE_ASSET = "ROGUE_ASSET"
    DORMANT_ASSET = "DORMANT_ASSET"
    UNMANAGED_SWITCH_SHADOW = "UNMANAGED_SWITCH_SHADOW"
    VULNERABILITY_GAP = "VULNERABILITY_GAP"


class DiscrepancySeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReconciliationDiscrepancy(BaseModel):
    """Specific discrepancy between Armis passive visibility and OTbase ground truth."""
    discrepancy_type: DiscrepancyType
    severity: DiscrepancySeverity
    asset_id: Optional[str] = None
    asset_tag: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    armis_value: Any = None
    ground_truth_value: Any = None
    description: str
    remediation_recommendation: str
    detected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ReconciliationReport(BaseModel):
    """Overall summary of Armis vs OTbase ground-truth reconciliation."""
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_armis_devices: int = 0
    total_otbase_assets: int = 0
    correlated_assets_count: int = 0
    rogue_assets_count: int = 0
    dormant_assets_count: int = 0
    discrepancies: List[ReconciliationDiscrepancy] = Field(default_factory=list)
    summary_by_type: Dict[str, int] = Field(default_factory=dict)
