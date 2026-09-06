from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class ViolationSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class SecurityViolationType(str, Enum):
    DIRECT_IT_TO_OT = "Direct IT-to-OT Perimeter Breach (Purdue Bypass)"
    UNINSPECTED_CROSS_ZONE = "Uninspected Cross-Zone Industrial Conduit"
    DUAL_HOMED_BRIDGE = "Dual-Homed Host Bridging Level 3 and Level 1"
    INSECURE_PLAINTEXT_MGMT = "Cleartext Administrative Protocol Traversing Conduits"
    WEAK_KEYSWITCH_REMOTE = "Safety-Critical PLC Key Switch Left in REMOTE Position"
    DEFAULT_CREDENTIALS = "Legacy Unauthenticated OT Protocol Endpoint Exposed"

class SecurityViolation(BaseModel):
    id: str
    violation_type: SecurityViolationType
    severity: ViolationSeverity
    title: str
    description: str
    affected_asset_ids: List[str] = Field(default_factory=list)
    affected_conduit_id: Optional[str] = None
    standard_reference: str = "ISA/IEC 62443-3-3"
    remediation: str

class PurdueZone(BaseModel):
    id: str
    name: str
    purdue_level: str
    facility: str
    description: str
    color: str = "#2563eb"
    asset_ids: List[str] = Field(default_factory=list)

class Conduit(BaseModel):
    id: str
    name: str
    from_zone_id: str
    to_zone_id: str
    allowed_protocols: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    is_inspected: bool = False
    inspection_device: Optional[str] = None
    is_encrypted: bool = False
    status: str = "Active"
