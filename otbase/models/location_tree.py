from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class LocationTier(str, Enum):
    ENTERPRISE = "Enterprise"
    SITE = "Site"
    BUILDING = "Building"
    CONTROL_ROOM = "Control Room"
    CABINET_SKID = "Cabinet / Skid"

class LocationNode(BaseModel):
    id: str
    name: str
    tier: LocationTier
    parent_id: Optional[str] = None
    description: Optional[str] = None
    facility: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class OTSystem(BaseModel):
    """
    Functional cyber-physical grouping (e.g. 'Boiler Feed Pump Skid', 'Fluid Catalytic Cracker Train A').
    Groups controllers, HMIs, drives, and network infrastructure into an operational system.
    """
    id: str
    name: str
    description: str
    facility: str
    primary_controller_id: Optional[str] = None
    asset_ids: List[str] = Field(default_factory=list)
    shared_switch_ids: List[str] = Field(default_factory=list)
    conduit_ids: List[str] = Field(default_factory=list)
    process_criticality: str = "High"
    total_bandwidth_kbps: float = 0.0
    active_alarms: int = 0
