from enum import Enum
from typing import List, Optional, Dict, Any
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

class LayoutPerspective(str, Enum):
    CONNECTIONS = "Connections Layout (L1/L2 Physical Ports)"
    LOCATIONS = "Locations Layout (Spatial Containment)"
    PURDUE_HIERARCHY = "Hierarchy (Purdue) Layout"
    NETWORKS = "Networks Layout (L3 Subnets)"
    ORGANIC = "Organic Layout (Force-Directed)"

class GraphNodeType(str, Enum):
    MANAGED_SWITCH = "managed_switch"
    UNMANAGED_SWITCH = "unmanaged_switch"
    ROUTER_FIREWALL = "router_firewall"
    PLC = "plc"
    HMI = "hmi"
    SCADA_SERVER = "scada_server"
    FIELD_DEVICE = "field_device"
    SUBNET = "subnet"
    LOCATION_BOX = "location_box"

class GraphNode(BaseModel):
    id: str
    label: str
    node_type: GraphNodeType
    x: float = 0.0
    y: float = 0.0
    width: float = 140.0
    height: float = 60.0
    purdue_level: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    location_id: Optional[str] = None
    location_path: Optional[str] = None
    is_unmanaged: bool = False
    parent_box_id: Optional[str] = None
    port_count: Optional[int] = None
    active_ports: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class GraphEdge(BaseModel):
    id: str
    source_id: str
    target_id: str
    source_port: Optional[str] = None
    target_port: Optional[str] = None
    edge_type: str = "discovered_l1"  # discovered_l1, manual_asserted, routed_l3, conduit
    is_manual: bool = False  # False = solid line (discovered), True = dashed line (manually asserted)
    vlan_id: Optional[int] = None
    waypoints: List[List[float]] = Field(default_factory=list)  # [[x, y], [x, y]] for Kandinsky 90-deg routing
    bandwidth_kbps: float = 0.0
    protocol: Optional[str] = None
    is_conduit_violation: bool = False

class TopologyPerspectiveData(BaseModel):
    perspective: LayoutPerspective
    facility: str
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    unmanaged_switch_count: int = 0
    orthogonal_grid_size: int = 20

