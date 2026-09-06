import pytest
from otbase.models.asset import Asset, DeviceType, PurdueLevel, Criticality, KeySwitchMode, NetworkInterface
from otbase.models.topology import PurdueZone, Conduit, SecurityViolationType
from otbase.engine.topology_analyzer import TopologyAnalyzer

def test_dual_homed_violation_detection():
    # Asset in Level 3 with a second NIC in Level 1 subnet
    dual_homed_ews = Asset(
        id="ews-01",
        tag_name="EWS-01",
        display_name="Engineering Workstation",
        vendor="Dell",
        model="Precision 3640",
        device_type=DeviceType.ENGINEERING_WORKSTATION,
        purdue_level=PurdueLevel.LEVEL_3,
        network_interfaces=[
            NetworkInterface(name="Plant LAN", mac_address="00:50:56:01:02:03", ip_address="192.168.30.50"),
            NetworkInterface(name="Direct Control NIC", mac_address="00:50:56:01:02:04", ip_address="192.168.10.99")
        ]
    )

    zones = [
        PurdueZone(id="z3", name="Level 3 Zone", purdue_level="Level 3 - Operations & Historians", facility="Plant", description="Ops"),
        PurdueZone(id="z1", name="Level 1 Zone", purdue_level="Level 1 - Basic Control (PLCs/RTUs)", facility="Plant", description="Control")
    ]
    conduits = []

    violations = TopologyAnalyzer.audit([dual_homed_ews], zones, conduits)
    assert len(violations) >= 1
    assert any(v.violation_type == SecurityViolationType.DUAL_HOMED_BRIDGE for v in violations)

def test_uninspected_conduit_violation():
    zones = [
        PurdueZone(id="z2", name="Level 2 Zone", purdue_level="Level 2 - Supervisory / HMIs", facility="Plant", description="HMI"),
        PurdueZone(id="z1", name="Level 1 Zone", purdue_level="Level 1 - Basic Control (PLCs/RTUs)", facility="Plant", description="PLC")
    ]
    conduit = Conduit(
        id="cnd-1",
        name="Uninspected Link",
        from_zone_id="z2",
        to_zone_id="z1",
        is_inspected=False
    )

    violations = TopologyAnalyzer.audit([], zones, [conduit])
    assert any(v.violation_type == SecurityViolationType.UNINSPECTED_CROSS_ZONE for v in violations)
