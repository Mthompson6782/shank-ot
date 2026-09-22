from otbase.engine.location_engine import LocationEngine
from otbase.models.asset import Asset, DeviceType, PurdueLevel, NetworkInterface
from otbase.models.location_tree import LocationTier, OTSystem

def test_duplicate_ip_disambiguation():
    # Simulate two identical OEM machine skids configuring the same private IP (192.168.1.50)
    assets = [
        Asset(
            id="plc-skid-1",
            tag_name="PLC-SKID-01",
            display_name="Skid 1 Coagulation Controller",
            vendor="Rockwell",
            model="CompactLogix",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            location_id="loc-skid-01",
            location_path="Water Plant/Building 1/Room A/Skid 1",
            network_interfaces=[NetworkInterface(mac_address="00:1D:9C:01:01:01", ip_address="192.168.1.50")]
        ),
        Asset(
            id="plc-skid-2",
            tag_name="PLC-SKID-02",
            display_name="Skid 2 Flocculation Controller (OEM Duplicate)",
            vendor="Rockwell",
            model="CompactLogix",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            location_id="loc-skid-02",
            location_path="Water Plant/Building 1/Room A/Skid 2",
            network_interfaces=[NetworkInterface(mac_address="00:1D:9C:02:02:02", ip_address="192.168.1.50")]
        )
    ]

    report = LocationEngine.disambiguate_duplicate_ips(assets)
    assert report["total_duplicate_ips_tracked"] == 1
    cluster = report["duplicate_subnets"][0]
    assert cluster["ip_address"] == "192.168.1.50"
    assert cluster["collision_count"] == 2
    assert cluster["assets"][0]["location_id"] != cluster["assets"][1]["location_id"]

def test_shared_trunk_switch_detection():
    systems = [
        OTSystem(
            id="sys-1",
            name="Intake Pumping System",
            description="Intake pumps",
            facility="Plant",
            shared_switch_ids=["SW-CORE-01"]
        ),
        OTSystem(
            id="sys-2",
            name="Chemical Treatment System",
            description="Chemical feed",
            facility="Plant",
            shared_switch_ids=["SW-CORE-01"]
        )
    ]

    shared = LocationEngine.find_shared_trunk_switches(systems)
    assert len(shared) == 1
    assert shared[0]["switch_id"] == "SW-CORE-01"
    assert "Intake Pumping System" in shared[0]["serving_systems"]
    assert "Chemical Treatment System" in shared[0]["serving_systems"]
