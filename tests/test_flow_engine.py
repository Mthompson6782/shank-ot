from otbase.engine.flow_engine import FlowEngine
from otbase.models.pid_schema import FlowTelemetryRecord
from otbase.models.asset import Asset, DeviceType, PurdueLevel, NetworkInterface

def test_sankey_generation_and_profiling():
    assets = [
        Asset(
            id="plc-01",
            tag_name="PLC-01",
            display_name="Intake PLC",
            vendor="Rockwell",
            model="5580",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            network_interfaces=[NetworkInterface(mac_address="00:11:22:33:44:55", ip_address="192.168.10.10")]
        ),
        Asset(
            id="hmi-01",
            tag_name="HMI-01",
            display_name="Operator HMI",
            vendor="AVEVA",
            model="InTouch",
            device_type=DeviceType.HMI,
            purdue_level=PurdueLevel.LEVEL_2,
            network_interfaces=[NetworkInterface(mac_address="00:11:22:33:44:66", ip_address="192.168.20.15")]
        )
    ]

    flows = [
        FlowTelemetryRecord(
            src_ip="192.168.20.15",
            dst_ip="192.168.10.10",
            src_port=49152,
            dst_port=44818,
            protocol="TCP",
            byte_count=104857600,  # 100 MB
            packet_count=150000,
            sampling_ratio=128
        )
    ]

    sankey = FlowEngine.generate_sankey_data(flows, assets)
    assert len(sankey["nodes"]) >= 2
    assert len(sankey["links"]) == 1
    assert sankey["links"][0]["value"] == 100.0

    # Profile asset
    profile = FlowEngine.profile_asset_traffic("192.168.10.10", flows, assets)
    assert profile["total_inbound_mb"] == 100.0
    assert len(profile["inbound_peers"]) == 1
    assert profile["inbound_peers"][0]["peer_name"] == "HMI-01"
