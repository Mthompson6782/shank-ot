from otbase.discovery.switch_interrogator import SwitchInterrogator
from otbase.models.asset import Asset, DeviceType, PurdueLevel, NetworkInterface
from otbase.models.pid_schema import SwitchPortDiscovery, SwitchPortLearnedMac

def test_deterministic_physical_link_resolution():
    switches = [
        Asset(
            id="sw-test-01",
            tag_name="SW-TEST-01",
            display_name="Test Stratix Switch",
            vendor="Rockwell",
            model="Stratix 5700",
            device_type=DeviceType.INDUSTRIAL_SWITCH,
            purdue_level=PurdueLevel.LEVEL_2,
            network_interfaces=[
                NetworkInterface(mac_address="00:1D:9C:00:11:22", ip_address="192.168.20.2")
            ]
        )
    ]

    endpoints = [
        Asset(
            id="plc-test-01",
            tag_name="PLC-TEST-01",
            display_name="Test ControlLogix",
            vendor="Rockwell",
            model="ControlLogix 5580",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            network_interfaces=[
                NetworkInterface(mac_address="00:1D:9C:33:44:55", ip_address="192.168.10.10")
            ]
        )
    ]

    telemetry = [
        SwitchPortDiscovery(
            switch_ip="192.168.20.2",
            switch_name="SW-TEST-01",
            if_index=1,
            if_name="FastEthernet1/1",
            learned_macs=[SwitchPortLearnedMac(mac_address="00:1D:9C:33:44:55", vlan_id=10)]
        )
    ]

    bindings = SwitchInterrogator.resolve_physical_links(switches, endpoints, telemetry)
    assert len(bindings) == 1
    assert bindings[0]["status"] == "Deterministic L1 Link Resolved"
    assert bindings[0]["bound_asset_id"] == "plc-test-01"
    assert bindings[0]["port_name"] == "FastEthernet1/1"

    # Verify endpoint interface was bound
    iface = endpoints[0].network_interfaces[0]
    assert iface.switch_port is not None
    assert iface.switch_port.port_name == "FastEthernet1/1"
    assert iface.switch_port.switch_asset_id == "sw-test-01"
