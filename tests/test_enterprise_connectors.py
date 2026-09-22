from otbase.exporter.enterprise_connectors import EnterpriseConnectors
from otbase.models.asset import Asset, DeviceType, PurdueLevel, NetworkInterface, SwitchPortBinding
from otbase.models.topology import Conduit

def test_servicenow_cmdb_payload():
    assets = [
        Asset(
            id="plc-01",
            tag_name="PLC-01",
            display_name="Main Controller",
            vendor="Rockwell Automation",
            model="ControlLogix 5580",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            network_interfaces=[
                NetworkInterface(
                    mac_address="00:1D:9C:AA:BB:CC",
                    ip_address="192.168.10.10",
                    switch_port=SwitchPortBinding(
                        switch_asset_id="sw-01",
                        port_name="FastEthernet1/1",
                        vlan_id=10
                    )
                )
            ]
        )
    ]

    payload = EnterpriseConnectors.generate_servicenow_cmdb_payload(assets, "Water Plant")
    assert payload["source"] == "OTbase Service Graph Connector"
    assert payload["records_count"] == 1
    rec = payload["records"][0]
    assert rec["sys_class_name"] == "cmdb_ci_industrial_plc"
    assert rec["switch_port_attachment"]["switch_port"] == "FastEthernet1/1"
    assert rec["switch_port_attachment"]["vlan"] == 10

def test_splunk_and_firewall_rules():
    assets = [
        Asset(
            id="plc-01",
            tag_name="PLC-01",
            display_name="Main Controller",
            vendor="Rockwell Automation",
            model="ControlLogix 5580",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            network_interfaces=[NetworkInterface(mac_address="00:1D:9C:AA:BB:CC", ip_address="192.168.10.10")]
        )
    ]
    conduits = [
        Conduit(
            id="cnd-1",
            name="Supervisory Polling",
            from_zone_id="zone-l2",
            to_zone_id="zone-l1",
            allowed_protocols=["CIP"],
            ports=[44818],
            is_inspected=True
        )
    ]

    # Splunk events
    events = EnterpriseConnectors.generate_splunk_ta_events(assets, [])
    assert "CEF:0|Langner|OTbase" in events
    assert "PLC-01" in events

    # Firewall rules
    rules = EnterpriseConnectors.generate_firewall_rules(conduits, assets, "fortinet")
    assert "config firewall policy" in rules
    assert "set name \"CONDUIT_SUPERVISORY_POLLING\"" in rules
    assert "set service \"CIP\"" in rules
