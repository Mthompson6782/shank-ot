import pytest
from otbase.models.asset import (
    Asset, NetworkInterface, SerialPort, DeviceType, PurdueLevel, Criticality, KeySwitchMode
)

def test_asset_creation_and_defaults():
    asset = Asset(
        id="test-plc-01",
        tag_name="PLC-TEST",
        display_name="Test Controller",
        vendor="Rockwell Automation",
        model="1756-L83E",
        device_type=DeviceType.PLC,
        purdue_level=PurdueLevel.LEVEL_1,
        criticality=Criticality.HIGH,
        key_switch=KeySwitchMode.RUN,
        network_interfaces=[
            NetworkInterface(
                name="eth0",
                mac_address="00:1D:9C:AA:BB:CC",
                ip_address="192.168.10.50"
            )
        ]
    )

    assert asset.id == "test-plc-01"
    assert asset.tag_name == "PLC-TEST"
    assert asset.purdue_level == PurdueLevel.LEVEL_1
    assert asset.key_switch == KeySwitchMode.RUN
    assert len(asset.network_interfaces) == 1
    assert asset.network_interfaces[0].ip_address == "192.168.10.50"
    assert asset.ot_risk_score == 0.0

def test_key_switch_modes():
    assert KeySwitchMode.RUN.value.startswith("RUN")
    assert KeySwitchMode.REMOTE_RUN.value.startswith("REM")
