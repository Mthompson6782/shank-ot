import pytest
from otbase.models.asset import Asset, DeviceType, PurdueLevel, Criticality, KeySwitchMode
from otbase.db.seed_data import get_ics_advisories, get_rockwell_water_chassis
from otbase.engine.cve_matcher import CVEMatcher

def test_cve_matching_on_asset_and_rack_module():
    advisories = get_ics_advisories()
    chassis = get_rockwell_water_chassis()

    asset = Asset(
        id="test-clx-1",
        tag_name="PLC-MAIN",
        display_name="Main ControlLogix 5580",
        vendor="Rockwell Automation",
        model="ControlLogix 5580",
        catalog_number="1756-L83E",
        firmware_version="33.011",
        device_type=DeviceType.PLC,
        purdue_level=PurdueLevel.LEVEL_1,
        criticality=Criticality.HIGH,
        key_switch=KeySwitchMode.REMOTE_RUN,
        chassis=chassis
    )

    matches = CVEMatcher.match_asset(asset, advisories)
    assert len(matches) > 0

    cve_ids = [m.cve_id for m in matches]
    # Check that CVE-2022-1159 (CIP tamper) matched controller
    assert "CVE-2022-1159" in cve_ids
    # Check that CVE-2020-6967 matched the 1756-EN2T comm module in slot 2!
    assert "CVE-2020-6967" in cve_ids

    # Check slot module CVE was recorded
    slot2 = next(m for m in asset.chassis.modules if m.slot == 2)
    assert "CVE-2020-6967" in slot2.cves
