import pytest
from otbase.models.asset import Chassis, RackModule, ModuleType, LEDStatus, LEDColor
from otbase.db.seed_data import get_rockwell_water_chassis

def test_rack_chassis_structure():
    chassis = get_rockwell_water_chassis()
    assert chassis.total_slots == 10
    assert len(chassis.modules) == 8

    # Slot 0 is power supply
    slot0 = chassis.modules[0]
    assert slot0.slot == 0
    assert slot0.module_type == ModuleType.POWER_SUPPLY
    assert slot0.catalog_number == "1756-PA72"

    # Slot 1 is CPU
    slot1 = chassis.modules[1]
    assert slot1.slot == 1
    assert slot1.module_type == ModuleType.CONTROLLER
    assert slot1.catalog_number == "1756-L83E"
    assert slot1.firmware_version == "33.011"
    assert len(slot1.status_leds) >= 3

    # Slot 2 is Ethernet Comm Adapter
    slot2 = chassis.modules[2]
    assert slot2.slot == 2
    assert slot2.module_type == ModuleType.COMM_ADAPTER
    assert slot2.catalog_number == "1756-EN2T"
    assert slot2.firmware_version == "5.028"
