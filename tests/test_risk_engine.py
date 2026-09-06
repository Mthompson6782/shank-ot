import pytest
from otbase.models.asset import Asset, PurdueLevel, Criticality, KeySwitchMode, DeviceType
from otbase.models.vulnerability import CompensatingControl, CompensatingControlType
from otbase.engine.risk_engine import OTRiskEngine

def test_ot_risk_calculation():
    # Base CVSS = 8.8 (High) on Level 1 PLC with Safety-Critical criticality in REMOTE_RUN mode
    score_remote = OTRiskEngine.calculate_score(
        base_cvss_max=8.8,
        purdue_level=PurdueLevel.LEVEL_1,
        criticality=Criticality.SAFETY_CRITICAL,
        key_switch=KeySwitchMode.REMOTE_RUN
    )
    # 8.8 * 1.25 * 1.5 * 1.15 = 18.975 -> clamped to 10.0
    assert score_remote == 10.0

    # If physical key switch is locked to RUN (0.70x factor)
    score_locked = OTRiskEngine.calculate_score(
        base_cvss_max=8.8,
        purdue_level=PurdueLevel.LEVEL_1,
        criticality=Criticality.HIGH,
        key_switch=KeySwitchMode.RUN
    )
    # 8.8 * 1.25 * 1.20 * 0.70 = 9.24 -> 9.2
    assert score_locked < 10.0

    # With compensating control (DPI Firewall 40% reduction)
    comp_ctrl = CompensatingControl(
        id="c1",
        control_type=CompensatingControlType.DPI_INDUSTRIAL_FIREWALL,
        name="Firewall DPI",
        description="Filter port 44818 CIP writes",
        risk_reduction_pct=40.0,
        is_active=True
    )
    score_compensated = OTRiskEngine.calculate_score(
        base_cvss_max=8.8,
        purdue_level=PurdueLevel.LEVEL_1,
        criticality=Criticality.HIGH,
        key_switch=KeySwitchMode.RUN,
        compensating_controls=[comp_ctrl]
    )
    # 9.24 * 0.60 = 5.54 -> 5.5
    assert score_compensated < score_locked
    assert score_compensated == 5.5
