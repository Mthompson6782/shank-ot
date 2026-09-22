from typing import List, Optional
from otbase.models.asset import Asset, PurdueLevel, Criticality, KeySwitchMode
from otbase.models.vulnerability import CompensatingControl

class OTRiskEngine:
    """
    Computes contextual OT Risk Scores based on Michael Thompson's methodology:
    Traditional IT CVSS only measures raw vulnerability attributes.
    OT Risk incorporates:
    1. Base CVSS of all active CVEs.
    2. Purdue Level Exposure & Attack Path Depth.
    3. Physical Process Criticality (Safety-Critical SIS vs. Non-essential).
    4. Hardware Key Switch State (RUN vs. REMOTE).
    5. Active Compensating Controls (Firewall DPI, Air-gap, Diodes).
    """

    PURDUE_MULTIPLIERS = {
        PurdueLevel.LEVEL_0: 1.10,
        PurdueLevel.LEVEL_1: 1.25,  # Direct physical I/O and process actuation
        PurdueLevel.LEVEL_2: 1.05,
        PurdueLevel.LEVEL_3: 1.15,
        PurdueLevel.LEVEL_3_5: 1.30, # Perimeter exposure to enterprise / internet
        PurdueLevel.LEVEL_4: 0.90
    }

    CRITICALITY_MULTIPLIERS = {
        Criticality.SAFETY_CRITICAL: 1.50,
        Criticality.HIGH: 1.20,
        Criticality.MEDIUM: 1.00,
        Criticality.LOW: 0.75
    }

    KEY_SWITCH_ADJUSTMENTS = {
        KeySwitchMode.RUN: 0.70,         # 30% reduction: memory write-protected by physical key
        KeySwitchMode.REMOTE_RUN: 1.15,  # 15% increase: allows unauthenticated remote ladder logic changes
        KeySwitchMode.REMOTE_PROG: 1.25, # 25% increase: allows remote CPU halt
        KeySwitchMode.PROG: 1.00,
        KeySwitchMode.NOT_APPLICABLE: 1.00
    }

    @classmethod
    def calculate_score(
        cls,
        base_cvss_max: float,
        purdue_level: PurdueLevel,
        criticality: Criticality,
        key_switch: KeySwitchMode = KeySwitchMode.NOT_APPLICABLE,
        compensating_controls: Optional[List[CompensatingControl]] = None
    ) -> float:
        if base_cvss_max <= 0.0:
            # Baseline background exposure score based on criticality and level
            raw = 1.5 * cls.PURDUE_MULTIPLIERS.get(purdue_level, 1.0) * cls.CRITICALITY_MULTIPLIERS.get(criticality, 1.0)
            return round(min(10.0, max(0.5, raw)), 1)

        purdue_factor = cls.PURDUE_MULTIPLIERS.get(purdue_level, 1.0)
        crit_factor = cls.CRITICALITY_MULTIPLIERS.get(criticality, 1.0)
        key_factor = cls.KEY_SWITCH_ADJUSTMENTS.get(key_switch, 1.0)

        # Apply compensating controls reduction
        comp_factor = 1.0
        if compensating_controls:
            for ctrl in compensating_controls:
                if ctrl.is_active:
                    comp_factor *= (1.0 - (ctrl.risk_reduction_pct / 100.0))

        score = (base_cvss_max * purdue_factor * crit_factor * key_factor * comp_factor)
        # Normalize and clamp to 0.1 - 10.0
        clamped = max(0.1, min(10.0, score))
        return round(clamped, 1)

    @classmethod
    def recalculate_asset_risk(
        cls,
        asset: Asset,
        max_cvss: float,
        compensating_controls: Optional[List[CompensatingControl]] = None
    ) -> float:
        score = cls.calculate_score(
            base_cvss_max=max_cvss,
            purdue_level=asset.purdue_level,
            criticality=asset.criticality,
            key_switch=asset.key_switch,
            compensating_controls=compensating_controls
        )
        asset.ot_risk_score = score
        return score
