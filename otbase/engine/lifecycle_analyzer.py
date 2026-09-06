from typing import List, Dict
from otbase.models.asset import Asset
from otbase.models.lifecycle import LifecycleMilestone, ObsolescenceRisk, LifecycleState

class LifecycleAnalyzer:
    """Evaluates asset hardware and OS lifecycle status, predicting obsolescence risk."""

    @classmethod
    def analyze_assets(
        cls,
        assets: List[Asset],
        milestones: List[LifecycleMilestone]
    ) -> List[ObsolescenceRisk]:
        risks: List[ObsolescenceRisk] = []
        ms_map = {m.model.lower(): m for m in milestones}

        for asset in assets:
            matched_ms = None
            for key, ms in ms_map.items():
                if key in asset.model.lower() or (asset.catalog_number and key in asset.catalog_number.lower()):
                    matched_ms = ms
                    break

            # Check legacy OS
            os_risk = None
            if asset.os_name:
                os_low = asset.os_name.lower()
                if "windows 7" in os_low or "windows xp" in os_low or "server 2003" in os_low or "server 2008" in os_low:
                    os_risk = LifecycleState.END_OF_SUPPORT

            state = LifecycleState.ACTIVE
            urgency = "Low"
            recommendation = "Maintain standard preventive maintenance schedule."

            if os_risk == LifecycleState.END_OF_SUPPORT:
                state = LifecycleState.END_OF_SUPPORT
                urgency = "Critical"
                recommendation = "Upgrade host OS to Windows 10 IoT Enterprise LTSC or migrate to Linux/hypervisor container."
            elif matched_ms:
                state = matched_ms.state
                if state == LifecycleState.DISCONTINUED:
                    urgency = "Critical"
                    recommendation = f"Immediate replacement required. Upgrade to {matched_ms.replacement_model}."
                elif state == LifecycleState.END_OF_SUPPORT:
                    urgency = "High"
                    recommendation = f"Vendor security patches discontinued. Plan capital project to migrate to {matched_ms.replacement_model}."
                elif state == LifecycleState.END_OF_LIFE:
                    urgency = "Medium"
                    recommendation = f"New unit sales ceased. Procure strategic spare modules; roadmap transition to {matched_ms.replacement_model}."
                elif state == LifecycleState.MATURE:
                    urgency = "Low"
                    recommendation = f"Hardware is mature. Evaluate {matched_ms.replacement_model} for next facility refresh."
            elif "4.5" in (asset.firmware_version or "") and "s7-400" in asset.model.lower():
                state = LifecycleState.END_OF_SUPPORT
                urgency = "High"
                recommendation = "Legacy S7-400 firmware unsupported. Migrate to S7-1500R/H Redundant Controller."

            if state != LifecycleState.ACTIVE:
                risks.append(
                    ObsolescenceRisk(
                        asset_id=asset.id,
                        tag_name=asset.tag_name,
                        vendor=asset.vendor,
                        model=asset.model,
                        firmware_version=asset.firmware_version or "N/A",
                        state=state,
                        urgency=urgency,
                        replacement_recommendation=recommendation,
                        notes=f"Lifecycle State: {state.value}"
                    )
                )

        return risks
