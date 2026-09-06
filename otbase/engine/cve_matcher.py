import re
from typing import List, Dict, Tuple, Optional
from otbase.models.asset import Asset, RackModule
from otbase.models.vulnerability import (
    ICSAdvisory, VulnerabilityMatch, CVSSSeverity, CompensatingControl
)
from otbase.engine.risk_engine import OTRiskEngine

class CVEMatcher:
    """Matches hardware models and firmware revisions against ICS-CERT advisories."""

    @classmethod
    def match_asset(
        cls,
        asset: Asset,
        advisories: List[ICSAdvisory],
        applied_controls: Optional[List[CompensatingControl]] = None
    ) -> List[VulnerabilityMatch]:
        matches: List[VulnerabilityMatch] = []
        applied_controls = applied_controls or []

        # 1. Match Main Asset
        for adv in advisories:
            if cls._is_match(
                vendor=asset.vendor,
                model=asset.model,
                catalog=asset.catalog_number,
                firmware=asset.firmware_version,
                advisory=adv
            ):
                ot_risk = OTRiskEngine.calculate_score(
                    base_cvss_max=adv.cvss_base_score,
                    purdue_level=asset.purdue_level,
                    criticality=asset.criticality,
                    key_switch=asset.key_switch,
                    compensating_controls=applied_controls
                )
                match = VulnerabilityMatch(
                    id=f"vm-{asset.id}-{adv.cve_id}",
                    asset_id=asset.id,
                    asset_tag=asset.tag_name,
                    advisory_id=adv.advisory_id,
                    cve_id=adv.cve_id,
                    title=adv.title,
                    vendor=adv.vendor,
                    cvss_base_score=adv.cvss_base_score,
                    ot_contextual_risk=ot_risk,
                    severity=adv.severity,
                    remediation=adv.remediation,
                    active_compensating_controls=applied_controls,
                    status="Compensated" if applied_controls else "Unmitigated"
                )
                matches.append(match)

        # 2. Match Chassis Rack Modules (Slot-level inspection)
        if asset.chassis:
            for module in asset.chassis.modules:
                for adv in advisories:
                    if cls._is_match(
                        vendor=module.vendor,
                        model=module.name,
                        catalog=module.catalog_number,
                        firmware=module.firmware_version,
                        advisory=adv
                    ):
                        # Avoid duplicates if already matched at controller level
                        if any(m.cve_id == adv.cve_id and m.module_slot == module.slot for m in matches):
                            continue

                        ot_risk = OTRiskEngine.calculate_score(
                            base_cvss_max=adv.cvss_base_score,
                            purdue_level=asset.purdue_level,
                            criticality=asset.criticality,
                            key_switch=asset.key_switch,
                            compensating_controls=applied_controls
                        )
                        match = VulnerabilityMatch(
                            id=f"vm-{asset.id}-slot{module.slot}-{adv.cve_id}",
                            asset_id=asset.id,
                            asset_tag=f"{asset.tag_name} [Slot {module.slot}: {module.catalog_number}]",
                            module_slot=module.slot,
                            module_catalog=module.catalog_number,
                            advisory_id=adv.advisory_id,
                            cve_id=adv.cve_id,
                            title=f"Slot {module.slot} ({module.name}): {adv.title}",
                            vendor=adv.vendor,
                            cvss_base_score=adv.cvss_base_score,
                            ot_contextual_risk=ot_risk,
                            severity=adv.severity,
                            remediation=adv.remediation,
                            active_compensating_controls=applied_controls,
                            status="Compensated" if applied_controls else "Unmitigated"
                        )
                        matches.append(match)

                        # Update module's own CVE tracker
                        if adv.cve_id not in module.cves:
                            module.cves.append(adv.cve_id)
                        module.cve_count = len(module.cves)

        # Update asset active CVEs list
        asset.active_cves = list({m.cve_id for m in matches})
        # Recalculate asset overall risk
        max_cvss = max([m.cvss_base_score for m in matches], default=0.0)
        OTRiskEngine.recalculate_asset_risk(asset, max_cvss, applied_controls)

        return matches

    @classmethod
    def _is_match(
        cls,
        vendor: str,
        model: str,
        catalog: Optional[str],
        firmware: Optional[str],
        advisory: ICSAdvisory
    ) -> bool:
        # Vendor match
        if advisory.vendor.lower() not in vendor.lower() and vendor.lower() not in advisory.vendor.lower():
            return False

        # Model or catalog match
        model_matched = False
        target_strings = [model.lower()]
        if catalog:
            target_strings.append(catalog.lower())

        for aff in advisory.affected_models:
            aff_low = aff.lower()
            if any(aff_low in ts or ts in aff_low for ts in target_strings):
                model_matched = True
                break

        if not model_matched:
            return False

        # Firmware match
        if not firmware or firmware.lower() in ("n/a", "none", "unknown"):
            return False

        try:
            if re.search(advisory.affected_firmware_pattern, firmware):
                return True
        except re.error:
            # Fallback simple check
            return advisory.affected_firmware_pattern in firmware

        return False
