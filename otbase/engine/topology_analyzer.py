from typing import List, Dict
from otbase.models.asset import Asset, PurdueLevel, KeySwitchMode, Criticality
from otbase.models.topology import (
    PurdueZone, Conduit, SecurityViolation, SecurityViolationType, ViolationSeverity
)

class TopologyAnalyzer:
    """Analyzes Purdue network zones, conduits, and asset network interfaces for security violations."""

    @classmethod
    def audit(
        cls,
        assets: List[Asset],
        zones: List[PurdueZone],
        conduits: List[Conduit]
    ) -> List[SecurityViolation]:
        violations: List[SecurityViolation] = []

        # 1. Audit for Dual-Homed Bridge hosts across Purdue Levels
        for asset in assets:
            if len(asset.network_interfaces) >= 2:
                # Check if interfaces belong to radically different subnets / vlans
                ips = [iface.ip_address for iface in asset.network_interfaces if iface.ip_address]
                vlans = [iface.vlan for iface in asset.network_interfaces if iface.vlan is not None]
                names = [iface.name.lower() for iface in asset.network_interfaces]

                # Check if asset is Level 3 or 4 but has a NIC in Level 1 subnet (e.g. 192.168.10.x vs 192.168.30.x)
                if asset.purdue_level in (PurdueLevel.LEVEL_3, PurdueLevel.LEVEL_4):
                    for iface in asset.network_interfaces:
                        if iface.ip_address and (iface.ip_address.startswith("192.168.10.") or "control" in iface.name.lower() or "direct" in iface.name.lower()):
                            violations.append(
                                SecurityViolation(
                                    id=f"viol-dual-{asset.id}",
                                    violation_type=SecurityViolationType.DUAL_HOMED_BRIDGE,
                                    severity=ViolationSeverity.CRITICAL,
                                    title=f"Dual-Homed Multi-NIC Breach: {asset.tag_name}",
                                    description=(
                                        f"Host '{asset.display_name}' ({asset.tag_name}) is located in {asset.purdue_level.value}, "
                                        f"but has secondary NIC '{iface.name}' configured with IP {iface.ip_address} bridging directly "
                                        f"into the Level 1 control subnet, bypassing Level 2 and Level 3 firewalls."
                                    ),
                                    affected_asset_ids=[asset.id],
                                    standard_reference="ISA/IEC 62443-3-3 SR 5.2 (Zone Boundary Protection)",
                                    remediation="Remove the secondary physical network interface. Route all engineering and diagnostics traffic through an authenticated Level 3.5 Jump Host."
                                )
                            )

        # 2. Audit Safety-Critical PLCs in REMOTE position
        for asset in assets:
            if asset.purdue_level == PurdueLevel.LEVEL_1 and asset.criticality in (Criticality.SAFETY_CRITICAL, Criticality.HIGH):
                if asset.key_switch in (KeySwitchMode.REMOTE_RUN, KeySwitchMode.REMOTE_PROG):
                    violations.append(
                        SecurityViolation(
                            id=f"viol-key-{asset.id}",
                            violation_type=SecurityViolationType.WEAK_KEYSWITCH_REMOTE,
                            severity=ViolationSeverity.HIGH,
                            title=f"Hardware Memory Key Switch in REMOTE: {asset.tag_name}",
                            description=(
                                f"Controller '{asset.tag_name}' ({asset.model}) is rated '{asset.criticality.value}', "
                                f"but its physical chassis key switch is set to '{asset.key_switch.value}'. "
                                f"This allows remote firmware flash, ladder logic tampering, and memory overwrite attacks over CIP/S7comm."
                            ),
                            affected_asset_ids=[asset.id],
                            standard_reference="CISA CPG 2.I / IEC 62443-4-2 CR 1.1",
                            remediation="Physically rotate the chassis key switch to 'RUN' (hardware memory write protect). Lock the cabinet and store keys in a dual-custody lockbox."
                        )
                    )

        # 3. Audit Conduits for uninspected or high-risk flows
        zone_map = {z.id: z for z in zones}
        for conduit in conduits:
            from_zone = zone_map.get(conduit.from_zone_id)
            to_zone = zone_map.get(conduit.to_zone_id)

            if from_zone and to_zone:
                # Direct IT (Level 4) to Field/Control (Level 1/0)
                if "Level 4" in from_zone.purdue_level and ("Level 1" in to_zone.purdue_level or "Level 0" in to_zone.purdue_level):
                    violations.append(
                        SecurityViolation(
                            id=f"viol-cnd-itot-{conduit.id}",
                            violation_type=SecurityViolationType.DIRECT_IT_TO_OT,
                            severity=ViolationSeverity.CRITICAL,
                            title=f"Direct IT-to-OT Conduit Bypass: {conduit.name}",
                            description=f"Conduit '{conduit.name}' directly connects enterprise Level 4 to industrial control without traversing Level 3.5 IDMZ.",
                            affected_conduit_id=conduit.id,
                            standard_reference="ISA/IEC 62443-3-2 Zone & Conduit Assessment",
                            remediation="Terminate this conduit immediately. Terminate external sessions at an IDMZ reverse proxy or jump box."
                        )
                    )

                # Uninspected Cross-Zone Conduit
                if not conduit.is_inspected and from_zone.purdue_level != to_zone.purdue_level:
                    violations.append(
                        SecurityViolation(
                            id=f"viol-cnd-uninsp-{conduit.id}",
                            violation_type=SecurityViolationType.UNINSPECTED_CROSS_ZONE,
                            severity=ViolationSeverity.HIGH,
                            title=f"Uninspected Cross-Zone Conduit: {conduit.name}",
                            description=f"Conduit '{conduit.name}' passes between {from_zone.name} and {to_zone.name} without an inline DPI firewall or gateway.",
                            affected_conduit_id=conduit.id,
                            standard_reference="ISA/IEC 62443-3-3 SR 5.1",
                            remediation="Place an industrial stateful firewall (e.g., FL mGuard, Tofino, Cisco ISA3000) inline on this conduit."
                        )
                    )

        return violations
