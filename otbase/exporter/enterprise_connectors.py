from typing import List, Dict, Any, Optional
import json
from datetime import datetime, timezone
from otbase.models.asset import Asset, DeviceType
from otbase.models.topology import Conduit, SecurityViolation
from otbase.models.pid_schema import FlowTelemetryRecord

class EnterpriseConnectors:
    """
    Enterprise Connectors for Upstream IT/OT Ecosystem Integration:
    1. ServiceNow CMDB Service Graph Connector (ISA-95 Equipment Model).
    2. Splunk Enterprise Security Technical Add-on (TA) Event Stream.
    3. Industrial Firewall Policy Enforcer (Fortinet FortiOS & Palo Alto PAN-OS).
    """

    @classmethod
    def generate_servicenow_cmdb_payload(
        cls,
        assets: List[Asset],
        facility: str
    ) -> Dict[str, Any]:
        """
        Maps discovered OT assets into ServiceNow Service Graph Connector schema
        adhering to ISA-95 equipment hierarchy (Enterprise, Site, Area, Work Center, Control Device).
        """
        records = []
        for a in assets:
            cmdb_class = "cmdb_ci_industrial_plc" if a.device_type == DeviceType.PLC else (
                "cmdb_ci_ip_switch" if a.device_type == DeviceType.INDUSTRIAL_SWITCH else (
                    "cmdb_ci_hmi" if a.device_type == DeviceType.HMI else "cmdb_ci_hardware"
                )
            )

            primary_ip = a.network_interfaces[0].ip_address if a.network_interfaces else None
            primary_mac = a.network_interfaces[0].mac_address if a.network_interfaces else None
            port_binding = a.network_interfaces[0].switch_port if a.network_interfaces else None

            records.append({
                "sys_class_name": cmdb_class,
                "name": a.tag_name,
                "display_name": a.display_name,
                "vendor": a.vendor,
                "model_id": a.model,
                "serial_number": a.serial_number or "UNKNOWN",
                "firmware_version": a.firmware_version,
                "ip_address": primary_ip,
                "mac_address": primary_mac,
                "isa95_level": a.purdue_level.value.split(" - ")[0],
                "location": {
                    "enterprise": "Global Water Utilities Corp",
                    "facility": facility,
                    "area": a.area or "Process Cell",
                    "path": a.location_path or f"{facility}/{a.area}"
                },
                "switch_port_attachment": {
                    "switch_id": port_binding.switch_asset_id if port_binding else None,
                    "switch_port": port_binding.port_name if port_binding else None,
                    "vlan": port_binding.vlan_id if port_binding else None
                } if port_binding else None,
                "operational_criticality": a.criticality.value,
                "ot_risk_score": a.ot_risk_score
            })

        return {
            "source": "SHANK Service Graph Connector",
            "schema_version": "2.4.0",
            "extracted_at": datetime.now(timezone.utc).isoformat(),
            "target_cmdb_table": "cmdb_ci_industrial_device",
            "records_count": len(records),
            "records": records
        }

    @classmethod
    def generate_splunk_ta_events(
        cls,
        assets: List[Asset],
        violations: List[SecurityViolation],
        flows: Optional[List[FlowTelemetryRecord]] = None
    ) -> str:
        """
        Generates Splunk CIM / CEF formatted syslog event stream for ingestion by
        Splunk Technical Add-on (TA) for SHANK.
        """
        events = []
        now = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

        # Asset inventory baseline events
        for a in assets:
            ip = a.network_interfaces[0].ip_address if a.network_interfaces else "0.0.0.0"
            mac = a.network_interfaces[0].mac_address if a.network_interfaces else "00:00:00:00:00:00"
            evt = (
                f"{now} shank-server CEF:0|Thompson|SHANK|3.4.0|ASSET_DISCOVERY|Device Discovered|1|"
                f"src={ip} smac={mac} suser={a.tag_name} dhost={a.model} "
                f"cat={a.device_type.value} cs1Label=PurdueLevel cs1={a.purdue_level.value} "
                f"cs2Label=RiskScore cs2={a.ot_risk_score} cs3Label=Vendor cs3={a.vendor}"
            )
            events.append(evt)

        # Security violation alert events
        for v in violations:
            sev_num = 10 if v.severity.value == "Critical" else (7 if v.severity.value == "High" else 4)
            evt = (
                f"{now} shank-server CEF:0|Thompson|SHANK|3.4.0|SECURITY_VIOLATION|{v.title}|{sev_num}|"
                f"msg={v.description} cs1Label=StandardRef cs1={v.standard_reference} "
                f"cs2Label=Remediation cs2={v.remediation}"
            )
            events.append(evt)

        return "\n".join(events)

    @classmethod
    def generate_firewall_rules(
        cls,
        conduits: List[Conduit],
        assets: List[Asset],
        vendor: str = "fortinet"
    ) -> str:
        """
        Generates authoritative industrial firewall rules (Fortinet FortiOS CLI or Palo Alto PAN-OS)
        enforcing verified Purdue conduits and blocking uninspected cross-zone traffic.
        """
        lines = []
        if vendor.lower() == "fortinet":
            lines.append("# ========================================================")
            lines.append("# Fortinet FortiOS Industrial Firewall Policy (OTbase Sync)")
            lines.append("# ========================================================")
            lines.append("config firewall policy")
            
            for idx, c in enumerate(conduits):
                pol_id = 100 + idx
                ports_str = " ".join([str(p) for p in c.ports]) if c.ports else "ALL"
                status_str = "enable" if c.is_inspected else "disable # DISABLED: Uninspected Cross-Zone Conduit"
                
                lines.append(f"  edit {pol_id}")
                lines.append(f"    set name \"CONDUIT_{c.name.replace(' ', '_').upper()}\"")
                lines.append(f"    set srcintf \"port-ot-zone-{c.from_zone_id}\"")
                lines.append(f"    set dstintf \"port-ot-zone-{c.to_zone_id}\"")
                lines.append(f"    set action accept")
                lines.append(f"    set schedule \"always\"")
                lines.append(f"    set service \"{' '.join(c.allowed_protocols)}\"")
                lines.append(f"    set utm-status enable")
                lines.append(f"    set ips-sensor \"Industrial_ICS_DPI\"")
                lines.append(f"    set status {status_str}")
                lines.append("  next")
            lines.append("end")

        else:
            lines.append("<!-- Palo Alto PAN-OS Security Rulebase XML (OTbase Sync) -->")
            lines.append("<security>")
            lines.append("  <rules>")
            for c in conduits:
                lines.append(f"    <entry name=\"CONDUIT_{c.name.replace(' ', '_')}\">")
                lines.append(f"      <from><member>{c.from_zone_id}</member></from>")
                lines.append(f"      <to><member>{c.to_zone_id}</member></to>")
                lines.append(f"      <application>")
                for p in c.allowed_protocols:
                    lines.append(f"        <member>{p.lower()}</member>")
                lines.append(f"      </application>")
                lines.append(f"      <action>allow</action>")
                lines.append(f"      <profile-setting><group><member>Industrial-DPI</member></group></profile-setting>")
                lines.append("    </entry>")
            lines.append("  </rules>")
            lines.append("</security>")

        return "\n".join(lines)
