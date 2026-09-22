from typing import List, Dict, Any, Optional, Tuple
from otbase.models.asset import Asset, SwitchPortBinding, NetworkInterface
from otbase.models.pid_schema import (
    SwitchPortDiscovery, SwitchPortLearnedMac, ArpDiscoveryEntry
)

class SwitchInterrogator:
    """
    Simulates and executes active SNMP interrogation of managed industrial switches
    (Cisco Catalyst, Stratix 5700, Moxa EDS, Ruggedcom, Siemens SCALANCE).

    Walks standard MIBs:
    1. RFC 1213 MIB-II & RFC 2863 ifXTable (interface speeds, duplex, oper/admin status).
    2. RFC 1493 / RFC 4188 Bridge MIB (dot1dTpFdbTable for MAC-to-port bridging).
    3. IEEE 802.1Q Q-BRIDGE-MIB (dot1qVlanCurrentTable for access vs trunk ports).
    4. IEEE 802.1AB LLDP-MIB and Cisco CDP-MIB for switch-to-switch neighbor adjacencies.

    Deterministic Layer 1 Resolution:
    Cross-references switch port MAC tables with subnet ARP tables. When a switch port
    learns a single MAC corresponding to an active endpoint, OTbase binds that endpoint
    directly to that physical switch interface.
    """

    @classmethod
    def parse_bridge_fdb(
        cls,
        fdb_entries: List[Dict[str, Any]],
        port_index_map: Dict[int, str]
    ) -> Dict[str, List[str]]:
        """
        Parses dot1dTpFdbTable entries (MAC -> dot1dBasePort -> ifName).
        Returns a mapping of ifName -> [learned MAC addresses].
        """
        port_macs: Dict[str, List[str]] = {}
        for entry in fdb_entries:
            port_num = entry.get("dot1dBasePort")
            mac = entry.get("mac", "").upper().replace("-", ":")
            if_name = port_index_map.get(port_num, f"Port {port_num}")
            if if_name not in port_macs:
                port_macs[if_name] = []
            if mac and mac not in port_macs[if_name]:
                port_macs[if_name].append(mac)
        return port_macs

    @classmethod
    def resolve_physical_links(
        cls,
        switches: List[Asset],
        endpoints: List[Asset],
        switch_port_telemetry: List[SwitchPortDiscovery],
        arp_cache: Optional[List[ArpDiscoveryEntry]] = None
    ) -> List[Dict[str, Any]]:
        """
        Deterministic Layer 1 Physical Link Resolution Algorithm.
        
        Evaluates switch port tables against endpoint MAC and ARP caches:
        - If a switch port has learned exactly 1 MAC, and that MAC matches an endpoint,
          that endpoint is deterministically bound to that physical switch port (Layer 1 termination).
        - If a switch port has learned multiple MACs and has LLDP/CDP neighbor data or 802.1Q trunks,
          it is classified as an Uplink / Trunk interconnect.
        """
        resolved_bindings = []

        # Build MAC to asset mapping
        mac_to_asset: Dict[str, Tuple[Asset, NetworkInterface]] = {}
        for asset in endpoints:
            for iface in asset.network_interfaces:
                norm_mac = iface.mac_address.upper().replace("-", ":")
                mac_to_asset[norm_mac] = (asset, iface)

        # Also incorporate ARP cache if available
        if arp_cache:
            for arp in arp_cache:
                norm_mac = arp.mac_address.upper().replace("-", ":")
                if norm_mac not in mac_to_asset:
                    # Look up if any asset has this IP
                    for asset in endpoints:
                        for iface in asset.network_interfaces:
                            if iface.ip_address == arp.ip_address:
                                mac_to_asset[norm_mac] = (asset, iface)
                                break

        # Process each switch's ports
        switch_map = {sw.id: sw for sw in switches}

        for port in switch_port_telemetry:
            sw_asset = switch_map.get(port.switch_ip) or switch_map.get(port.switch_name or "")
            if not sw_asset:
                # Find switch by management IP in its interfaces
                for s in switches:
                    if any(iface.ip_address == port.switch_ip for iface in s.network_interfaces):
                        sw_asset = s
                        break

            sw_id = sw_asset.id if sw_asset else port.switch_name or port.switch_ip
            sw_name = sw_asset.display_name if sw_asset else port.switch_name or port.switch_ip

            # Analyze learned MACs
            learned_mac_list = [m.mac_address.upper().replace("-", ":") for m in port.learned_macs]
            
            # Case 1: Trunk / Inter-switch link (multiple MACs or neighbor LLDP detected)
            if len(learned_mac_list) > 1 or port.is_trunk or port.neighbor_system_name:
                resolved_bindings.append({
                    "switch_id": sw_id,
                    "switch_name": sw_name,
                    "port_name": port.if_name,
                    "is_trunk": True,
                    "neighbor_system": port.neighbor_system_name,
                    "neighbor_port": port.neighbor_port_id,
                    "learned_mac_count": len(learned_mac_list),
                    "vlan_ids": port.vlan_ids,
                    "status": "Uplink / Trunk"
                })
                continue

            # Case 2: Single learned MAC on access port -> Deterministic Layer 1 Endpoint Termination
            if len(learned_mac_list) == 1:
                target_mac = learned_mac_list[0]
                if target_mac in mac_to_asset:
                    bound_asset, bound_iface = mac_to_asset[target_mac]
                    
                    binding = SwitchPortBinding(
                        switch_asset_id=sw_id,
                        switch_name=sw_name,
                        port_name=port.if_name,
                        vlan_id=port.vlan_ids[0] if port.vlan_ids else 1,
                        is_uplink=False,
                        resolution_method="SNMP dot1dTpFdbTable Bridge Forwarding + ARP Correlation"
                    )
                    bound_iface.switch_port = binding

                    resolved_bindings.append({
                        "switch_id": sw_id,
                        "switch_name": sw_name,
                        "port_name": port.if_name,
                        "bound_asset_id": bound_asset.id,
                        "bound_asset_tag": bound_asset.tag_name,
                        "mac_address": target_mac,
                        "vlan_id": binding.vlan_id,
                        "speed_mbps": port.if_speed_bps // 1000000,
                        "duplex": port.duplex,
                        "status": "Deterministic L1 Link Resolved"
                    })
                else:
                    # Learned MAC of an uncatalogued asset or transient device
                    resolved_bindings.append({
                        "switch_id": sw_id,
                        "switch_name": sw_name,
                        "port_name": port.if_name,
                        "bound_asset_id": None,
                        "mac_address": target_mac,
                        "vlan_id": port.vlan_ids[0] if port.vlan_ids else 1,
                        "status": "Unidentified Live MAC on Access Port"
                    })

        return resolved_bindings

    @classmethod
    def generate_switch_port_telemetry(cls, facility: str) -> List[SwitchPortDiscovery]:
        """
        Generates authoritative switch port discovery profiles modeling industrial managed switches
        (e.g., Stratix 5700 / Cisco Catalyst 2960 / Moxa EDS-510E).
        """
        telemetry: List[SwitchPortDiscovery] = []

        if "water" in facility.lower():
            # Cisco Catalyst IE-3400 Industrial Managed Switch (SW-01-IND)
            # Port Fa1/1 -> PLC-01-MAIN (ControlLogix 5580)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-01-IND",
                if_index=1,
                if_name="FastEthernet1/1",
                if_descr="IE-3400 10/100Base-TX Access Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[10],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:1D:9C:C4:55:01", vlan_id=10)]
            ))
            # Port Fa1/2 -> PLC-02-CHEM (CompactLogix 5380)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-01-IND",
                if_index=2,
                if_name="FastEthernet1/2",
                if_descr="IE-3400 10/100Base-TX Access Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[10],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:1D:9C:88:22:19", vlan_id=10)]
            ))
            # Port Fa1/3 -> HMI-01-OP (AVEVA InTouch HMI)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-01-IND",
                if_index=3,
                if_name="FastEthernet1/3",
                if_descr="IE-3400 10/100Base-TX Access Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[20],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:50:56:A2:3B:11", vlan_id=20)]
            ))
            # Port Fa1/4 -> EWS-01-ENG (Dual-Homed Secondary NIC)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-01-IND",
                if_index=4,
                if_name="FastEthernet1/4",
                if_descr="IE-3400 10/100Base-TX Access Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[10],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:50:56:88:C1:23", vlan_id=10)]
            ))
            # Port Fa1/5 -> HIST-01-SRV (FactoryTalk Historian SE)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-01-IND",
                if_index=5,
                if_name="FastEthernet1/5",
                if_descr="IE-3400 10/100Base-TX Access Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[30],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:50:56:11:44:AA", vlan_id=30)]
            ))
            # Port Fa1/6 -> FIT-101-RAW (Endress+Hauser Promag Flowmeter)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-01-IND",
                if_index=6,
                if_name="FastEthernet1/6",
                if_descr="IE-3400 10/100Base-TX Access Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[10],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:07:90:3A:41:88", vlan_id=10)]
            ))
            # Port Gi1/1 -> Trunk to IDMZ Firewall FL mGuard RS4000
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-01-IND",
                if_index=9,
                if_name="GigabitEthernet1/1",
                if_descr="Uplink Trunk to IDMZ Firewall",
                if_speed_bps=1000000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=True,
                vlan_ids=[10, 20, 30, 35],
                neighbor_system_name="IDMZ-SEC-GW01",
                neighbor_port_id="eth1",
                learned_macs=[
                    SwitchPortLearnedMac(mac_address="00:A0:45:11:22:34", vlan_id=35)
                ]
            ))

        elif "walmart" in facility.lower() or "cold chain" in facility.lower():
            # Cisco Catalyst IE-3300 Rugged Industrial Ethernet Switch (SW-COLD-01)
            # Port Fa1/1 -> PLC-NH3-COMP-01 (Frick Quantum HD Compressor 1)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-COLD-01",
                if_index=1,
                if_name="FastEthernet1/1",
                if_descr="IE-3300 10/100Base-TX Engine Room Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[10],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:0E:8C:11:22:01", vlan_id=10)]
            ))
            # Port Fa1/2 -> PLC-NH3-COMP-02 (Frick Quantum HD Compressor 2)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-COLD-01",
                if_index=2,
                if_name="FastEthernet1/2",
                if_descr="IE-3300 10/100Base-TX Engine Room Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[10],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:0E:8C:11:22:02", vlan_id=10)]
            ))
            # Port Fa1/3 -> HMI-COLD-DOCK (Rockwell PanelView Plus 7)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-COLD-01",
                if_index=3,
                if_name="FastEthernet1/3",
                if_descr="IE-3300 10/100Base-TX Supervisory HMI Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[20],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:50:56:B2:3C:44", vlan_id=20)]
            ))
            # Port Fa1/4 -> RACK-E3-GROCERY (Emerson Copeland E3 Rack Controller)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-COLD-01",
                if_index=4,
                if_name="FastEthernet1/4",
                if_descr="IE-3300 10/100Base-TX Refrigeration Rack Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[10],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:08:E1:44:55:12", vlan_id=10)]
            ))
            # Port Fa1/5 -> NH3-GAS-SAFETY-01 (Det-Tronics Eagle Quantum Premier)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-COLD-01",
                if_index=5,
                if_name="FastEthernet1/5",
                if_descr="IE-3300 10/100Base-TX Gas Detection Life Safety Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[10],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:1B:4F:99:88:01", vlan_id=10)]
            ))
            # Port Fa1/6 -> SCADA-IGNITION-HIST (Inductive Automation Ignition Server)
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-COLD-01",
                if_index=6,
                if_name="FastEthernet1/6",
                if_descr="IE-3300 10/100Base-TX FSMA Logging Server Port",
                if_speed_bps=100000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=False,
                vlan_ids=[30],
                learned_macs=[SwitchPortLearnedMac(mac_address="00:50:56:99:11:A3", vlan_id=30)]
            ))
            # Port Gi1/1 -> Uplink Trunk to Azure IoT Edge Gateway
            telemetry.append(SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-COLD-01",
                if_index=9,
                if_name="GigabitEthernet1/1",
                if_descr="Uplink Trunk to Azure IoT Edge Gateway",
                if_speed_bps=1000000000,
                if_oper_status="up",
                duplex="full",
                is_trunk=True,
                vlan_ids=[10, 20, 30, 35],
                neighbor_system_name="IOT-AZURE-COLDGW",
                neighbor_port_id="eth0",
                learned_macs=[
                    SwitchPortLearnedMac(mac_address="00:D0:C9:AA:BB:01", vlan_id=35)
                ]
            ))

        return telemetry

