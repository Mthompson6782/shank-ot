from typing import List, Dict, Any, Optional
from collections import defaultdict
from otbase.models.asset import Asset
from otbase.models.pid_schema import FlowTelemetryRecord, HostSocketRecord

class FlowEngine:
    """
    Engine for ingesting and analyzing NetFlow (v5/v9), sFlow, and host-level socket telemetry.
    Reconstructs behavioral network context without heavy DPI packet taps:
    - Generates Sankey flow volume matrices between Purdue levels, subnets, and functional OT systems.
    - Profiles device communication pathways to verify authorized SCADA/PLC links and alert on rogue flows.
    """

    @classmethod
    def ingest_netflow_records(
        cls,
        raw_flows: List[Dict[str, Any]],
        sampling_ratio: int = 128
    ) -> List[FlowTelemetryRecord]:
        """
        Parses NetFlow v5/v9/sFlow export datagrams.
        Multiplies sampled packets/bytes by sampling ratio to reconstruct actual line-rate volumes.
        """
        records: List[FlowTelemetryRecord] = []
        for flow in raw_flows:
            sampled_bytes = flow.get("bytes", 0)
            sampled_pkts = flow.get("packets", 0)
            
            # Reconstruct true wire volume from sampling
            true_bytes = sampled_bytes * sampling_ratio
            true_pkts = sampled_pkts * sampling_ratio

            records.append(
                FlowTelemetryRecord(
                    src_ip=flow["src_ip"],
                    dst_ip=flow["dst_ip"],
                    src_port=flow.get("src_port", 0),
                    dst_port=flow.get("dst_port", 0),
                    protocol=flow.get("protocol", "TCP"),
                    byte_count=true_bytes,
                    packet_count=true_pkts,
                    sampling_ratio=sampling_ratio
                )
            )
        return records

    @classmethod
    def generate_sankey_data(
        cls,
        flows: List[FlowTelemetryRecord],
        assets: List[Asset]
    ) -> Dict[str, Any]:
        """
        Generates nodes and links for directional Sankey flow visualizations
        displaying proportional communication volumes across Purdue levels, subnets, and systems.
        """
        # Map IP addresses to Purdue level / asset name
        ip_to_label: Dict[str, str] = {}
        ip_to_level: Dict[str, str] = {}

        for a in assets:
            lvl = a.purdue_level.value.split(" - ")[0]
            for iface in a.network_interfaces:
                if iface.ip_address:
                    ip_to_label[iface.ip_address] = f"{a.tag_name} ({lvl})"
                    ip_to_level[iface.ip_address] = lvl

        # Aggregate flows between Purdue levels / systems
        flow_matrix = defaultdict(float)

        for f in flows:
            src_lbl = ip_to_label.get(f.src_ip, f"External / {f.src_ip}")
            dst_lbl = ip_to_label.get(f.dst_ip, f"External / {f.dst_ip}")
            mb_transferred = round(f.byte_count / (1024 * 1024), 2)
            flow_matrix[(src_lbl, dst_lbl)] += mb_transferred

        # Format into Sankey node & link indices
        all_nodes = list(set([src for src, _ in flow_matrix.keys()] + [dst for _, dst in flow_matrix.keys()]))
        node_map = {name: idx for idx, name in enumerate(all_nodes)}

        links = []
        for (src, dst), volume in flow_matrix.items():
            if volume > 0.001:
                links.append({
                    "source": node_map[src],
                    "target": node_map[dst],
                    "source_name": src,
                    "target_name": dst,
                    "value": round(volume, 2),
                    "unit": "MB"
                })

        return {
            "nodes": [{"name": n} for n in all_nodes],
            "links": sorted(links, key=lambda x: x["value"], reverse=True)
        }

    @classmethod
    def profile_asset_traffic(
        cls,
        target_ip: str,
        flows: List[FlowTelemetryRecord],
        assets: List[Asset]
    ) -> Dict[str, Any]:
        """
        Isolates a discovered device to inspect all observed communication paths,
        validating that field assets communicate strictly with authorized controllers and SCADA servers.
        """
        ip_to_asset = {}
        for a in assets:
            for iface in a.network_interfaces:
                if iface.ip_address:
                    ip_to_asset[iface.ip_address] = a

        inbound_talkers = []
        outbound_destinations = []
        total_inbound_bytes = 0
        total_outbound_bytes = 0
        observed_protocols = set()
        anomalous_flows = []

        for f in flows:
            if f.dst_ip == target_ip:
                total_inbound_bytes += f.byte_count
                observed_protocols.add(f"{f.protocol}/{f.dst_port}")
                peer = ip_to_asset.get(f.src_ip)
                peer_name = peer.tag_name if peer else f.src_ip
                peer_level = peer.purdue_level.value if peer else "Unknown / External"
                
                # Check for anomalous flows (e.g. direct IT Level 4 talker into Level 1 PLC)
                if peer and "Level 4" in peer.purdue_level.value:
                    anomalous_flows.append({
                        "flow": f"{peer.tag_name} -> {target_ip}",
                        "severity": "Critical",
                        "reason": "Direct IT-to-OT flow bypassing IDMZ"
                    })

                inbound_talkers.append({
                    "peer_ip": f.src_ip,
                    "peer_name": peer_name,
                    "peer_level": peer_level,
                    "port": f.dst_port,
                    "protocol": f.protocol,
                    "bytes": f.byte_count,
                    "packets": f.packet_count
                })

            elif f.src_ip == target_ip:
                total_outbound_bytes += f.byte_count
                observed_protocols.add(f"{f.protocol}/{f.dst_port}")
                peer = ip_to_asset.get(f.dst_ip)
                peer_name = peer.tag_name if peer else f.dst_ip
                peer_level = peer.purdue_level.value if peer else "Unknown / External"

                outbound_destinations.append({
                    "peer_ip": f.dst_ip,
                    "peer_name": peer_name,
                    "peer_level": peer_level,
                    "port": f.dst_port,
                    "protocol": f.protocol,
                    "bytes": f.byte_count,
                    "packets": f.packet_count
                })

        return {
            "target_ip": target_ip,
            "total_inbound_mb": round(total_inbound_bytes / (1024 * 1024), 2),
            "total_outbound_mb": round(total_outbound_bytes / (1024 * 1024), 2),
            "observed_services": list(observed_protocols),
            "inbound_peers": inbound_talkers,
            "outbound_peers": outbound_destinations,
            "anomalies": anomalous_flows
        }

    @classmethod
    def get_seed_telemetry(cls, facility: str) -> List[FlowTelemetryRecord]:
        """
        Generates realistic industrial flow records (sampled at 1:128) for the active facility.
        """
        flows: List[FlowTelemetryRecord] = []

        if "water" in facility.lower():
            # SCADA HMI (192.168.20.20) polling PLC-01 (192.168.10.10) over CIP / EtherNet/IP (TCP 44818)
            flows.append(FlowTelemetryRecord(
                src_ip="192.168.20.20",
                dst_ip="192.168.10.10",
                src_port=49152,
                dst_port=44818,
                protocol="TCP",
                byte_count=84500000,
                packet_count=124000,
                sampling_ratio=128
            ))
            # SCADA HMI (192.168.20.20) polling PLC-02 Chemical (192.168.10.20) over EtherNet/IP (TCP 44818)
            flows.append(FlowTelemetryRecord(
                src_ip="192.168.20.20",
                dst_ip="192.168.10.20",
                src_port=49153,
                dst_port=44818,
                protocol="TCP",
                byte_count=42100000,
                packet_count=68000,
                sampling_ratio=128
            ))
            # Historian (192.168.20.30) replicating tags from HMI / SCADA
            flows.append(FlowTelemetryRecord(
                src_ip="192.168.20.20",
                dst_ip="192.168.20.30",
                src_port=51200,
                dst_port=135,
                protocol="TCP",
                byte_count=195000000,
                packet_count=215000,
                sampling_ratio=128
            ))
            # PLC-01 (192.168.10.10) cyclic I/O to Remote Point I/O (192.168.10.75) via UDP 2222
            flows.append(FlowTelemetryRecord(
                src_ip="192.168.10.10",
                dst_ip="192.168.10.75",
                src_port=2222,
                dst_port=2222,
                protocol="UDP",
                byte_count=61200000,
                packet_count=980000,
                sampling_ratio=128
            ))
            # Dual-Homed EWS breach (192.168.30.100) directly connecting to PLC-01 (192.168.10.10) bypassing Level 2
            flows.append(FlowTelemetryRecord(
                src_ip="192.168.30.100",
                dst_ip="192.168.10.10",
                src_port=50124,
                dst_port=44818,
                protocol="TCP",
                byte_count=12800000,
                packet_count=15400,
                sampling_ratio=128
            ))

        return flows
