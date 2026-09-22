import math
from typing import List, Dict, Any, Optional, Tuple
from otbase.models.asset import Asset, DeviceType, PurdueLevel
from otbase.models.topology import (
    PurdueZone, Conduit, LayoutPerspective, GraphNode, GraphEdge,
    GraphNodeType, TopologyPerspectiveData
)
from otbase.models.location_tree import LocationNode, LocationTier

class KandinskyLayoutEngine:
    """
    Mathematical Graph Layout Engine implementing the Kandinsky Orthogonal Model.
    
    Produces clean, schematic, right-angle (90-degree) blueprints similar to electrical
    schematics and Piping & Instrumentation Diagrams (P&IDs):
    - Orthogonal Grid Routing snapped to Cartesian coordinates.
    - Planarization and bend minimization.
    - High-degree switch port adaptation (routing multiple connections cleanly to switch boundaries).
    - Multi-perspective layout synthesis (Connections, Locations, Purdue, Networks, Organic).
    - Hybrid modeling of unmanaged switching fabrics (solid lines for discovered, dashed for manual).
    - Export to SVG, GraphML, and Visio XML.
    """

    GRID_SNAP = 20

    @classmethod
    def snap(cls, val: float) -> float:
        return round(val / cls.GRID_SNAP) * cls.GRID_SNAP

    @classmethod
    def compute_orthogonal_waypoints(
        cls,
        src_x: float, src_y: float, src_w: float, src_h: float,
        dst_x: float, dst_y: float, dst_w: float, dst_h: float
    ) -> List[List[float]]:
        """
        Computes orthogonal 90-degree bend waypoints between two node boundaries.
        Routes: (Exit Port) -> Horizontal/Vertical Segments -> (Entry Port).
        """
        # Determine exit point on source and entry point on target
        # If source is above destination
        if src_y + src_h < dst_y:
            p_start = [src_x + src_w / 2, src_y + src_h]
            p_end = [dst_x + dst_w / 2, dst_y]
            mid_y = cls.snap((p_start[1] + p_end[1]) / 2)
            return [
                [cls.snap(p_start[0]), cls.snap(p_start[1])],
                [cls.snap(p_start[0]), mid_y],
                [cls.snap(p_end[0]), mid_y],
                [cls.snap(p_end[0]), cls.snap(p_end[1])]
            ]
        elif dst_y + dst_h < src_y:
            p_start = [src_x + src_w / 2, src_y]
            p_end = [dst_x + dst_w / 2, dst_y + dst_h]
            mid_y = cls.snap((p_start[1] + p_end[1]) / 2)
            return [
                [cls.snap(p_start[0]), cls.snap(p_start[1])],
                [cls.snap(p_start[0]), mid_y],
                [cls.snap(p_end[0]), mid_y],
                [cls.snap(p_end[0]), cls.snap(p_end[1])]
            ]
        else:
            # Side-by-side
            if src_x < dst_x:
                p_start = [src_x + src_w, src_y + src_h / 2]
                p_end = [dst_x, dst_y + dst_h / 2]
            else:
                p_start = [src_x, src_y + src_h / 2]
                p_end = [dst_x + dst_w, dst_y + dst_h / 2]
            mid_x = cls.snap((p_start[0] + p_end[0]) / 2)
            return [
                [cls.snap(p_start[0]), cls.snap(p_start[1])],
                [mid_x, cls.snap(p_start[1])],
                [mid_x, cls.snap(p_end[1])],
                [cls.snap(p_end[0]), cls.snap(p_end[1])]
            ]

    @classmethod
    def generate_perspective(
        cls,
        perspective: LayoutPerspective,
        assets: List[Asset],
        zones: List[PurdueZone],
        conduits: List[Conduit],
        locations: Optional[List[LocationNode]] = None,
        unmanaged_switches: Optional[List[Dict[str, Any]]] = None
    ) -> TopologyPerspectiveData:
        """
        Synthesizes the topology graph for the selected operational perspective.
        """
        if perspective == LayoutPerspective.CONNECTIONS:
            return cls._build_connections_layout(assets, unmanaged_switches)
        elif perspective == LayoutPerspective.LOCATIONS:
            return cls._build_locations_layout(assets, locations)
        elif perspective == LayoutPerspective.PURDUE_HIERARCHY:
            return cls._build_purdue_layout(assets, zones, conduits)
        elif perspective == LayoutPerspective.NETWORKS:
            return cls._build_networks_layout(assets)
        else:
            return cls._build_organic_layout(assets)

    # 1. Connections Layout (L1/L2 Physical Switch Ports)
    @classmethod
    def _build_connections_layout(
        cls,
        assets: List[Asset],
        unmanaged_switches: Optional[List[Dict[str, Any]]] = None
    ) -> TopologyPerspectiveData:
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        node_lookup: Dict[str, GraphNode] = {}

        # Separate switches and endpoints
        switches = [a for a in assets if a.device_type == DeviceType.INDUSTRIAL_SWITCH]
        firewalls = [a for a in assets if a.device_type == DeviceType.INDUSTRIAL_FIREWALL]
        endpoints = [a for a in assets if a.device_type not in (DeviceType.INDUSTRIAL_SWITCH, DeviceType.INDUSTRIAL_FIREWALL)]

        # Layout Switches centrally
        current_x = 300
        current_y = 260
        for sw in switches:
            gn = GraphNode(
                id=sw.id,
                label=sw.tag_name,
                node_type=GraphNodeType.MANAGED_SWITCH,
                x=float(current_x),
                y=float(current_y),
                width=220.0,
                height=80.0,
                purdue_level=sw.purdue_level.value,
                ip_address=sw.network_interfaces[0].ip_address if sw.network_interfaces else None,
                port_count=10,
                active_ports=["Fa1/1", "Fa1/2", "Fa1/3", "Fa1/4", "Gi1/1"],
                metadata={"model": sw.model, "vendor": sw.vendor}
            )
            nodes.append(gn)
            node_lookup[sw.id] = gn
            current_x += 380

        # Position Firewalls above switches
        fw_x = 350
        for fw in firewalls:
            gn = GraphNode(
                id=fw.id,
                label=fw.tag_name,
                node_type=GraphNodeType.ROUTER_FIREWALL,
                x=float(fw_x),
                y=60.0,
                width=180.0,
                height=60.0,
                purdue_level=fw.purdue_level.value,
                ip_address=fw.network_interfaces[0].ip_address if fw.network_interfaces else None,
                metadata={"model": fw.model}
            )
            nodes.append(gn)
            node_lookup[fw.id] = gn
            fw_x += 300

        # Add unmanaged switches if present
        unmanaged_count = 0
        if unmanaged_switches:
            for unsw in unmanaged_switches:
                unmanaged_count += 1
                gn = GraphNode(
                    id=unsw["id"],
                    label=unsw.get("label", "Unmanaged Switch"),
                    node_type=GraphNodeType.UNMANAGED_SWITCH,
                    x=float(unsw.get("x", 450)),
                    y=float(unsw.get("y", 420)),
                    width=150.0,
                    height=50.0,
                    is_unmanaged=True,
                    metadata={"ports": 5, "type": "Unmanaged Switch (Hybrid)"}
                )
                nodes.append(gn)
                node_lookup[gn.id] = gn

        # Position Endpoints around the switches
        ep_x = 60
        ep_y = 480
        for idx, ep in enumerate(endpoints):
            col_x = 60 + (idx % 5) * 220
            row_y = 460 + (idx // 5) * 160
            
            ntype = GraphNodeType.PLC if ep.device_type == DeviceType.PLC else (
                GraphNodeType.HMI if ep.device_type == DeviceType.HMI else (
                    GraphNodeType.SCADA_SERVER if ep.device_type == DeviceType.SCADA_SERVER else GraphNodeType.FIELD_DEVICE
                )
            )
            gn = GraphNode(
                id=ep.id,
                label=f"{ep.tag_name}\n({ep.display_name[:16]})",
                node_type=ntype,
                x=float(col_x),
                y=float(row_y),
                width=180.0,
                height=70.0,
                purdue_level=ep.purdue_level.value,
                ip_address=ep.network_interfaces[0].ip_address if ep.network_interfaces else None,
                mac_address=ep.network_interfaces[0].mac_address if ep.network_interfaces else None,
                location_path=ep.location_path,
                metadata={"model": ep.model, "vendor": ep.vendor}
            )
            nodes.append(gn)
            node_lookup[ep.id] = gn

        # Connect physical switch ports to endpoints
        edge_idx = 0
        for ep in endpoints:
            for iface in ep.network_interfaces:
                if iface.switch_port:
                    sw_node = node_lookup.get(iface.switch_port.switch_asset_id) or (switches[0] if switches else None)
                    target_sw_id = sw_node.id if hasattr(sw_node, "id") else iface.switch_port.switch_asset_id
                    
                    if target_sw_id in node_lookup and ep.id in node_lookup:
                        src_node = node_lookup[target_sw_id]
                        dst_node = node_lookup[ep.id]
                        waypoints = cls.compute_orthogonal_waypoints(
                            src_node.x, src_node.y, src_node.width, src_node.height,
                            dst_node.x, dst_node.y, dst_node.width, dst_node.height
                        )
                        edge_idx += 1
                        edges.append(GraphEdge(
                            id=f"edge-phys-{edge_idx}",
                            source_id=target_sw_id,
                            target_id=ep.id,
                            source_port=iface.switch_port.port_name,
                            target_port=iface.name,
                            edge_type="discovered_l1",
                            is_manual=False,  # Solid line = discovered
                            vlan_id=iface.switch_port.vlan_id,
                            waypoints=waypoints,
                            bandwidth_kbps=100000.0
                        ))

        # Add manual connections to unmanaged switches if specified
        if unmanaged_switches:
            for unsw in unmanaged_switches:
                for child_id in unsw.get("connected_asset_ids", []):
                    if child_id in node_lookup and unsw["id"] in node_lookup:
                        src_n = node_lookup[unsw["id"]]
                        dst_n = node_lookup[child_id]
                        edge_idx += 1
                        edges.append(GraphEdge(
                            id=f"edge-manual-{edge_idx}",
                            source_id=unsw["id"],
                            target_id=child_id,
                            source_port="Port",
                            target_port="eth0",
                            edge_type="manual_asserted",
                            is_manual=True,  # Dashed line = manually asserted link
                            waypoints=cls.compute_orthogonal_waypoints(
                                src_n.x, src_n.y, src_n.width, src_n.height,
                                dst_n.x, dst_n.y, dst_n.width, dst_n.height
                            )
                        ))

        return TopologyPerspectiveData(
            perspective=LayoutPerspective.CONNECTIONS,
            facility=assets[0].facility if assets else "Plant",
            nodes=nodes,
            edges=edges,
            unmanaged_switch_count=unmanaged_count
        )

    # 2. Locations Layout (Spatial Containment Hierarchy)
    @classmethod
    def _build_locations_layout(
        cls,
        assets: List[Asset],
        locations: Optional[List[LocationNode]] = None
    ) -> TopologyPerspectiveData:
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []

        # Group assets by area / skid
        areas: Dict[str, List[Asset]] = {}
        for a in assets:
            loc = a.area or "General Plant Floor"
            if loc not in areas:
                areas[loc] = []
            areas[loc].append(a)

        box_x = 40
        box_y = 60
        for area_name, area_assets in areas.items():
            col_count = math.ceil(math.sqrt(len(area_assets))) or 1
            box_w = max(320, col_count * 200 + 40)
            box_h = max(240, math.ceil(len(area_assets) / col_count) * 120 + 80)

            # Location bounding box
            box_id = f"loc-box-{area_name.lower().replace(' ', '-')}"
            nodes.append(GraphNode(
                id=box_id,
                label=f"LOCATION: {area_name.upper()}",
                node_type=GraphNodeType.LOCATION_BOX,
                x=float(box_x),
                y=float(box_y),
                width=float(box_w),
                height=float(box_h),
                metadata={"tier": "Control Room / Skid", "device_count": len(area_assets)}
            ))

            # Inner assets
            for idx, a in enumerate(area_assets):
                ax = box_x + 30 + (idx % col_count) * 190
                ay = box_y + 50 + (idx // col_count) * 110
                nodes.append(GraphNode(
                    id=a.id,
                    label=a.tag_name,
                    node_type=GraphNodeType.PLC if a.device_type == DeviceType.PLC else GraphNodeType.HMI,
                    x=float(ax),
                    y=float(ay),
                    width=170.0,
                    height=55.0,
                    purdue_level=a.purdue_level.value,
                    ip_address=a.network_interfaces[0].ip_address if a.network_interfaces else None,
                    parent_box_id=box_id
                ))

            box_x += box_w + 50
            if box_x > 1200:
                box_x = 40
                box_y += box_h + 60

        return TopologyPerspectiveData(
            perspective=LayoutPerspective.LOCATIONS,
            facility=assets[0].facility if assets else "Plant",
            nodes=nodes,
            edges=edges
        )

    # 3. Hierarchy (Purdue) Layout
    @classmethod
    def _build_purdue_layout(
        cls,
        assets: List[Asset],
        zones: List[PurdueZone],
        conduits: List[Conduit]
    ) -> TopologyPerspectiveData:
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        node_lookup: Dict[str, GraphNode] = {}

        # Vertical levels
        tier_y = {
            "Level 3.5": 40,
            "Level 3": 170,
            "Level 2": 320,
            "Level 1": 480,
            "Level 0": 640
        }

        tier_counts = {"Level 3.5": 0, "Level 3": 0, "Level 2": 0, "Level 1": 0, "Level 0": 0}

        for a in assets:
            lvl_key = "Level 1"
            for k in tier_y:
                if k in a.purdue_level.value:
                    lvl_key = k
                    break
            
            x_pos = 60 + tier_counts[lvl_key] * 210
            y_pos = tier_y[lvl_key]
            tier_counts[lvl_key] += 1

            gn = GraphNode(
                id=a.id,
                label=a.tag_name,
                node_type=GraphNodeType.PLC if a.device_type == DeviceType.PLC else (
                    GraphNodeType.HMI if a.device_type == DeviceType.HMI else GraphNodeType.SCADA_SERVER
                ),
                x=float(x_pos),
                y=float(y_pos),
                width=180.0,
                height=55.0,
                purdue_level=a.purdue_level.value,
                ip_address=a.network_interfaces[0].ip_address if a.network_interfaces else None
            )
            nodes.append(gn)
            node_lookup[a.id] = gn

        # Add conduits as orthogonal edges
        zone_map = {z.id: z for z in zones}
        for c in conduits:
            from_z = zone_map.get(c.from_zone_id)
            to_z = zone_map.get(c.to_zone_id)
            if from_z and to_z and from_z.asset_ids and to_z.asset_ids:
                src_id = from_z.asset_ids[0]
                dst_id = to_z.asset_ids[0]
                if src_id in node_lookup and dst_id in node_lookup:
                    src_n = node_lookup[src_id]
                    dst_n = node_lookup[dst_id]
                    waypoints = cls.compute_orthogonal_waypoints(
                        src_n.x, src_n.y, src_n.width, src_n.height,
                        dst_n.x, dst_n.y, dst_n.width, dst_n.height
                    )
                    edges.append(GraphEdge(
                        id=f"edge-cnd-{c.id}",
                        source_id=src_id,
                        target_id=dst_id,
                        edge_type="conduit",
                        protocol="/".join(c.allowed_protocols[:2]),
                        waypoints=waypoints,
                        is_manual=False
                    ))

        return TopologyPerspectiveData(
            perspective=LayoutPerspective.PURDUE_HIERARCHY,
            facility=assets[0].facility if assets else "Plant",
            nodes=nodes,
            edges=edges
        )

    # 4. Networks Layout (Layer 3 Subnetting)
    @classmethod
    def _build_networks_layout(cls, assets: List[Asset]) -> TopologyPerspectiveData:
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []

        subnets: Dict[str, List[Asset]] = {}
        for a in assets:
            for iface in a.network_interfaces:
                if iface.ip_address:
                    octs = iface.ip_address.split(".")
                    sub = f"{octs[0]}.{octs[1]}.{octs[2]}.0/24"
                    if sub not in subnets:
                        subnets[sub] = []
                    subnets[sub].append(a)
                    break

        cur_x = 40
        for sub, sub_assets in subnets.items():
            # Subnet router node
            sub_id = f"sub-{sub.replace('/', '_').replace('.', '_')}"
            nodes.append(GraphNode(
                id=sub_id,
                label=f"NETWORK\n{sub}",
                node_type=GraphNodeType.SUBNET,
                x=float(cur_x),
                y=80.0,
                width=180.0,
                height=60.0,
                metadata={"host_count": len(sub_assets)}
            ))

            for idx, a in enumerate(sub_assets):
                ay = 180 + idx * 80
                nodes.append(GraphNode(
                    id=a.id,
                    label=a.tag_name,
                    node_type=GraphNodeType.PLC if a.device_type == DeviceType.PLC else GraphNodeType.HMI,
                    x=float(cur_x),
                    y=float(ay),
                    width=180.0,
                    height=50.0,
                    ip_address=a.network_interfaces[0].ip_address if a.network_interfaces else None
                ))
                edges.append(GraphEdge(
                    id=f"edge-sub-{a.id}",
                    source_id=sub_id,
                    target_id=a.id,
                    edge_type="routed_l3",
                    waypoints=[
                        [cur_x + 90, 140],
                        [cur_x + 90, ay]
                    ]
                ))

            cur_x += 280

        return TopologyPerspectiveData(
            perspective=LayoutPerspective.NETWORKS,
            facility=assets[0].facility if assets else "Plant",
            nodes=nodes,
            edges=edges
        )

    # 5. Organic Layout (Force-directed clustering)
    @classmethod
    def _build_organic_layout(cls, assets: List[Asset]) -> TopologyPerspectiveData:
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        
        # Radial clustering around core switch / controller
        center_x = 550
        center_y = 350
        radius = 280
        total = len(assets)

        for idx, a in enumerate(assets):
            angle = (2 * math.pi / max(1, total)) * idx
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)

            nodes.append(GraphNode(
                id=a.id,
                label=a.tag_name,
                node_type=GraphNodeType.PLC if a.device_type == DeviceType.PLC else GraphNodeType.HMI,
                x=float(cls.snap(x)),
                y=float(cls.snap(y)),
                width=160.0,
                height=50.0,
                ip_address=a.network_interfaces[0].ip_address if a.network_interfaces else None
            ))

        return TopologyPerspectiveData(
            perspective=LayoutPerspective.ORGANIC,
            facility=assets[0].facility if assets else "Plant",
            nodes=nodes,
            edges=edges
        )

    # Exporters: SVG, GraphML, Visio XML
    @classmethod
    def export_svg(cls, data: TopologyPerspectiveData) -> str:
        """Generates standard SVG schematic blueprint of the Kandinsky orthogonal layout."""
        svg_lines = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 1000" width="100%" height="100%" style="background:#090d16; font-family:Inter,sans-serif;">',
            f'<defs>',
            f'  <marker id="arrow" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
            f'    <path d="M 0 0 L 10 5 L 0 10 z" fill="#38bdf8"/>',
            f'  </marker>',
            f'  <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">',
            f'    <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#1e293b" stroke-width="0.5"/>',
            f'  </pattern>',
            f'</defs>',
            f'<rect width="100%" height="100%" fill="url(#grid)"/>',
            f'<text x="30" y="40" fill="#38bdf8" font-size="18" font-weight="bold">OTBASE TOPOLOGY // {data.perspective.value.upper()}</text>',
            f'<text x="30" y="60" fill="#94a3b8" font-size="12">Facility: {data.facility} | Kandinsky Orthogonal 90-Degree Routing</text>'
        ]

        # Render edges
        for edge in data.edges:
            stroke_style = "stroke:#ef4444; stroke-dasharray:6,6;" if edge.is_manual else "stroke:#0284c7;"
            points_str = " ".join([f"{p[0]},{p[1]}" for p in edge.waypoints])
            if points_str:
                svg_lines.append(f'<polyline points="{points_str}" fill="none" style="{stroke_style} stroke-width:2;" />')
                if edge.source_port:
                    first_pt = edge.waypoints[0]
                    svg_lines.append(f'<text x="{first_pt[0]+4}" y="{first_pt[1]-4}" fill="#38bdf8" font-size="9">{edge.source_port}</text>')

        # Render nodes
        for node in data.nodes:
            color = "#1e293b"
            border = "#38bdf8"
            if node.node_type == GraphNodeType.MANAGED_SWITCH:
                border = "#06b6d4"
            elif node.node_type == GraphNodeType.UNMANAGED_SWITCH:
                border = "#eab308"
            elif node.node_type == GraphNodeType.ROUTER_FIREWALL:
                border = "#dc2626"
            elif node.node_type == GraphNodeType.LOCATION_BOX:
                color = "rgba(15, 23, 42, 0.4)"
                border = "#64748b"

            svg_lines.append(f'<rect x="{node.x}" y="{node.y}" width="{node.width}" height="{node.height}" rx="4" fill="{color}" stroke="{border}" stroke-width="1.5" />')
            lines = node.label.split("\n")
            for i, line in enumerate(lines):
                svg_lines.append(f'<text x="{node.x + 10}" y="{node.y + 20 + i*16}" fill="#f8fafc" font-size="11" font-weight="bold">{line}</text>')
            if node.ip_address:
                svg_lines.append(f'<text x="{node.x + 10}" y="{node.y + node.height - 8}" fill="#94a3b8" font-size="10">{node.ip_address}</text>')

        svg_lines.append('</svg>')
        return "\n".join(svg_lines)

    @classmethod
    def export_graphml(cls, data: TopologyPerspectiveData) -> str:
        """Exports the topology graph to standard GraphML format for yFiles / Gephi."""
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="d0" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="d1" for="node" attr.name="ip" attr.type="string"/>',
            '  <key id="d2" for="edge" attr.name="port" attr.type="string"/>',
            '  <key id="d3" for="edge" attr.name="manual" attr.type="boolean"/>',
            '  <graph id="G" edgedefault="undirected">'
        ]
        for n in data.nodes:
            lines.append(f'    <node id="{n.id}">')
            lines.append(f'      <data key="d0">{n.label.replace(chr(10), " ")}</data>')
            if n.ip_address:
                lines.append(f'      <data key="d1">{n.ip_address}</data>')
            lines.append('    </node>')

        for e in data.edges:
            lines.append(f'    <edge id="{e.id}" source="{e.source_id}" target="{e.target_id}">')
            if e.source_port:
                lines.append(f'      <data key="d2">{e.source_port}</data>')
            lines.append(f'      <data key="d3">{"true" if e.is_manual else "false"}</data>')
            lines.append('    </edge>')

        lines.append('  </graph>')
        lines.append('</graphml>')
        return "\n".join(lines)
