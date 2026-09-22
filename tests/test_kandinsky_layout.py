from otbase.engine.kandinsky_layout import KandinskyLayoutEngine
from otbase.models.topology import LayoutPerspective
from otbase.models.asset import Asset, DeviceType, PurdueLevel, NetworkInterface

def test_kandinsky_orthogonal_routing_and_perspectives():
    # Test orthogonal waypoint computation
    waypoints = KandinskyLayoutEngine.compute_orthogonal_waypoints(
        src_x=100, src_y=100, src_w=100, src_h=50,
        dst_x=300, dst_y=300, dst_w=100, dst_h=50
    )
    assert len(waypoints) == 4
    # Verify right angles: p0 to p1 is vertical, p1 to p2 is horizontal, p2 to p3 is vertical
    assert waypoints[0][0] == waypoints[1][0]
    assert waypoints[1][1] == waypoints[2][1]
    assert waypoints[2][0] == waypoints[3][0]

    # Test perspective generation
    assets = [
        Asset(
            id="sw-01",
            tag_name="SW-01",
            display_name="Switch 01",
            vendor="Cisco",
            model="IE-3400",
            device_type=DeviceType.INDUSTRIAL_SWITCH,
            purdue_level=PurdueLevel.LEVEL_2,
            network_interfaces=[NetworkInterface(mac_address="00:11:22:33:44:01", ip_address="192.168.20.2")]
        ),
        Asset(
            id="plc-01",
            tag_name="PLC-01",
            display_name="PLC 01",
            vendor="Rockwell",
            model="5580",
            device_type=DeviceType.PLC,
            purdue_level=PurdueLevel.LEVEL_1,
            network_interfaces=[NetworkInterface(mac_address="00:11:22:33:44:02", ip_address="192.168.10.10")]
        )
    ]

    persp = KandinskyLayoutEngine.generate_perspective(
        perspective=LayoutPerspective.CONNECTIONS,
        assets=assets,
        zones=[],
        conduits=[]
    )
    assert len(persp.nodes) == 2
    assert persp.perspective == LayoutPerspective.CONNECTIONS

    # Test SVG and GraphML export
    svg = KandinskyLayoutEngine.export_svg(persp)
    assert "<svg" in svg
    assert "Kandinsky" in svg

    graphml = KandinskyLayoutEngine.export_graphml(persp)
    assert "<graphml" in graphml
