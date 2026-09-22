from otbase.discovery.backplane_crawler import BackplaneCrawler

def test_cip_backplane_crawl_simulation():
    chassis, downstream = BackplaneCrawler.simulate_cip_backplane_crawl("192.168.10.10")
    assert chassis.total_slots == 10
    assert len(chassis.modules) == 7
    assert chassis.modules[0].catalog_number == "1756-L83E"
    assert chassis.modules[1].catalog_number == "1756-EN2T"

    # Verify downstream remote I/O and drives were discovered
    assert len(downstream) == 2
    tags = [d.tag_name for d in downstream]
    assert "RIO-POINT-IO-01" in tags
    assert "VFD-PUMP-DRIVE-01" in tags

def test_profinet_dcp_broadcast_parser():
    dcp_data = {
        "station_name": "simatic-et200sp-node4",
        "mac_address": "00:0E:8C:11:22:33",
        "vendor_id": "0x002A",
        "device_id": "0x0301",
        "ip_address": "192.168.10.60",
        "subnet_mask": "255.255.255.0",
        "gateway": "192.168.10.1"
    }
    parsed = BackplaneCrawler.parse_profinet_dcp_broadcast(dcp_data)
    assert parsed["protocol"] == "PROFINET DCP"
    assert parsed["station_name"] == "simatic-et200sp-node4"
    assert parsed["ip_address"] == "192.168.10.60"
