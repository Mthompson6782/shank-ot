from datetime import datetime, timezone
from otbase.models.pid_schema import (
    PIDPayload, DiscoveryNodeMetadata, ArpDiscoveryEntry, SwitchPortDiscovery,
    SwitchPortLearnedMac, FlowTelemetryRecord
)
from otbase.db.repository import repo

def test_pid_payload_validation_and_ingestion():
    payload = PIDPayload(
        pid_version="1.0.0",
        metadata=DiscoveryNodeMetadata(
            probe_id="probe-edge-substation-01",
            location_id="loc-skid-01",
            location_path="Global Corp/Substation Alpha/Relay Room/Panel 4",
            probed_subnets=["192.168.10.0/24"]
        ),
        arp_entries=[
            ArpDiscoveryEntry(
                ip_address="192.168.10.180",
                mac_address="00:1D:9C:AA:BB:CC",
                oui_vendor="Rockwell Automation",
                hostname="REMOTE-PANEL-01"
            )
        ],
        switch_ports=[
            SwitchPortDiscovery(
                switch_ip="192.168.20.2",
                switch_name="SW-01-IND",
                if_index=7,
                if_name="FastEthernet1/7",
                learned_macs=[SwitchPortLearnedMac(mac_address="00:1D:9C:AA:BB:CC", vlan_id=10)]
            )
        ],
        flow_telemetry=[
            FlowTelemetryRecord(
                src_ip="192.168.20.15",
                dst_ip="192.168.10.180",
                src_port=50000,
                dst_port=44818,
                protocol="TCP",
                byte_count=5242880,
                packet_count=6400,
                sampling_ratio=128
            )
        ]
    )

    result = repo.ingest_pid(payload)
    assert result["status"] == "success"
    assert result["probe_id"] == "probe-edge-substation-01"
    assert "REMOTE-PANEL-01" in result["assets"]

    # Verify asset was created with proper location
    asset = None
    for a in repo.list_assets():
        if a.tag_name == "REMOTE-PANEL-01":
            asset = a
            break
    assert asset is not None
    assert asset.location_id == "loc-skid-01"
    assert asset.network_interfaces[0].ip_address == "192.168.10.180"
