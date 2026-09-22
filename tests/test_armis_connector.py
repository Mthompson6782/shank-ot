"""
Tests for Armis Integration Connector & Reconciliation Engine
=============================================================
Verifies:
1. Armis token authentication & AQL device querying (simulation)
2. Normalization of ArmisDeviceRecord to SHANK Asset models
3. Discrepancy detection: Firmware drift, port conflict, rogue assets, dormant assets
4. Ingestion of Armis connection flows into FlowEngine
5. FastAPI REST endpoints for Armis sync and reconciliation
"""

import pytest
from fastapi.testclient import TestClient

from otbase.web.app import app
from otbase.db.repository import repo
from otbase.discovery.armis_connector import ArmisConnector, ReconciliationEngine
from otbase.models.asset import Asset, DeviceType, PurdueLevel, NetworkInterface, SwitchPortBinding
from otbase.models.armis_schema import ArmisDeviceRecord, DiscrepancyType, DiscrepancySeverity


def test_armis_authentication_and_mock_dataset():
    connector = ArmisConnector(simulate=True)
    token = connector.authenticate()
    assert token.startswith("armis_sim_jwt_token")

    devices = connector.get_devices(aql="in:devices")
    assert len(devices) >= 8

    # Verify device attributes
    plc_dev = next(d for d in devices if d.name == "PLC-01-MAIN")
    assert plc_dev.manufacturer == "Rockwell Automation"
    assert plc_dev.ip_address == "192.168.10.10"
    assert plc_dev.mac_address == "00:1D:9C:C4:55:01"
    assert "CIP" in plc_dev.protocols

    connections = connector.get_connections()
    assert len(connections) >= 4
    # Check unauthorized rogue connection is present
    rogue_conn = next(c for c in connections if c.source_ip == "192.168.20.88")
    assert rogue_conn.destination_ip == "192.168.10.10"
    assert rogue_conn.protocol == "CIP"


def test_armis_device_normalization_to_asset():
    connector = ArmisConnector(simulate=True)
    mock_dev = ArmisDeviceRecord(
        id=999,
        name="PLC-TEST-01",
        ipAddress="10.0.0.50",
        macAddress="00:11:22:33:44:55",
        manufacturer="Siemens",
        model="S7-1500",
        category="Industrial",
        type="PLC",
        operatingSystem="Siemens Firmware",
        operatingSystemVersion="v2.8",
        switch="10.0.0.2",
        switchPort="GigabitEthernet0/1",
        vlan=10,
        riskLevel=6,
        vulnerabilities=["CVE-2020-15782"],
    )

    asset = connector.normalize_device_to_asset(mock_dev)
    assert asset.tag_name == "PLC-TEST-01"
    assert asset.device_type == DeviceType.PLC
    assert asset.purdue_level == PurdueLevel.LEVEL_1
    assert len(asset.network_interfaces) == 1
    assert asset.network_interfaces[0].ip_address == "10.0.0.50"
    assert asset.network_interfaces[0].mac_address == "00:11:22:33:44:55"
    assert asset.network_interfaces[0].switch_port is not None
    assert asset.network_interfaces[0].switch_port.port_name == "GigabitEthernet0/1"
    assert "CVE-2020-15782" in asset.active_cves


def test_reconciliation_engine_discrepancy_detection():
    engine = ReconciliationEngine()

    # Ground truth asset with firmware 33.011 and switch port Fa1/1
    gt_asset = Asset(
        id="gt-plc-01",
        tag_name="PLC-01-MAIN",
        display_name="Main PLC",
        vendor="Rockwell Automation",
        model="ControlLogix 5580",
        firmware_version="33.011",
        device_type=DeviceType.PLC,
        purdue_level=PurdueLevel.LEVEL_1,
        network_interfaces=[
            NetworkInterface(
                name="eth0",
                mac_address="00:1D:9C:C4:55:01",
                ip_address="192.168.10.10",
                switch_port=SwitchPortBinding(
                    switch_asset_id="sw-01",
                    port_name="FastEthernet1/1",
                )
            )
        ]
    )

    # Dormant asset with no Armis traffic
    dormant_asset = Asset(
        id="gt-cold-standby",
        tag_name="PLC-STANDBY-02",
        display_name="Cold Standby PLC",
        vendor="Rockwell Automation",
        model="1756-L83E",
        firmware_version="33.011",
        device_type=DeviceType.PLC,
        purdue_level=PurdueLevel.LEVEL_1,
        network_interfaces=[
            NetworkInterface(
                name="eth0",
                mac_address="00:1D:9C:C4:99:99",
                ip_address="192.168.10.99",
            )
        ]
    )

    # Armis device with firmware drift (observed v32 instead of 33.011) and port conflict (Fa1/9 vs Fa1/1)
    armis_correlated = ArmisDeviceRecord(
        id=101,
        name="PLC-01-MAIN",
        ipAddress="192.168.10.10",
        macAddress="00:1D:9C:C4:55:01",
        manufacturer="Rockwell Automation",
        model="ControlLogix 5580",
        category="Industrial",
        type="PLC",
        operatingSystemVersion="v32",  # Mismatch!
        switchPort="FastEthernet1/9",  # Port Mismatch!
    )

    # Rogue device discovered by Armis, not in repository
    armis_rogue = ArmisDeviceRecord(
        id=999,
        name="ROGUE-RASPBERRY-PI",
        ipAddress="192.168.10.250",
        macAddress="B8:27:EB:11:22:33",
        manufacturer="Raspberry Pi Foundation",
        model="Raspberry Pi 4",
        category="Computers",
        type="Workstation",
    )

    report = engine.reconcile(
        armis_devices=[armis_correlated, armis_rogue],
        repository_assets=[gt_asset, dormant_asset]
    )

    assert report.total_armis_devices == 2
    assert report.total_otbase_assets == 2
    assert report.correlated_assets_count == 1
    assert report.rogue_assets_count == 1
    assert report.dormant_assets_count == 1

    disc_types = [d.discrepancy_type for d in report.discrepancies]
    assert DiscrepancyType.FIRMWARE_MISMATCH in disc_types
    assert DiscrepancyType.PORT_MISMATCH in disc_types
    assert DiscrepancyType.ROGUE_ASSET in disc_types
    assert DiscrepancyType.DORMANT_ASSET in disc_types


def test_armis_fastapi_rest_endpoints():
    client = TestClient(app)

    # 1. Trigger Armis Sync
    sync_resp = client.post("/api/armis/sync", json={"simulate": True, "aql": "in:devices"})
    assert sync_resp.status_code == 200
    sync_data = sync_resp.json()
    assert sync_data["status"] == "success"
    assert sync_data["devices_discovered"] >= 8
    assert sync_data["rogue_assets"] >= 1

    # 2. Get Armis Devices
    dev_resp = client.get("/api/armis/devices")
    assert dev_resp.status_code == 200
    dev_data = dev_resp.json()
    assert dev_data["count"] >= 8

    # 3. Get Reconciliation Report
    recon_resp = client.get("/api/armis/reconciliation")
    assert recon_resp.status_code == 200
    recon_data = recon_resp.json()
    assert len(recon_data["discrepancies"]) > 0
    assert any(d["discrepancy_type"] == "ROGUE_ASSET" for d in recon_data["discrepancies"])
    assert any(d["discrepancy_type"] == "FIRMWARE_MISMATCH" for d in recon_data["discrepancies"])

    # 4. Ingest Connection Flows to Sankey Flow Engine
    flow_resp = client.post("/api/armis/connections/ingest-to-flows")
    assert flow_resp.status_code == 200
    flow_data = flow_resp.json()
    assert flow_data["status"] == "success"
    assert flow_data["total_flows"] > 0
