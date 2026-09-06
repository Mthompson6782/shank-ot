import io
import json
import zipfile
import sqlite3
import pytest
from otbase.discovery.parsers.ignition_parser import IgnitionParser
from otbase.models.asset import DeviceType, PurdueLevel, Criticality

SAMPLE_IGNITION_TAGS_JSON = json.dumps({
    "name": "DefaultTagProvider",
    "tagType": "Provider",
    "tags": [
        {
            "name": "WaterTreatment",
            "tagType": "Folder",
            "tags": [
                {
                    "name": "RawWaterIntake",
                    "tagType": "Folder",
                    "tags": [
                        {
                            "name": "IntakePump_Flow_GPM",
                            "tagType": "AtomicTag",
                            "dataType": "Float4",
                            "valueSource": "opc",
                            "opcServer": "Ignition OPC UA Server",
                            "opcItemPath": "ns=1;s=[Intake_ControlLogix_PLC]Program:Intake.FlowRate"
                        },
                        {
                            "name": "ChlorineGas_Feed_PPM",
                            "tagType": "AtomicTag",
                            "dataType": "Float4",
                            "valueSource": "opc",
                            "opcServer": "Ignition OPC UA Server",
                            "opcItemPath": "ns=1;s=[Chemical_CompactLogix_PLC]Program:Dosing.ChlorineFeedRate"
                        }
                    ]
                },
                {
                    "name": "BoilerPlant",
                    "tagType": "Folder",
                    "tags": [
                        {
                            "name": "Boiler4_EmergencyShutdown_Trip",
                            "tagType": "AtomicTag",
                            "dataType": "Boolean",
                            "valueSource": "opc",
                            "opcServer": "Ignition OPC UA Server",
                            "opcItemPath": "ns=1;s=[Boiler_Safety_SIS]Program:Safety.ESD_TripActive"
                        }
                    ]
                }
            ]
        }
    ]
})

def create_mock_gwbk_bytes() -> bytes:
    """Creates an in-memory .gwbk zip file containing an SQLite database and ignition.conf."""
    # 1. Create in-memory SQLite database
    db_buffer = io.BytesIO()
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE DEVICES (
            DEVICES_ID INTEGER PRIMARY KEY,
            NAME TEXT,
            TYPE TEXT,
            ENABLED INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE DEVICESETTINGS (
            DEVICESETTINGS_ID INTEGER PRIMARY KEY,
            DEVICEID INTEGER,
            PROPNAME TEXT,
            PROPVALUE TEXT
        )
    """)

    # Insert mock devices
    cursor.execute("INSERT INTO DEVICES VALUES (1, 'Wellfield_ControlLogix', 'com.inductiveautomation.ControlLogix', 1)")
    cursor.execute("INSERT INTO DEVICES VALUES (2, 'Substation_RTAC', 'com.inductiveautomation.DNP3', 1)")
    cursor.execute("INSERT INTO DEVICES VALUES (3, 'Filter_S7_1500', 'com.inductiveautomation.SiemensS71500', 1)")

    # Insert device settings (IPs and slots)
    cursor.execute("INSERT INTO DEVICESETTINGS VALUES (1, 1, 'Hostname', '192.168.10.35')")
    cursor.execute("INSERT INTO DEVICESETTINGS VALUES (2, 1, 'Slot', '1')")
    cursor.execute("INSERT INTO DEVICESETTINGS VALUES (3, 2, 'Hostname', '10.20.10.10')")
    cursor.execute("INSERT INTO DEVICESETTINGS VALUES (4, 3, 'Hostname', '192.168.10.70')")
    cursor.execute("INSERT INTO DEVICESETTINGS VALUES (5, 3, 'Slot', '2')")

    conn.commit()

    # Dump SQLite database to memory buffer
    backup_conn = sqlite3.connect(database="")
    # Write db to buffer using dump
    sqlite_file = io.BytesIO()
    for line in conn.iterdump():
        pass
    conn.close()

    # Create real SQLite file on disk or in bytes
    real_db_bytes = io.BytesIO()
    real_conn = sqlite3.connect(database="")
    # Use real temp sqlite file
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
        tpath = tf.name

    tmp_conn = sqlite3.connect(tpath)
    tmp_cur = tmp_conn.cursor()
    tmp_cur.execute("CREATE TABLE DEVICES (DEVICES_ID INTEGER PRIMARY KEY, NAME TEXT, TYPE TEXT, ENABLED INTEGER)")
    tmp_cur.execute("CREATE TABLE DEVICESETTINGS (DEVICESETTINGS_ID INTEGER PRIMARY KEY, DEVICEID INTEGER, PROPNAME TEXT, PROPVALUE TEXT)")
    tmp_cur.execute("INSERT INTO DEVICES VALUES (1, 'Wellfield_ControlLogix', 'com.inductiveautomation.ControlLogix', 1)")
    tmp_cur.execute("INSERT INTO DEVICES VALUES (2, 'Substation_RTAC', 'com.inductiveautomation.DNP3', 1)")
    tmp_cur.execute("INSERT INTO DEVICES VALUES (3, 'Filter_S7_1500', 'com.inductiveautomation.SiemensS71500', 1)")
    tmp_cur.execute("INSERT INTO DEVICESETTINGS VALUES (1, 1, 'Hostname', '192.168.10.35')")
    tmp_cur.execute("INSERT INTO DEVICESETTINGS VALUES (2, 1, 'Slot', '1')")
    tmp_cur.execute("INSERT INTO DEVICESETTINGS VALUES (3, 2, 'Hostname', '10.20.10.10')")
    tmp_cur.execute("INSERT INTO DEVICESETTINGS VALUES (4, 3, 'Hostname', '192.168.10.70')")
    tmp_conn.commit()
    tmp_conn.close()

    with open(tpath, "rb") as rf:
        sqlite_content = rf.read()
    
    from pathlib import Path
    Path(tpath).unlink(missing_ok=True)

    # 2. Package into .gwbk zip
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("db_backup.sqlite", sqlite_content)
        z.writestr("ignition.conf", "wrapper.app.parameter.1=Plant_Primary_Gateway\n")
        z.writestr("backupinfo.xml", "<backupinfo><version>8.1.33</version></backupinfo>")

    return zip_buffer.getvalue()

def test_parse_ignition_gwbk():
    gwbk_bytes = create_mock_gwbk_bytes()
    assets, conduits = IgnitionParser.parse_gwbk_bytes(gwbk_bytes, facility="Municipal Water Facility")

    # Should have 1 Gateway + 3 Discovered PLCs/RTUs = 4 Assets
    assert len(assets) == 4

    # Verify Gateway asset
    gw = next(a for a in assets if a.device_type == DeviceType.SCADA_SERVER)
    assert gw.vendor == "Inductive Automation"
    assert "8.1.33" in gw.model
    assert gw.purdue_level == PurdueLevel.LEVEL_2

    # Verify Discovered PLCs
    clx = next(a for a in assets if "WELLFIELD" in a.tag_name)
    assert clx.vendor == "Rockwell Automation"
    assert clx.model == "ControlLogix"
    assert clx.network_interfaces[0].ip_address == "192.168.10.35"
    assert clx.purdue_level == PurdueLevel.LEVEL_1

    rtac = next(a for a in assets if "SUBSTATION" in a.tag_name)
    assert rtac.device_type == DeviceType.RTU
    assert rtac.network_interfaces[0].ip_address == "10.20.10.10"

    s7 = next(a for a in assets if "FILTER" in a.tag_name)
    assert s7.vendor == "Siemens"
    assert s7.network_interfaces[0].ip_address == "192.168.10.70"

    # Verify conduits created
    assert len(conduits) == 3

def test_parse_ignition_tag_json():
    assets, conduits = IgnitionParser.parse_tag_json(SAMPLE_IGNITION_TAGS_JSON, facility="Water Treatment Facility")

    # 3 Distinct PLCs discovered from tags: Intake_ControlLogix_PLC, Chemical_CompactLogix_PLC, Boiler_Safety_SIS
    assert len(assets) == 3

    tags = [a.tag_name for a in assets]
    assert "INTAKE_CONTROLLOGIX_PLC" in tags
    assert "CHEMICAL_COMPACTLOGIX_PLC" in tags
    assert "BOILER_SAFETY_SIS" in tags

    # Verify process semantics: Boiler_Safety_SIS has emergency shutdown / safety tags -> Criticality.SAFETY_CRITICAL
    sis = next(a for a in assets if "BOILER" in a.tag_name)
    assert sis.criticality == Criticality.SAFETY_CRITICAL

    # Intake PLC should be High
    clx = next(a for a in assets if "INTAKE" in a.tag_name)
    assert clx.criticality == Criticality.HIGH
