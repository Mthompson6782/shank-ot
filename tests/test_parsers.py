import pytest
from otbase.discovery.parsers.rockwell_l5x import RockwellL5XParser
from otbase.discovery.parsers.siemens_aml import SiemensAMLParser
from otbase.discovery.parsers.generic_csv import GenericAssetParser
from otbase.models.asset import ModuleType

SAMPLE_L5X = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<RSLogix5000Content SchemaRevision="1.0" SoftwareRevision="33.01" TargetName="PUMP_CONTROLLER" TargetType="Controller" ContainsContext="true">
  <Controller Use="Context" Name="PUMP_CONTROLLER" ProcessorType="1756-L83E" MajorRev="33" MinorRev="011">
    <Modules>
      <Module Name="CPU_Local" CatalogNumber="1756-L83E" Slot="0" Major="33" Minor="11"/>
      <Module Name="COMM_ETH" CatalogNumber="1756-EN2T" Slot="1" Major="5" Minor="28"/>
      <Module Name="DISCRETE_IN" CatalogNumber="1756-IB16" Slot="2" Major="3" Minor="2"/>
    </Modules>
  </Controller>
</RSLogix5000Content>"""

SAMPLE_AML = """<?xml version="1.0" encoding="utf-8"?>
<CAEXFile FileName="TIA_Hardware_Config.aml" SchemaVersion="2.15" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <InstanceHierarchy Name="WaterPlant_Automation">
    <InternalElement Name="S71500_Filter_PLC" OrderNumber="6ES7516-3AN02-0AB0">
      <Attribute Name="FirmwareVersion">
        <Value>2.8.3</Value>
      </Attribute>
      <InternalElement Name="DI_32x24V" OrderNumber="6ES7521-1BL00-0AB0" />
    </InternalElement>
  </InstanceHierarchy>
</CAEXFile>"""

SAMPLE_CSV = """tag_name,vendor,model,firmware_version,ip_address,purdue_level,device_type
PLC-BOOSTER-99,Rockwell Automation,1756-L83E,33.011,192.168.10.99,1,PLC
HMI-TOUCH-01,AVEVA,InTouch,2020 R2,192.168.20.15,2,HMI
"""

def test_rockwell_l5x_parser():
    asset = RockwellL5XParser.parse_string(SAMPLE_L5X, facility="Test Plant")
    assert asset.tag_name == "PUMP_CONTROLLER"
    assert asset.model == "1756-L83E"
    assert asset.firmware_version == "33.011"
    assert asset.chassis is not None
    assert len(asset.chassis.modules) == 3
    assert asset.chassis.modules[0].catalog_number == "1756-L83E"
    assert asset.chassis.modules[1].catalog_number == "1756-EN2T"

def test_siemens_aml_parser():
    asset = SiemensAMLParser.parse_string(SAMPLE_AML, facility="Test Plant")
    assert "S71500" in asset.tag_name
    assert asset.vendor == "Siemens"
    assert asset.firmware_version == "2.8.3"
    assert asset.chassis is not None

def test_generic_csv_parser():
    assets = GenericAssetParser.parse_csv(SAMPLE_CSV, facility="Test Plant")
    assert len(assets) == 2
    assert assets[0].tag_name == "PLC-BOOSTER-99"
    assert assets[0].network_interfaces[0].ip_address == "192.168.10.99"
    assert assets[1].tag_name == "HMI-TOUCH-01"
