# OT-BASE: Operational Technology Asset Management & Cybersecurity Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
[![ISA/IEC 62443](https://img.shields.io/badge/Compliance-ISA%2FIEC%2062443-orange.svg)](https://www.isa.org/standards-and-publications/isa-standards/isa-standards-committees/isa62443)
[![NIST SP 800-82r3](https://img.shields.io/badge/Framework-NIST%20SP%20800--82r3-red.svg)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)

**OT-BASE** is a high-fidelity, open architecture Operational Technology (OT) and Industrial Control System (ICS/SCADA) asset management and cybersecurity platform inspired by **Langner OT-BASE** (created by Ralph Langner).

Traditional IT asset management tools (Lansweeper, ServiceNow, Qualys, Tenable) assume that an asset is a single IP address with an agent installed on a standard OS. In cyber-physical industrial facilities, this assumption fails catastrophically:
- A single IP address often conceals an entire multi-slot **PLC Backplane / Chassis** (such as a Rockwell ControlLogix 1756 or Siemens S7-1500) housing independent power supplies, CPUs, communication cards, I/O modules, and motion/safety controllers—each with its own catalog number, hardware revision, serial number, and firmware version.
- Aggressive IT port scans or uncoordinated ping sweeps can freeze fragile industrial controllers, trip plant safety systems, and cause physical damage.
- IT CVSS scores fail to capture industrial realities. A vulnerability in an isolated Level 1 safety controller whose physical memory key switch is locked to `RUN` presents vastly different real-world risk than an exposed service in the Industrial DMZ.

---

## The 6 Core Pillars of OT-BASE

```
+-----------------------------------------------------------------------------------------------------------------+
|                                          OT-BASE Web Asset Center                                               |
|  - Executive KPI Dashboard & Real-Time Risk Heatmaps                                                            |
|  - Visual PLC Rack / Backplane Chassis Explorer (Slot-by-Slot Hardware & LED Status)                            |
|  - Purdue Enterprise Reference Architecture (PERA) & Zone / Conduit Visualizer                                   |
|  - Contextual OT Vulnerability & ICS-CERT Advisory Correlation Engine                                            |
|  - Hardware Obsolescence & End-of-Life (EOL / EOS) Replacement Planner                                          |
|  - Ingestion Lab (Rockwell Studio 5000 .L5X, Siemens .aml, CSV/JSON & Non-Intrusive Probes)                     |
+-------------------------------------------------------+---------------------------------------------------------+
                                                        |
                                                        v
+-----------------------------------------------------------------------------------------------------------------+
|                                           FastAPI Core Platform Backend                                         |
+------------------------------------+------------------------------------+---------------------------------------+
|         Asset & Backplane DB       |       Purdue Segmentation Rules    |        Contextual OT Risk Engine      |
|  - Enterprise -> Facility -> Area  |  - Levels 0, 1, 2, 3, 3.5, 4       |  - CVSS v3 Base Score                 |
|  - Numbered Backplane Slots        |  - ISA/IEC 62443 Security Zones    |  - Purdue Location Exposure Factor    |
|  - Sub-Module Firmware Tracking    |  - Cross-Zone Conduits & Ports     |  - Process Impact Criticality (SIS)   |
|  - Dual-Homed NIC Detection        |  - Automated Violation Detection   |  - Key Switch Write-Protect Discount  |
+------------------------------------+------------------------------------+---------------------------------------+
|                                    Discovery & Parser Subsystem                                                 |
|  - Studio 5000 .L5X XML Parser     |  - Siemens TIA Portal .aml Parser  |  - Safe Passive Broadcast Sniffer     |
+-----------------------------------------------------------------------------------------------------------------+
|                                        Compliance & HBOM / SBOM Subsystem                                       |
|  - IEC 62443-3-3 FR1-FR7 Auditing  |  - NIST SP 800-82r3 Flaw Controls  |  - Hardware Bill of Materials (HBOM)  |
+-----------------------------------------------------------------------------------------------------------------+
```

### 1. Visual PLC Rack / Chassis Backplane Modeling (The Signature OT-BASE Feature)
Unlike IT scanners that stop at the network interface, OT-BASE accurately models industrial chassis:
- **Rockwell ControlLogix 1756** (4, 7, 10, 13, 17-slot chassis) and **Siemens S7-1500 / S7-400** modular rails.
- Displays slot numbers (0–16), catalog/part numbers, serial numbers, hardware revisions, and firmware versions for every card.
- Real-time animated **LED Status Indicators** (`RUN`, `FORCE`, `BAT`, `NET`, `OK`, `FLT`).
- **Slot-Level CVE Tracking**: Distinguishes between vulnerabilities in the CPU (e.g. CVE-2022-1159) versus vulnerabilities in the Ethernet communications bridge (e.g. CVE-2020-6967 in 1756-EN2T).

### 2. Purdue Reference Architecture & ISA/IEC 62443 Conduits
Visualizes and audits segmentation across all Purdue levels:
- **Level 0**: Physical Process & Field Instrumentation (Flowmeters, Transmitters, Drives).
- **Level 1**: Basic Process Control Systems (PLCs, RTUs, IEDs, Safety Instrumented Systems).
- **Level 2**: Supervisory & Area Control (Operator HMIs, SCADA Terminals, Industrial Managed Switches).
- **Level 3**: Site Operations & Control (Historians, Engineering Workstations, Asset Centers).
- **Level 3.5**: Industrial DMZ (IDMZ Jump Hosts, Reverse Proxies, Security Gateways).
- **Automated Violation Audit**: Flags dual-homed multi-NIC bridges bypassing supervisory firewalls, direct Level 4 IT-to-OT links, uninspected cross-zone conduits, and PLCs left in `REMOTE` position.

### 3. Contextual OT Vulnerability & Advisory Engine
In OT, CVSS Base scores are insufficient. OT-BASE applies Ralph Langner's contextual risk model:
$$\text{OT Risk Score} = \min\left(10.0, \frac{\text{Base CVSS} \times \text{Purdue Factor} \times \text{Criticality Factor} \times \text{Key Switch Factor}}{\prod (1 - \text{Compensating Control Discount})}\right)$$
- **Physical Key Switch Discount**: Rotating the controller key switch to `RUN` hardware write-protects memory, discounting vulnerability exploitability by **30%**.
- **Compensating Controls**: Record and apply compensating defenses (Inline DPI Firewalls, Data Diodes, Isolated VLANs, Read-Only Gateways) to document defensibility without requiring risky plant shutdowns.

### 4. Hardware Obsolescence & Lifecycle Management (EOL / EOS)
- Tracks vendor lifecycle milestones: Active, Mature, End-of-Life (sales discontinued), End-of-Support (firmware patches ceased), and Obsolete.
- Generates urgency ratings and modernization upgrade paths (e.g. migrating legacy Siemens S7-400H to S7-1500R/H).

### 5. Ingestion Lab & Non-Intrusive Discovery
- **Inductive Automation Ignition Parser**: Ingests Gateway Backups (`.gwbk` SQLite database) and Tag JSON exports. Extracts the entire PLC/RTU device connection table (Logix, Siemens, Modbus, DNP3), hostnames, IPs, slot mappings, and parses tag semantics to infer process criticality (safety loops, chemical feeds, boilers).
- **Rockwell Studio 5000 `.L5X` Parser**: Extracts complete controller configurations, chassis backplanes, slot numbers, and catalog revisions.
- **Siemens TIA Portal `.aml` (AutomationML) Parser**: Ingests S7 hardware configuration trees.
- **Bulk CSV / JSON Importer**: Normalizes external asset spreadsheets.
- **Safe Passive Sniffer**: Captures CIP ListIdentity, S7comm SZL, Modbus FC43, and PROFINET DCP broadcasts without invasive TCP port sweeps.

### 6. Compliance Scorecards & Hardware Bill of Materials (HBOM)
- Automated scoring against **ISA/IEC 62443** (Foundational Requirements FR1 to FR7), **NIST SP 800-82r3**, and **CISA Cross-Sector CPGs**.
- One-click export of complete **Hardware Bill of Materials (HBOM)** in JSON and CSV formats.

---

## Quick Start

### 1. Installation
Ensure Python 3.10+ is installed:
```powershell
pip install -r requirements.txt
```

### 2. Run Test Suite
Run the automated pytest test suite:
```powershell
python -m pytest tests/ -v
```

### 3. Launch the OT-BASE Asset Center Web Dashboard
Start the local server:
```powershell
python -m otbase.cli start --port 8000
```
Open your browser to: **`http://localhost:8000`**

---

## Pre-Populated Industrial Scenarios

Switch between pre-configured industrial plant environments directly from the web navigation bar or CLI:

1. **Municipal Water Treatment Facility (`water_treatment`)**:
   - Primary Control: Rockwell ControlLogix 5580 (10-slot 1756-A10 chassis with EN2T, IB16, OB16E, IF8, OF4, SYNCH).
   - Chemical Dosing: CompactLogix 5380 (5069-L320ERM).
   - Operator Supervisory: AVEVA InTouch 2020 R2 HMI, FactoryTalk Historian SE.
   - Dual-homed EWS breach and Level 3.5 IDMZ Security Gateway (FL mGuard RS4000).

2. **500kV Transmission Substation Alpha (`substation`)**:
   - Automation Controller: Schweitzer SEL-3530 Real-Time Automation Controller (RTAC).
   - Protection Relays: SEL-421 Distance Relay, Siemens SIPROTEC 5 7UT85.
   - Electronic Security Perimeter: Ruggedcom RX1500 (NERC CIP-005 compliant).

3. **Petrochemical Continuous Refinery (`refinery`)**:
   - Distributed Control: Yokogawa Centum VP Field Control Station (AFV30D) & HIS Console.
   - Safety Instrumented System (SIS): Schneider Electric Triconex Tricon v11.4 (TMR SIL 3).
   - Legacy Utility: Siemens SIMATIC S7-400H Redundant System (End of Support).

---

## CLI Usage Guide

```powershell
# Start web server
python -m otbase.cli start --host 127.0.0.1 --port 8000

# Inspect active inventory
python -m otbase.cli inspect

# Deep inspect a specific PLC rack chassis
python -m otbase.cli inspect PLC-01-MAIN

# Run ISA/IEC 62443 compliance audit in terminal
python -m otbase.cli audit

# Trigger safe passive OT network discovery probe
python -m otbase.cli scan

# Switch plant scenario
python -m otbase.cli seed --scenario substation

# Export Hardware Bill of Materials (HBOM)
python -m otbase.cli export --format csv
python -m otbase.cli export --format json
```

---

## REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/status` | System health, version, and active facility |
| `GET` | `/api/dashboard` | Executive KPIs, risk averages, and top riskiest assets |
| `GET` | `/api/scenarios` | List available plant simulation scenarios |
| `POST` | `/api/scenarios/{name}` | Switch active plant scenario (`water_treatment`, `substation`, `refinery`) |
| `GET` | `/api/assets` | Query asset inventory with filtering (Purdue level, vendor, tag) |
| `GET` | `/api/assets/{id}` | Detailed asset metadata, network interfaces, and active CVEs |
| `PUT` | `/api/assets/{id}/keyswitch` | Update physical key switch (`RUN`, `REMOTE_RUN`, `PROG`) |
| `GET` | `/api/chassis/{id}` | Visual rack chassis layout and slot module breakdown |
| `GET` | `/api/topology` | Purdue zones, conduits, and detected segmentation violations |
| `GET` | `/api/vulnerabilities` | Correlated ICS-CERT advisories and contextual OT risk scores |
| `POST` | `/api/vulnerabilities/{id}/compensate` | Apply compensating control (DPI firewall, key lock, diode) |
| `DELETE` | `/api/vulnerabilities/{id}/compensate/{cid}` | Remove compensating control and recalculate risk |
| `GET` | `/api/lifecycle` | Hardware obsolescence status and EOL/EOS replacement advice |
| `POST` | `/api/discovery/probe` | Run simulated safe non-intrusive broadcast probe |
| `POST` | `/api/ingest/upload` | Upload `.L5X`, `.aml`, `.csv`, or `.json` configuration file |
| `GET` | `/api/export/hbom/json` | Download Hardware Bill of Materials (JSON) |
| `GET` | `/api/export/hbom/csv` | Download Hardware Bill of Materials (CSV) |
| `GET` | `/api/export/compliance` | Generate IEC 62443 & NIST SP 800-82 audit scorecard |

---

## Standards & Framework Alignments

- **ISA/IEC 62443**:
  - `IEC 62443-3-2`: Security Risk Assessment, Zone and Conduit Identification.
  - `IEC 62443-3-3`: System Security Requirements (FR 1 through FR 7).
  - `IEC 62443-4-2`: Technical Security Requirements for IACS Components.
- **NIST SP 800-82r3**: Guide to Industrial Control Systems (ICS) Security.
- **NERC CIP**: Bulk Electric System Electronic Security Perimeters (CIP-005) & System Management (CIP-007).
- **CISA Cross-Sector Cybersecurity Performance Goals (CPGs)**: Asset inventory (2.A), physical key locks (2.I), and network segmentation.
