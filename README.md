# 🗡️ SHANK: SCADA & Hardware Asset Network Knowledge
## *The Open-Architecture Industrial Control Systems (ICS) Asset & Network Knowledge Platform*

[![Blade Fleet](https://img.shields.io/badge/BLADE_FLEET-SHANK-DC2626?style=flat-square)](https://github.com/Mthompson6782/shank-ot)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
[![ISA/IEC 62443](https://img.shields.io/badge/Compliance-ISA%2FIEC%2062443-orange.svg)](https://www.isa.org/standards-and-publications/isa-standards/isa-standards-committees/isa62443)
[![NIST SP 800-82r3](https://img.shields.io/badge/Framework-NIST%20SP%20800--82r3-red.svg)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)

**SHANK** (**S**CADA & **H**ardware **A**sset **N**etwork **K**nowledge) is an industrial-grade, open-architecture operational technology (OT) asset management, network context reconstruction, and cyber-physical security platform designed and engineered from the specifications of **Michael Thompson's SHANK platform**.

Unlike IT discovery tools that sweep IP subnets with aggressive port probes and crash fragile PLCs, **SHANK** operates through a decoupled two-tier architecture: edge **Selective Probing Nodes** interrogate infrastructure (switches, routers, chassis backplanes) and package structured **Portable Inventory Data (PID)** for automated aggregation, deterministic Layer 1 physical link resolution, multi-perspective Kandinsky orthogonal network rendering, and enterprise ITSM/SIEM/Firewall integration.

---

## Architecture Overview: Decoupled Two-Tier Engine

```
+-----------------------------------------------------------------------------------------------------------------+
|                                          SHANK Inventory Center (Central Hub)                                   |
|  - Multi-Dimensional Context Engine (5-Tier Location Trees, Duplicate IP Disambiguation, OT Systems)            |
|  - Kandinsky Orthogonal 90° Graph Engine (Connections, Locations, Purdue Hierarchy, Networks, Organic)          |
|  - NetFlow / sFlow Telemetry Aggregator (Sankey Flow Matrix & Asset Directional Path Profiling)                 |
|  - Contextual OT Risk & ICS-CERT Engine (Michael Thompson Risk Formula + Key Switch Memory Locks)               |
|  - Enterprise Ecosystem Connectors (ServiceNow CMDB ISA-95, Splunk TA Syslog, Fortinet/Palo Alto Firewalls)     |
+-------------------------------------------------------+---------------------------------------------------------+
                                                        ^
                                                        |  JSON-over-HTTPS (Encrypted / Air-Gapped Sneakernet)
                                                        |  Portable Inventory Data (PID Schema v1.2)
+-------------------------------------------------------+---------------------------------------------------------+
|                                        Selective Probing Nodes (Distributed Edge)                               |
|  - SNMP Switch Interrogation: RFC 1213/2863 ifXTable, RFC 1493/4188 Bridge MIB dot1dTpFdbTable, LLDP/CDP       |
|  - Backplane Crawler: CIP Routing Across ControlLogix 1756, Remote Point I/O, PowerFlex Drives, S7comm, DCP    |
|  - Passive Telemetry Collector: NetFlow v5/v9 & sFlow Sampling (1:128) for Zero-Overhead Flow Ingestion        |
|  - Industrial Config Ingestion: Rockwell .L5X, Siemens .aml, Ignition .gwbk Gateway Backups, CSV/JSON Spreadsheets |
+-----------------------------------------------------------------------------------------------------------------+
```

---

## Core Pillars of the SHANK Architecture

### 1. Selective Probing & Deterministic Layer 1 Link Resolution
Rather than ping-sweeping PLCs, the discovery node directly queries industrial managed switches (Cisco IE, Hirschmann, Moxa, Ruggedcom):
- Interrogates `ifTable`/`ifXTable` for interface operational status, speeds, duplex, and port descriptions.
- Queries Bridge MIB `dot1dTpFdbTable` / `dot1qTpFdbTable` for MAC forwarding tables across all 802.1Q VLAN trunks.
- Correlates with local ARP caches (`ipNetToMediaTable`) to translate MAC addresses to IP addresses.
- Resolves multi-chassis switch uplinks via LLDP (`lldpRemTable`) and CDP (`cdpCacheTable`).
- **Physical Link Binding**: Disambiguates single-device edge ports from trunk uplinks, deterministically pinning each PLC and HMI to its exact physical switch port (`SW-01-IND Fa1/1 -> PLC-01-MAIN`).

### 2. Automation Backplane Traversal & Deep Chassis Modeling
Industrial controllers are modular racks containing multiple processors, communication adapters, and I/O cards:
- **Rockwell ControlLogix 1756**: Uses Common Industrial Protocol (CIP) route paths (`1, <slot>`) to crawl backplane slots, extracting catalog numbers, firmware revisions, hardware series, and serial numbers.
- **Fieldbus & Remote I/O**: Traverses communication bridges (1756-EN2T) onto remote Ethernet/IP subnets to discover Point I/O drops (1734-AENT) and PowerFlex 525 drives.
- **Siemens S7 & PROFINET**: Parses S7comm System Status Lists (SZL 0x0011 / 0x0111) and PROFINET DCP Layer 2 multicast identify frames (`0x8892`).
- **Slot-Level CVE Tracking**: Pinpoints whether a vulnerability exists in the controller execution engine or the communication interface card.

### 3. Kandinsky Graph-Theoretic Orthogonal Layout Engine
Process engineers and OT operators reject erratic IT force-directed "hairball" diagrams. SHANK implements an orthogonal routing engine inspired by Kandinsky:
- **Orthogonal 90° Routing**: Edges route on strict horizontal and vertical grid segments with automated bend-point minimization and edge crossing reduction.
- **5 Operational Perspectives**:
  1. **Connections (Physical)**: Visualizes exact switch ports, patch cables, and Layer 1 physical topology.
  2. **Locations**: Organizes assets within nested boundaries representing geographic sites, buildings, rooms, and cabinet racks.
  3. **Purdue Hierarchy**: Enforces strict horizontal stratification from Level 0/1 up through Level 3.5 IDMZ.
  4. **Networks (Subnets/VLANs)**: Groups nodes by IP broadcast domains and 802.1Q VLAN tags.
  5. **Organic**: Force-directed spring layout for high-level exploratory analysis.
- **Hybrid Unmanaged Switch Modeling**: Unmanaged switches (e.g. Stratix 2000, Hirschmann Spider) lack SNMP management. SHANK detects groups of MAC addresses appearing on a single managed switch port and synthesizes an intermediate "virtual hub" with dotted boundary lines.
- **Vector & Data Export**: One-click export to native SVG and GraphML for enterprise architecture modeling.

### 4. Multi-Dimensional Context & Duplicate IP Disambiguation
Industrial facilities frequently deploy standardized OEM machine skids (packaging lines, RO skids, turbine skids) with identical factory IP addressing (`192.168.1.50`):
- **5-Tier Location Tree**: `Enterprise -> Site -> Building -> Room / Area -> Cabinet`.
- **Disambiguation Engine**: Binds identical IP addresses to their distinct Location Tree nodes and physical switch port context, allowing multiple assets with IP `192.168.1.50` to coexist cleanly without database key collisions.
- **Functional OT Systems**: Groups cross-Purdue assets into logical manufacturing lines (e.g. *Water Clarification & Filtration System*).
- **Shared Trunk Risk Analysis**: Automatically flags when two logically isolated systems route traffic through the same unsegmented switch trunk.

### 5. Sampled Flow Telemetry & Sankey Behavioral Profiling
Continuous Deep Packet Inspection (DPI) requires expensive physical taps and dedicated compute hardware:
- Ingests sampled NetFlow v5/v9 and sFlow (1:128 sampling rate) directly from core and distribution switches.
- Assembles an aggregated, directional byte/packet flow matrix.
- Generates interactive **Sankey Diagrams** showing inter-zone traffic volume and protocol distribution.
- **Device Traffic Path Profiler**: Profiles every observed communication partner for each asset and detects unauthorized conduits (e.g. direct Level 1 PLC communicating directly with Level 4 enterprise subnets).

### 6. Enterprise Ecosystem Connectors
Closes the gap between factory floor reality and corporate cybersecurity systems:
- **ServiceNow CMDB**: Generates payloads for the Service Graph Connector mapped to the ISA-95 equipment model (`cmdb_ci_ot_control_system`, `cmdb_ci_ot_network_interface`).
- **Splunk Industrial TA**: Produces Common Event Format (CEF) syslog events for asset lifecycle, switch port state changes, and key switch manipulation.
- **Industrial Firewall ACL Policy Generator**: Synthesizes enforceable rule-sets for **Fortinet FortiOS** (`config firewall policy`) and **Palo Alto PAN-OS** (XML/CLI set syntax) based strictly on discovered valid communication baselines.

---

## Quick Start

### 1. Installation
Ensure Python 3.10+ is installed:
```powershell
pip install -r requirements.txt
```

### 2. Run Test Suite
Run the automated pytest test suite (30 passing tests):
```powershell
python -m pytest tests/ -v
```

### 3. Launch the SHANK Web Asset Center
Start the local server:
```powershell
python -m otbase.cli start --port 8000
```
Open your browser to: **`http://localhost:8000`**

---

## CLI Usage Guide

```powershell
# Start the web server and REST API
python -m otbase.cli start --host 127.0.0.1 --port 8000

# Inspect active inventory
python -m otbase.cli inspect

# Deep inspect a specific PLC rack chassis
python -m otbase.cli inspect PLC-01-MAIN

# Run ISA/IEC 62443 compliance audit in terminal
python -m otbase.cli audit

# Inspect Kandinsky orthogonal topology across perspectives
python -m otbase.cli topology --mode connections
python -m otbase.cli topology --mode purdue
python -m otbase.cli topology --mode locations
python -m otbase.cli topology --mode networks

# Export data to enterprise connectors
python -m otbase.cli export --format servicenow
python -m otbase.cli export --format splunk
python -m otbase.cli export --format firewall
python -m otbase.cli export --format graphml
python -m otbase.cli export --format svg
```

---

## REST API Reference

| Category | Method | Endpoint | Description |
| :--- | :--- | :--- | :--- |
| **System** | `GET` | `/api/status` | System health, version, active scenario |
| **Dashboard** | `GET` | `/api/dashboard` | Executive KPIs, risk heatmaps, top riskiest assets |
| **Scenarios** | `POST` | `/api/scenarios/{name}` | Switch industrial scenarios (`water_treatment`, `substation`, `refinery`) |
| **Assets** | `GET` | `/api/assets` | Query inventory with filtering (Purdue, vendor, tag) |
| **Assets** | `PUT` | `/api/assets/{id}/keyswitch` | Toggle physical key switch (`RUN`, `REMOTE_RUN`, `PROG`) |
| **Chassis** | `GET` | `/api/chassis/{id}` | Slot-by-slot chassis hardware & active LEDs |
| **Topology** | `GET` | `/api/topology` | Purdue zones, conduits, and rule violations |
| **Topology** | `GET` | `/api/topology/perspectives` | Kandinsky orthogonal coordinates (5 perspectives) |
| **Topology** | `GET` | `/api/topology/unmanaged-switch`| Virtual hub model for unmanaged switches |
| **Telemetry** | `GET` | `/api/telemetry/flows` | Ingested NetFlow/sFlow raw flow records |
| **Telemetry** | `GET` | `/api/telemetry/sankey` | Sankey node/link flow volume matrix |
| **Telemetry** | `GET` | `/api/telemetry/profile/{ip}` | Detailed asset traffic path profiler |
| **Context** | `GET` | `/api/locations` | 5-tier location trees & duplicate IP report |
| **Context** | `GET` | `/api/systems` | Functional OT Systems & shared switch risk |
| **PID Ingest** | `POST` | `/api/ingest/pid` | Ingest Portable Inventory Data from discovery node |
| **Enterprise** | `GET` | `/api/export/servicenow` | ServiceNow CMDB Service Graph payload (ISA-95) |
| **Enterprise** | `GET` | `/api/export/splunk` | Splunk TA CEF syslog stream |
| **Enterprise** | `GET` | `/api/export/firewall-rules` | FortiOS & PAN-OS industrial firewall policies |
| **Enterprise** | `GET` | `/api/export/topology-graphml` | Export topology as standard GraphML XML |
| **Enterprise** | `GET` | `/api/export/topology-svg` | Download standalone SVG orthogonal diagram |
| **Compliance** | `GET` | `/api/export/compliance` | Generate IEC 62443 & NIST SP 800-82 audit scorecard |
| **HBOM** | `GET` | `/api/export/hbom/json` | Download complete Hardware Bill of Materials (JSON) |

---

## Standards & Framework Alignments

- **ISA/IEC 62443**:
  - `IEC 62443-3-2`: Security Risk Assessment, Zone and Conduit Identification.
  - `IEC 62443-3-3`: System Security Requirements (FR 1 through FR 7).
  - `IEC 62443-4-2`: Technical Security Requirements for IACS Components.
- **NIST SP 800-82r3**: Guide to Industrial Control Systems (ICS) Security.
- **NERC CIP**: Bulk Electric System Electronic Security Perimeters (CIP-005) & System Management (CIP-007).
- **CISA Cross-Sector Cybersecurity Performance Goals (CPGs)**: Asset inventory (2.A), physical key locks (2.I), and network segmentation.
