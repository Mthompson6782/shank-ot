import argparse
import sys
import json
import uvicorn

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from otbase.config import settings
from otbase.db.repository import repo
from otbase.engine.topology_analyzer import TopologyAnalyzer
from otbase.engine.cve_matcher import CVEMatcher
from otbase.discovery.probe_simulator import OTProbeSimulator
from otbase.exporter.hbom_sbom import HBOMExporter
from otbase.exporter.compliance_report import ComplianceReportGenerator

def main():
    parser = argparse.ArgumentParser(
        prog="shank",
        description="SHANK: SCADA & Hardware Asset Network Knowledge (Blade Fleet OT Platform)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: start
    start_parser = subparsers.add_parser("start", help="Start the SHANK Web Console")
    start_parser.add_argument("--host", default=settings.host, help=f"Bind host (default: {settings.host})")
    start_parser.add_argument("--port", type=int, default=settings.port, help=f"Port (default: {settings.port})")
    start_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")

    # Command: seed
    seed_parser = subparsers.add_parser("seed", help="Reset and load an industrial plant scenario")
    seed_parser.add_argument(
        "--scenario",
        choices=["water_treatment", "substation", "refinery"],
        default="water_treatment",
        help="Scenario to load"
    )

    # Command: inspect
    inspect_parser = subparsers.add_parser("inspect", help="Inspect assets or rack chassis")
    inspect_parser.add_argument("asset_id", nargs="?", help="Specific asset tag or ID")

    # Command: scan
    subparsers.add_parser("scan", help="Run safe passive OT broadcast probe sweep")

    # Command: audit
    audit_parser = subparsers.add_parser("audit", help="Run IEC 62443 / NIST SP 800-82 compliance audit")

    # Command: export
    export_parser = subparsers.add_parser("export", help="Export Hardware Bill of Materials (HBOM)")
    export_parser.add_argument("--format", choices=["json", "csv"], default="json")

    args = parser.parse_args()

    if not args.command or args.command == "start":
        host = getattr(args, "host", settings.host)
        port = getattr(args, "port", settings.port)
        print(f"\n==================================================================")
        print(f"  🗡️ SHANK: SCADA & Hardware Asset Network Knowledge")
        print(f"  Blade Fleet Platform | Console starting on http://{host}:{port}")
        print(f"  Active Facility: {repo.current_facility}")
        print(f"  Total Assets Loaded: {len(repo.assets)}")
        print(f"==================================================================\n")
        uvicorn.run("otbase.web.app:app", host=host, port=port, reload=getattr(args, "reload", False))

    elif args.command == "seed":
        repo.load_scenario(args.scenario)
        print(f"✓ Loaded scenario '{args.scenario}'. Active facility: {repo.current_facility} ({len(repo.assets)} assets).")

    elif args.command == "inspect":
        if args.asset_id:
            asset = repo.get_asset(args.asset_id)
            if not asset:
                # Try finding by tag
                for a in repo.list_assets():
                    if a.tag_name.lower() == args.asset_id.lower():
                        asset = a
                        break
            if not asset:
                print(f"Asset '{args.asset_id}' not found.")
                sys.exit(1)

            print(f"\n--- [ASSET] {asset.tag_name} ({asset.display_name}) ---")
            print(f"Vendor / Model:     {asset.vendor} {asset.model} (Rev: {asset.hardware_revision or 'N/A'})")
            print(f"Firmware:           {asset.firmware_version or 'N/A'}")
            print(f"Purdue Level:       {asset.purdue_level.value}")
            print(f"Key Switch:         {asset.key_switch.value}")
            print(f"Criticality:        {asset.criticality.value}")
            print(f"OT Risk Score:      {asset.ot_risk_score} / 10.0")
            print(f"Active CVEs:        {', '.join(asset.active_cves) or 'None'}")

            if asset.chassis:
                print(f"\n--- [RACK CHASSIS] {asset.chassis.model} ({len(asset.chassis.modules)} Slots Occupied) ---")
                for m in asset.chassis.modules:
                    cve_str = f" [CVEs: {', '.join(m.cves)}]" if m.cves else ""
                    print(f"  Slot {m.slot:02d}: {m.name} | Cat: {m.catalog_number} | FW: {m.firmware_version}{cve_str}")
        else:
            assets = repo.list_assets()
            print(f"\nTotal Assets ({len(assets)}) in {repo.current_facility}:\n")
            for a in assets:
                has_chassis = f"({len(a.chassis.modules)} slots)" if a.chassis else "standalone"
                print(f" - [{a.tag_name:15s}] {a.model:25s} | {a.purdue_level.value:30s} | Risk: {a.ot_risk_score:4.1f} | {has_chassis}")

    elif args.command == "scan":
        new_assets = OTProbeSimulator.run_safe_discovery_sweep(repo.current_facility)
        for a in new_assets:
            repo.save_asset(a)
        print(f"✓ Passive probe completed. Discovered and added {len(new_assets)} asset(s):")
        for a in new_assets:
            print(f"   + {a.tag_name} ({a.vendor} {a.model}) @ {a.network_interfaces[0].ip_address}")

    elif args.command == "audit":
        assets = repo.list_assets()
        violations = TopologyAnalyzer.audit(assets, repo.list_zones(), repo.list_conduits())
        scorecard = ComplianceReportGenerator.evaluate(repo.current_facility, assets, violations)
        print(f"\n========================================================")
        print(f"  OT-BASE Cybersecurity Compliance Audit Report")
        print(f"  Facility: {scorecard.facility}")
        print(f"  Overall Score: {scorecard.overall_score}%")
        print(f"  IEC 62443 Score: {scorecard.iec_62443_score}% | NIST SP 800-82: {scorecard.nist_800_82_score}%")
        print(f"========================================================\n")
        for r in scorecard.requirements:
            print(f"[{r.code}] {r.title}: {r.status} ({r.actual_score}%)")
            for f in r.findings:
                print(f"   ⚠️ {f}")

    elif args.command == "export":
        assets = repo.list_assets()
        if args.format == "csv":
            print(HBOMExporter.generate_hbom_csv(assets))
        else:
            print(json.dumps(HBOMExporter.generate_hbom_json(assets), indent=2))

if __name__ == "__main__":
    main()
